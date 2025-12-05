# capture_logic.py
import os
import sys
import time
import threading
import traceback
import queue
import json
import socket
from datetime import datetime
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Any

import pandas as pd
import numpy as np
import httpx

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, conf
except Exception:
    print("❌ scapy가 필요합니다. pip install scapy")
    sys.exit(1)

# =================================================================
# --- 전역 설정 (gui.py와 동기화되어야 함)
# =================================================================
log_queue: queue.Queue = None
metrics_queue: queue.Queue = None
risk_update_queue: queue.Queue = None
command_queue: queue.Queue = None

API_URL: str = "https://network-ai-analysis.onrender.com/predict"
RISK_JSON_UPLOAD_URL: str = "https://network-security-service-ma6i.vercel.app/api-management/ip-threats"
API_KEY: str = ""
AUTH_KEY: str = ""
NETWORK_INTERFACE: str = ""
CHUNK_DURATION: float = 5.0
FLOW_INACTIVITY: float = 10.0
IP_HIT_THRESHOLD: float = 1000.0

RISK_IP_FILE = "risk_ips.json"

RISK_IP_STORAGE: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    'events': [],
    'last_seen': 0.0
})
RISK_IP_LOCK = threading.Lock()
RISK_ATTACKS = ['Port_Scan', 'Slowloris_Attack', 'IP_Threshold_Exceeded']

# 자동 제외 대상 (자기 IP들)
EXCLUDE_IPS = set()
_LOCAL_IPS_POPULATED = False
_LOCAL_IPS_LOCK = threading.Lock()

def _detect_local_ips():
    """표준 라이브러리와 (있다면) netifaces를 사용해 로컬 IP를 수집."""
    ips = set()
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            ip = res[4][0]
            ips.add(ip.split('%')[0])
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass

    try:
        import netifaces
        for iface in netifaces.interfaces():
            for fam in (netifaces.AF_INET, getattr(netifaces, 'AF_INET6', None)):
                if fam is None: continue
                addrs = netifaces.ifaddresses(iface).get(fam, [])
                for a in addrs:
                    ip = a.get('addr')
                    if ip:
                        ips.add(ip.split('%')[0])
    except Exception:
        pass

    ips.update({"127.0.0.1", "0.0.0.0", "::1"})
    return ips

def _ensure_local_ips_populated():
    global _LOCAL_IPS_POPULATED
    if _LOCAL_IPS_POPULATED:
        return
    with _LOCAL_IPS_LOCK:
        if _LOCAL_IPS_POPULATED:
            return
        try:
            local_ips = _detect_local_ips()
            EXCLUDE_IPS.update(local_ips)
        finally:
            _LOCAL_IPS_POPULATED = True

def log_message(message: str, level: str = 'INFO', data: Dict[str, Any] = None):
    if log_queue:
        log_queue.put((level, message, data or {}))

def update_gui_metrics(features: Dict[str, Any]):
    if metrics_queue:
        metrics_queue.put(features)

def update_gui_risk_ip(ip_data: Dict[str, Any]):
    if risk_update_queue:
        risk_update_queue.put(ip_data)

def get_current_risk_ips():
    with RISK_IP_LOCK:
        return RISK_IP_STORAGE.copy()

def load_risk_ips_from_file():
    global RISK_IP_STORAGE
    if not os.path.exists(RISK_IP_FILE):
        log_message(f"ℹ️ 저장된 위험 IP 파일({RISK_IP_FILE})이 없습니다.", 'INFO')
        return

    try:
        with open(RISK_IP_FILE, 'r', encoding='utf-8') as f:
            data_from_file = json.load(f)
            loaded_storage = defaultdict(lambda: {
                'events': [],
                'last_seen': 0.0
            })
            for ip, data in data_from_file.items():
                loaded_storage[ip]['events'] = data.get('events', [])
                loaded_storage[ip]['last_seen'] = data.get('last_seen', 0.0)
            with RISK_IP_LOCK:
                RISK_IP_STORAGE = loaded_storage
            log_message(f"✅ {len(loaded_storage)}개의 위험 IP를 파일에서 불러왔습니다.", 'INFO')
    except Exception as e:
        log_message(f"❌ 위험 IP 파일({RISK_IP_FILE}) 로드 실패: {e}", 'ERROR')

def save_risk_ips_to_file():
    with RISK_IP_LOCK:
        data_to_save = {}
        for ip, data in RISK_IP_STORAGE.items():
            data_to_save[ip] = {
                'events': data['events'],
                'last_seen': data['last_seen']
            }
    try:
        with open(RISK_IP_FILE, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=4, ensure_ascii=False)
        log_message(f"✅ 위험 IP 목록이 {RISK_IP_FILE}에 저장되었습니다.", 'INFO')
    except Exception as e:
        log_message(f"❌ 위험 IP 파일 저장 실패: {e}", 'ERROR')

AMP_PORTS = [53, 69, 111, 123, 137, 161, 389, 1434, 1900]
PERSIST_TTL = 60.0

@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    first_seen: float
    last_seen: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_cnt: int = 0
    fin_cnt: int = 0
    rst_cnt: int = 0
    iat_list: list = field(default_factory=list)
    last_pkt_time: float = None

    def key(self): return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)

flows_lock = threading.Lock()
flows: Dict[Tuple, Flow] = {}
window_buffer = []
window_lock = threading.Lock()
recent_fsr = []
dst_persist = {}
gui_http_client: httpx.Client = None

def now(): return time.time()
def now_iso(): return datetime.now().isoformat()

def proto_num(pkt):
    if pkt.haslayer(TCP): return 6
    if pkt.haslayer(UDP): return 17
    if pkt.haslayer(ICMP): return 1
    return 0

def extract_tuple(pkt):
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None: return None
    src, dst, proto = ip.src, ip.dst, proto_num(pkt)
    sport, dport = 0, 0
    if proto == 6 and pkt.haslayer(TCP):
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif proto == 17 and pkt.haslayer(UDP):
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    return (src, dst, sport, dport, proto)

def reverse_key(key): src, dst, sport, dport, proto = key; return (dst, src, dport, sport, proto)
def to_numeric_safe_series(s, fill=0.0): return pd.to_numeric(s, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(fill)

def entropy_of_counts(counts_series):
    try:
        if counts_series is None: return 0.0
        counts = counts_series.value_counts()
        total = counts.sum()
        if total <= 0: return 0.0
        probs = counts / (total + 1e-12)
        ent = -(probs * np.log2(probs + 1e-12)).sum()
        return float(ent)
    except Exception:
        return 0.0

def process_packet(pkt):
    try:
        t = now()
        k = extract_tuple(pkt)
        if k is None: return
        src, dst, sport, dport, proto = k
        length = len(pkt)
        flags = None
        if proto == 6 and pkt.haslayer(TCP): flags = pkt[TCP].flags
        with flows_lock:
            f = flows.get(k)
            rev = reverse_key(k)
            revf = flows.get(rev)

            # 신규 플로우 생성(항상 이후 누적 코드가 실행되도록 last_pkt_time=None)
            if f is None and revf is None:
                f = Flow(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, proto=proto,
                         first_seen=t, last_seen=t, last_pkt_time=None)
                flows[f.key()] = f
            else:
                if f is None:
                    f = revf

            # 방향 판정 및 항상 패킷/바이트 누적
            is_forward = (src == f.src_ip and sport == f.src_port and dst == f.dst_ip and dport == f.dst_port)
            if is_forward:
                f.fwd_pkts += 1
                f.fwd_bytes += length
            else:
                f.bwd_pkts += 1
                f.bwd_bytes += length

            # TCP 플래그 누적 (항상 수행)
            if proto == 6 and flags is not None:
                if flags & 0x02: f.syn_cnt += 1
                if flags & 0x01: f.fin_cnt += 1
                if flags & 0x04: f.rst_cnt += 1

            # IAT 계산
            if f.last_pkt_time is not None:
                iat = t - f.last_pkt_time
                if iat >= 0: f.iat_list.append(iat)
            f.last_pkt_time = t
            f.last_seen = t
    except Exception:
        traceback.print_exc()

def expire_flows_and_collect():
    now_ts = now()
    to_emit = []
    with flows_lock:
        keys = list(flows.keys())
        for k in keys:
            f = flows.get(k)
            if f is None: continue
            if (now_ts - f.last_seen) >= FLOW_INACTIVITY:
                to_emit.append(f)
                try:
                    del flows[k]
                except Exception:
                    pass
    if to_emit:
        rows = []
        for f in to_emit:
            rows.append({
                'flow_start_time': f.first_seen, 'src_ip': f.src_ip, 'dst_ip': f.dst_ip, 'dstport': f.dst_port,
                'protocol': f.proto, 'flow_duration': int((f.last_seen - f.first_seen) * 1_000_000),
                'tot_fwd_pkts': f.fwd_pkts, 'tot_bwd_pkts': f.bwd_pkts, 'tot_len_fwd_pkts': f.fwd_bytes,
                'tot_len_bwd_pkts': f.bwd_bytes, 'syn_flag_cnt': f.syn_cnt,
                'flow_iat_mean': float(np.mean(f.iat_list)) if f.iat_list else 0.0,
                'flow_iat_std': float(np.std(f.iat_list, ddof=0)) if f.iat_list else 0.0,
            })
        with window_lock:
            window_buffer.extend(rows)

def _send_json_report_threaded():
    global RISK_JSON_UPLOAD_URL, AUTH_KEY, gui_http_client
    if not RISK_JSON_UPLOAD_URL or RISK_JSON_UPLOAD_URL == "http://example.com/api/risk-ips":
        log_message("ℹ️ 위험 IP 전송 URL이 설정되지 않아, 실시간 JSON 전송을 건너뜁니다.", 'INFO')
        return
    if not gui_http_client:
        log_message("❌ HTTP 클라이언트가 없어 JSON 전송 실패.", 'ERROR')
        return
    try:
        json_string = create_json_report()
        headers = {
            "auth-key": AUTH_KEY,
            "Content-Type": "application/json"
        }
        response = gui_http_client.post(RISK_JSON_UPLOAD_URL, data=json_string, headers=headers)
        if response.status_code == 200 or response.status_code == 201:
            log_message(f"✅ 위험 IP 목록 JSON 전송 성공 (-> {RISK_JSON_UPLOAD_URL})", 'INFO')
        else:
            log_message(f"❌ 위험 IP 목록 JSON 전송 실패: {response.status_code}", 'ERROR')
    except Exception as e:
        log_message(f"❌ JSON 전송 스레드 오류: {e}", 'ERROR')

def notify_risk_ip_update(ip: str, attack_label: str, count_value: int = 1):
    if not ip or not attack_label:
        return
    # 방어적 체크: EXCLUDE_IPS에 포함된 IP는 무시
    _ensure_local_ips_populated()
    if ip in EXCLUDE_IPS:
        # log_message(f"ℹ️ notify 호출된 IP {ip}은 제외 목록에 있어 처리하지 않습니다.", 'INFO')
        return
    try:
        with RISK_IP_LOCK:
            now_ts = now()
            last_seen_iso = datetime.fromtimestamp(now_ts).isoformat()
            storage = RISK_IP_STORAGE[ip]
            event = {"time": last_seen_iso, "count": count_value}
            storage['events'].append(event)
            storage['last_seen'] = now_ts
            total_threat_score = sum(e['count'] for e in storage['events'])
        ip_data = {
            'ip': ip,
            'attack_type': attack_label,
            'count_value': count_value,
            'total_hits': total_threat_score,
            'last_seen': time.strftime('%H:%M:%S')
        }
        update_gui_risk_ip(ip_data)
        threading.Thread(target=_send_json_report_threaded, daemon=True).start()
    except Exception as e:
        log_message(f"❌ notify_risk_ip_update 오류: {e}", 'ERROR')

def process_window_results(chunk_df: pd.DataFrame, detected_label: str):
    if detected_label not in RISK_ATTACKS:
        return
    if detected_label == 'IP_Threshold_Exceeded':
        return
    if 'src_ip' in chunk_df.columns:
        # 자동 제외 목록 준비
        _ensure_local_ips_populated()
        source_ips = chunk_df['src_ip'].unique()
        for ip in source_ips:
            if pd.notna(ip):
                ip_str = str(ip)
                if ip_str in EXCLUDE_IPS:
                    # log_message(f"ℹ️ 제외된 IP: {ip_str} (AI 탐지에서 무시됨)", 'INFO')
                    continue
                log_message(
                    f"🚨 [AI 탐지] {detected_label} 감지! IP: {ip_str}",
                    'ATTACK',
                    data={'ip': ip_str, 'attack_type': detected_label}
                )
                notify_risk_ip_update(ip_str, detected_label, count_value=1)

def check_ip_hit_threshold(src_counts: pd.Series):
    global IP_HIT_THRESHOLD
    if IP_HIT_THRESHOLD <= 0:
        return
    # 자동 제외 목록 준비
    _ensure_local_ips_populated()
    try:
        suspicious_ips = src_counts[src_counts >= IP_HIT_THRESHOLD]
        if not suspicious_ips.empty:
            attack_label = "IP_Threshold_Exceeded"
            for ip, count in suspicious_ips.items():
                if pd.isna(ip): continue
                ip_str = str(ip)
                if ip_str in EXCLUDE_IPS:
                    # log_message(f"ℹ️ 제외된 IP: {ip_str} (임계치 검사에서 무시됨)", 'INFO')
                    continue
                log_message(
                    f"🚨 [임계값 초과] IP: {ip_str}가 윈도우 내 {int(count)}회 등장 (임계값: {int(IP_HIT_THRESHOLD)})",
                    'ATTACK',
                    data={'ip': ip_str, 'attack_type': attack_label, 'count': count}
                )
                notify_risk_ip_update(ip_str, attack_label, count_value=int(count))
    except Exception as e:
        log_message(f"❌ IP 임계값 분석 중 오류: {e}", 'ERROR')

def compute_window_features(chunk_rows):
    global recent_fsr, dst_persist, gui_http_client
    if not chunk_rows:
        return
    df = pd.DataFrame(chunk_rows)
    defaults = {
        'flow_start_time': time.time(), 'flow_duration': 0, 'protocol': 0, 'dstport': 0,
        'tot_fwd_pkts': 0, 'tot_bwd_pkts': 0, 'tot_len_fwd_pkts': 0, 'tot_len_bwd_pkts': 0,
        'flow_iat_mean': 0.0, 'flow_iat_std': 0.0, 'syn_flag_cnt': 0, 'src_ip': None, 'dst_ip': None
    }
    for k, v in defaults.items():
        if k not in df.columns: df[k] = v

    df['flow_duration_sec'] = to_numeric_safe_series(df['flow_duration']) / 1_000_000
    df['protocol_num'] = df['protocol'].apply(lambda p: int(p) if pd.notna(p) else 0)
    df['is_tcp'] = (df['protocol_num'] == 6).astype(int)
    df['is_udp'] = (df['protocol_num'] == 17).astype(int)
    df['is_icmp'] = (df['protocol_num'] == 1).astype(int)
    df['dstport'] = to_numeric_safe_series(df['dstport']).astype(int)
    df['tot_fwd_pkts'] = to_numeric_safe_series(df['tot_fwd_pkts'])
    df['tot_bwd_pkts'] = to_numeric_safe_series(df['tot_bwd_pkts'])
    df['tot_len_fwd_pkts'] = to_numeric_safe_series(df['tot_len_fwd_pkts'])
    df['tot_len_bwd_pkts'] = to_numeric_safe_series(df['tot_len_bwd_pkts'])

    def avg_pkt_size(row):
        proto = int(row['protocol_num'])
        if proto == 17: return 200.0
        if proto == 6: return 900.0
        return 512.0

    df['_flow_pkt_sum'] = df['tot_fwd_pkts'] + df['tot_bwd_pkts']
    df['_avg_pkt_size'] = df.apply(avg_pkt_size, axis=1)
    df['_estimated_flow_bytes'] = df['_flow_pkt_sum'] * df['_avg_pkt_size']
    df['flow_byte_sum_raw'] = df['tot_len_fwd_pkts'] + df['tot_len_bwd_pkts']
    df['agg_len_per_flow'] = df[['flow_byte_sum_raw', '_estimated_flow_bytes']].max(axis=1)

    def per_flow_pkt_size(r):
        pkt_sum = r.get('_flow_pkt_sum', 0) or 0
        if pkt_sum <= 0: return 0.0
        raw = r.get('flow_byte_sum_raw', 0) or 0
        if raw > 0: return raw / pkt_sum
        return (r.get('_estimated_flow_bytes', 0) / pkt_sum) if pkt_sum > 0 else 0.0

    df['_per_flow_pkt_size'] = df.apply(per_flow_pkt_size, axis=1)

    if 'flow_start_time' in df.columns:
        df['_start_sec'] = df['flow_start_time'].astype(float).apply(lambda t: int(t))
        start_counts = df['_start_sec'].value_counts().to_dict()
        if start_counts:
            secs = sorted(start_counts.keys())
            per_sec = [start_counts.get(s, 0) for s in range(secs[0], secs[-1] + 1)]
            desired_len = int(max(1, CHUNK_DURATION))
            if len(per_sec) < desired_len:
                per_sec = ([0] * (desired_len - len(per_sec))) + per_sec
        else:
            per_sec = []
    else:
        per_sec = []

    flow_count = len(df)
    flow_start_rate = flow_count / float(CHUNK_DURATION) if CHUNK_DURATION > 0 else 0.0
    fsr_mean = float(np.mean(per_sec)) if per_sec else 0.0
    fsr_std = float(np.std(per_sec, ddof=0)) if per_sec else 0.0
    fsr_max = float(max(per_sec)) if per_sec else 0.0

    recent_fsr.append(fsr_mean)
    if len(recent_fsr) > 12: recent_fsr = recent_fsr[-12:]
    if len(recent_fsr) >= 2:
        prev_mean = float(np.mean(recent_fsr[:-1]))
        fsr_rate_increase = (fsr_mean / (prev_mean + 1e-9))
    else:
        fsr_rate_increase = 1.0

    agg = {}
    agg['src_ip_nunique'] = float(df['src_ip'].nunique() if 'src_ip' in df.columns else 0)
    agg['dst_ip_nunique'] = float(df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0)
    agg['dst_port_nunique'] = float(df['dstport'].nunique())
    agg['flow_count'] = float(flow_count)

    packet_count_sum = float(df['tot_fwd_pkts'].sum() + df['tot_bwd_pkts'].sum())
    agg['packet_count_sum'] = packet_count_sum

    raw_byte_sum = float(df['flow_byte_sum_raw'].sum())
    if raw_byte_sum > 0:
        byte_count_sum = raw_byte_sum
    else:
        byte_count_sum = float(df['agg_len_per_flow'].sum())
    agg['byte_count_sum'] = byte_count_sum
    agg['avg_flow_duration'] = float(df['flow_duration_sec'].mean() if not df['flow_duration_sec'].isnull().all() else 0.0)

    tcp_pkt_sum = float(df.loc[df['is_tcp'] == 1, '_flow_pkt_sum'].sum())
    udp_pkt_sum = float(df.loc[df['is_udp'] == 1, '_flow_pkt_sum'].sum())
    icmp_pkt_sum = float(df.loc[df['is_icmp'] == 1, '_flow_pkt_sum'].sum())

    den = packet_count_sum + 1e-9
    if packet_count_sum <= 0:
        agg['tcp_ratio'] = 0.0
        agg['udp_ratio'] = 0.0
        agg['icmp_ratio'] = 0.0
    else:
        agg['tcp_ratio'] = tcp_pkt_sum / den
        agg['udp_ratio'] = udp_pkt_sum / den
        agg['icmp_ratio'] = icmp_pkt_sum / den

    agg['syn_flag_ratio'] = float(df['syn_flag_cnt'].sum() / (tcp_pkt_sum + 1e-9))

    for p in AMP_PORTS:
        agg[f'udp_port_{p}_hit_sum'] = float(((df['dstport'] == p) & (df['is_udp'] == 1)).sum())

    agg['flow_iat_mean_mean'] = float(df['flow_iat_mean'].mean() if 'flow_iat_mean' in df.columns else 0.0)
    agg['flow_iat_std_mean'] = float(df['flow_iat_std'].mean() if 'flow_iat_std' in df.columns else 0.0)
    agg['src_ip_entropy'] = float(entropy_of_counts(df['src_ip']) if 'src_ip' in df.columns else 0.0)

    per_flow_sizes = df['_per_flow_pkt_size'].replace([np.inf, -np.inf], np.nan).fillna(0).values
    agg['flow_pkt_size_mean'] = float(np.mean(per_flow_sizes)) if len(per_flow_sizes) else 0.0
    agg['flow_pkt_size_median'] = float(np.median(per_flow_sizes)) if len(per_flow_sizes) else 0.0
    agg['flow_pkt_size_std'] = float(np.std(per_flow_sizes, ddof=0)) if len(per_flow_sizes) else 0.0
    agg['flow_pkt_size_max'] = float(np.max(per_flow_sizes)) if len(per_flow_sizes) else 0.0

    agg['flow_start_rate'] = float(flow_start_rate)
    agg['fsr_mean'] = float(fsr_mean)
    agg['fsr_std'] = float(fsr_std)
    agg['fsr_max'] = float(fsr_max)
    agg['fsr_rate_increase'] = float(fsr_rate_increase)

    sum_fwd = float(df['tot_fwd_pkts'].sum())
    sum_bwd = float(df['tot_bwd_pkts'].sum())
    agg['fwd_bwd_pkt_ratio'] = sum_fwd / (sum_bwd + 1.0)

    def proto_to_bit(p):
        try:
            p = int(p)
        except:
            return 0
        if p == 6: return 1 << 0
        if p == 17: return 1 << 1
        if p == 1: return 1 << 2
        return 1 << 3

    if 'src_ip' in df.columns and 'protocol_num' in df.columns:
        df['_proto_bit'] = df['protocol_num'].apply(lambda p: proto_to_bit(p) if not pd.isna(p) else 0)
        bits_per_src = df.groupby('src_ip')['_proto_bit'].agg(
            lambda s: int(np.bitwise_or.reduce(s.values) if len(s) > 0 else 0))
        popcounts = bits_per_src.apply(lambda x: bin(int(x)).count("1"))
        agg['src_proto_bitmask_nunique'] = float(bits_per_src.nunique() if len(bits_per_src) > 0 else 0.0)
        agg['src_proto_bitmask_max_popcount'] = float(popcounts.max() if len(popcounts) > 0 else 0.0)
        agg['src_proto_multi_protocol_fraction'] = float((popcounts >= 2).sum() / max(1.0, len(popcounts)))
    else:
        agg['src_proto_bitmask_nunique'] = 0.0
        agg['src_proto_bitmask_max_popcount'] = 0.0
        agg['src_proto_multi_protocol_fraction'] = 0.0

    if 'src_ip' in df.columns and 'protocol_num' in df.columns:
        proto_per_src = df.groupby('src_ip')['protocol_num'].nunique()
        agg['src_protocol_nunique_mean'] = float(proto_per_src.mean() if len(proto_per_src) > 0 else 0.0)
        agg['src_protocol_nunique_max'] = float(proto_per_src.max() if len(proto_per_src) > 0 else 0.0)
    else:
        agg['src_protocol_nunique_mean'] = 0.0
        agg['src_protocol_nunique_max'] = 0.0

    agg['dst_port_entropy'] = float(entropy_of_counts(df['dstport']) if 'dstport' in df.columns else 0.0)
    top_ports = df['dstport'].value_counts().head(1) if 'dstport' in df.columns else []
    agg['top_dst_port_1'] = float(top_ports.index[0] if len(top_ports) > 0 else 0.0)
    agg['top_dst_port_1_hits'] = float(top_ports.iloc[0] if len(top_ports) > 0 else 0.0)

    if 'src_ip' in df.columns:
        src_counts = df['src_ip'].value_counts()
        agg['top_src_count'] = float(src_counts.iloc[0] if len(src_counts) > 0 else 0.0)
        check_ip_hit_threshold(src_counts)
    else:
        agg['top_src_count'] = 0.0

    now_ts = time.time()
    avg_flow_dur = agg.get('avg_flow_duration', 0.0)
    window_suspicious = (avg_flow_dur >= 60.0)

    if 'dst_ip' in df.columns:
        for dst in df['dst_ip'].unique():
            if window_suspicious:
                entry = dst_persist.get(dst, {'count': 0, 'last_seen': 0})
                entry['count'] = entry.get('count', 0) + 1
                entry['last_seen'] = now_ts
                dst_persist[dst] = entry
            else:
                if dst in dst_persist:
                    dst_persist.pop(dst, None)

    for d in list(dst_persist.keys()):
        if now_ts - dst_persist[d]['last_seen'] > PERSIST_TTL:
            dst_persist.pop(d, None)

    agg['max_dst_persist'] = float(max((v['count'] for v in dst_persist.values()), default=0))

    update_gui_metrics(agg.copy())

    payload = {"features": agg}
    headers = {
        "api-key": API_KEY,
        "auth-key": AUTH_KEY
    }
    detected_label = 'BENIGN'

    try:
        if gui_http_client is None:
            log_message("❌ HTTP 클라이언트가 초기화되지 않았습니다.", 'ERROR')
            return

        response = gui_http_client.post(API_URL, json=payload, headers=headers)

        if response.status_code == 200:
            result = response.json()
            log_message("API 응답 수신", 'SERVER_RESPONSE', data=result)
            detected_label = result.get('category', 'IDLE')
            agg['Label'] = detected_label
            update_gui_metrics(agg)
        else:
            log_message(f"❌ API 오류: {response.status_code} - {response.text}", 'ERROR')

    except httpx.ConnectError:
        log_message(f"❌ 연결 실패: 분석 서버({API_URL})가 실행 중인지 확인하세요.", 'ERROR')
    except httpx.ReadTimeout:
        log_message(f"❌ 전송 시간 초과.", 'ERROR')
    except Exception as e:
        log_message(f"❌ 전송 중 알 수 없는 오류: {e}", 'ERROR')

    process_window_results(df, detected_label)

def create_json_report():
    with RISK_IP_LOCK:
        threat_list_for_json = []
        for ip, data in RISK_IP_STORAGE.items():
            events = data.get('events', [])
            if not events:
                continue
            total_hits = sum(e['count'] for e in events)
            threat_entry = {
                "source_ip": ip,
                "total_hits": total_hits,
                "last_seen": datetime.fromtimestamp(data['last_seen']).isoformat(),
                "events": events
            }
            threat_list_for_json.append(threat_entry)
        report_data = {
            "report_time": now_iso(),
            "total_unique_threat_ips": len(threat_list_for_json),
            "threat_ip_list": sorted(threat_list_for_json, key=lambda x: x['total_hits'], reverse=True)
        }
        json_output = json.dumps(report_data, indent=4, ensure_ascii=False)
        return json_output

def process_commands():
    global command_queue
    try:
        while True:
            (msg_type, message, data) = command_queue.get_nowait()
            if msg_type == 'COMMAND' and message.startswith("GUI: Remove IP"):
                ip_to_remove = data.get('ip')
                if ip_to_remove:
                    ip_was_removed = False
                    with RISK_IP_LOCK:
                        if ip_to_remove in RISK_IP_STORAGE:
                            del RISK_IP_STORAGE[ip_to_remove]
                            ip_was_removed = True
                            log_message(f"ℹ️ {ip_to_remove}가 GUI 요청으로 마스터 목록에서 삭제되었습니다.", 'INFO')
                        else:
                            log_message(f"ℹ️ {ip_to_remove}는 이미 마스터 목록에 없습니다.", 'INFO')
                    if ip_was_removed:
                        threading.Thread(target=_send_json_report_threaded, daemon=True).start()
            command_queue.task_done()
    except queue.Empty:
        pass
    except Exception as e:
        log_message(f"❌ 명령 처리 중 오류: {e}", 'ERROR')

def window_worker(stop_event: threading.Event):
    while not stop_event.wait(CHUNK_DURATION):
        try:
            process_commands()
            expire_flows_and_collect()
            with window_lock:
                chunk = window_buffer.copy()
                window_buffer.clear()
            compute_window_features(chunk)
        except Exception:
            log_message(f"윈도우 작업자 오류: {traceback.format_exc()}", 'ERROR')

def capture_logic(stop_event: threading.Event,
                  api_url, risk_json_upload_url,
                  api_key, auth_key, iface, chunk_duration, flow_inactivity,
                  ip_hit_threshold,
                  log_q: queue.Queue,
                  metrics_q: queue.Queue,
                  risk_q: queue.Queue,
                  cmd_q: queue.Queue
                  ):
    global gui_http_client, flows, window_buffer, recent_fsr, dst_persist, RISK_IP_STORAGE
    global API_URL, RISK_JSON_UPLOAD_URL, API_KEY, AUTH_KEY, NETWORK_INTERFACE, CHUNK_DURATION, FLOW_INACTIVITY, IP_HIT_THRESHOLD
    global log_queue, metrics_queue, risk_update_queue, command_queue

    API_URL = api_url
    RISK_JSON_UPLOAD_URL = risk_json_upload_url
    API_KEY = api_key
    AUTH_KEY = auth_key
    NETWORK_INTERFACE = iface
    CHUNK_DURATION = chunk_duration
    FLOW_INACTIVITY = flow_inactivity
    IP_HIT_THRESHOLD = ip_hit_threshold
    log_queue = log_q
    metrics_queue = metrics_q
    risk_update_queue = risk_q
    command_queue = cmd_q

    if not all([API_URL, API_KEY, AUTH_KEY, NETWORK_INTERFACE]):
        log_message("❌ API 설정 또는 네트워크 인터페이스가 지정되지 않았습니다. '설정' 탭을 확인하세요.", 'ERROR')
        return

    if not RISK_JSON_UPLOAD_URL or RISK_JSON_UPLOAD_URL == "http://example.com/api/risk-ips":
        log_message("⚠️ '설정' 탭에서 [위험 IP 전송 URL]이 설정되지 않았습니다. (실시간 JSON 전송 비활성화)", 'WARNING')
    else:
        pass

    try:
        gui_http_client = httpx.Client(timeout=15.0)
    except Exception as e:
        log_message(f"❌ HTTP 클라이언트 초기화 실패: {e}", 'ERROR')
        return

    with flows_lock:
        flows = {}
    with window_lock:
        window_buffer = []

    recent_fsr = []
    dst_persist = {}

    while not risk_update_queue.empty(): risk_update_queue.get_nowait()
    while not command_queue.empty(): command_queue.get_nowait()

    if IP_HIT_THRESHOLD > 0:
        log_message(f"ℹ️ IP 접속 횟수 임계값 활성화: {int(IP_HIT_THRESHOLD)}회", 'INFO')
    else:
        log_message(f"ℹ️ IP 접속 횟수 임계값 비활성화됨.", 'INFO')

    # 초기화 시 자동으로 로컬 IP를 수집해 EXCLUDE_IPS에 추가 (운영 중 변경 없음)
    _ensure_local_ips_populated()
    # log_message(f"ℹ️ 자동 제외 IP: {sorted(list(EXCLUDE_IPS))}", 'INFO')

    worker = threading.Thread(target=window_worker, args=(stop_event,), daemon=True)
    worker.start()

    sniffer = None
    try:
        conf.use_pcap = True
        sniffer = AsyncSniffer(iface=NETWORK_INTERFACE, filter="ip", prn=process_packet, store=False)
        sniffer.start()
        log_message(f"스니퍼 시작됨. 인터페이스: {NETWORK_INTERFACE}", 'INFO')

        stop_event.wait()
        log_message("종료 신호 수신, 정리 중...", 'INFO')

    except Exception as e:
        log_message(f"❌ 스니퍼 오류: {e}\n{traceback.format_exc()}", 'ERROR')
        log_message("❌ '설정' 탭에서 네트워크 인터페이스가 올바른지 확인하세요.", 'ERROR')

    finally:
        if sniffer and getattr(sniffer, "running", False):
            try:
                sniffer.stop()
                log_message("스니퍼 중지됨.", 'INFO')
            except Exception:
                pass

        process_commands()

        try:
            expire_flows_and_collect()
            with window_lock:
                chunk = window_buffer.copy()
            if chunk:
                log_message("마지막 플로우 처리 중...", 'INFO')
                compute_window_features(chunk)
        except Exception:
            pass

        save_risk_ips_to_file()
        log_message("캡처가 중지되었습니다. 최종 RISK_IP_STORAGE 상태가 저장되었습니다.", 'INFO')

        if gui_http_client:
            gui_http_client.close()
            log_message("HTTP 클라이언트 종료됨.", 'INFO')