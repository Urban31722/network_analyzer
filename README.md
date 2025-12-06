# network_analyzer
##### AION 프로젝트 네트워크 분석기 부분입니다. (필요한 코드 특징을 받아 수정 후 넘김)
---
## 코드 파일 구성
* capture_logic.py
* gui.py
* main.py
---
## capture_logic.py 핵심코드
> 데이터 분석의 핵심 단위인 플로우가 누적하는 정보
```python
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
```
> 패킷이 들어왔을 때 플로우를 생성하는 방법과, 여러 특징들을 어떻게 누적하는지 보여주는 부분
```python
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

            # 신규 플로우 생성
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

            # TCP 플래그 누적
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
```
> AI에 제공될 특징 중 엔트로피, 비율, 속도 크기를 계산하는 방법을 보여주는 부분
```python
def compute_window_features(chunk_rows):

    # 흐름 시작률(FSR) 계산
    flow_count = len(df)
    flow_start_rate = flow_count / float(CHUNK_DURATION) if CHUNK_DURATION > 0 else 0.0
    # ... (FSR 통계 및 증가율 계산)
    agg['flow_start_rate'] = float(flow_start_rate)
    agg['fsr_mean'] = float(fsr_mean)
    agg['fsr_rate_increase'] = float(fsr_rate_increase)

    # 프로토콜 비율 계산
    den = packet_count_sum + 1e-9
    agg['tcp_ratio'] = tcp_pkt_sum / den
    agg['udp_ratio'] = udp_pkt_sum / den
    agg['icmp_ratio'] = icmp_pkt_sum / den

    # 엔트로피 계산
    agg['src_ip_entropy'] = float(entropy_of_counts(df['src_ip']) if 'src_ip' in df.columns else 0.0)
    agg['dst_port_entropy'] = float(entropy_of_counts(df['dstport']) if 'dstport' in df.columns else 0.0)
    
    # ... (AI 서버로 전송)
    payload = {"features": agg}
```
---
## gui.py
