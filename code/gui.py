# gui.py
import os
import sys
import time
import threading
import traceback
import queue
import json
from typing import Dict, Any, List
from functools import partial

# GUI 라이브러리
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import psutil

# capture_logic 모듈 import
import capture_logic

# =================================================================
# --- 전역 설정 및 헬퍼 (main.py에서 초기화됨) ---
# =================================================================
CONFIG_FILE = "config.json"
RAM_USAGE_LIMIT = 90.0
IP_HIT_THRESHOLD = 1000.0

# GUI <-> 백그라운드 스레드 통신용 큐 (main.py에서 주입됨)
log_queue = None
metrics_queue = None
risk_update_queue = None
command_queue = None

# 초기 설정값 (load_config에서 덮어씀)
API_URL = "https://network-ai-analysis.onrender.com/predict"
RISK_JSON_UPLOAD_URL = "https://network-security-service-ma6i.vercel.app/api-management/ip-threats"
API_KEY = ""
AUTH_KEY = ""
NETWORK_INTERFACE = "Wi-Fi"
CHUNK_DURATION = 5.0
FLOW_INACTIVITY = 10.0


# 캡처 로직 모듈의 헬퍼 함수를 사용할 수 있도록 캡처 로직 모듈의 큐 동기화
def log_message(message: str, level: str = 'INFO', data: Dict[str, Any] = None):
    """ GUI 로깅 헬퍼 (capture_logic과 동일) """
    if log_queue:
        log_queue.put((level, message, data or {}))


def send_command(message: str, data: Dict[str, Any] = None):
    """ GUI에서 백그라운드 스레드로 명령을 전송합니다. """
    if command_queue:
        command_queue.put(('COMMAND', message, data or {}))


# =================================================================
# --- GUI 클래스 (CustomTkinter) ---
# =================================================================
class FlowAnalyzerApp(ctk.CTk):
    METRIC_GROUPS = {
        # ... (METRIC_GROUPS 내용은 원본과 동일) ...
        "Core": {
            'flow_count': "총 Flow 수",
            'packet_count_sum': "총 패킷량 (개)",
            'byte_count_sum': "총 바이트량 (B)",
            'flow_start_rate': "Flow 시작 속도 (F/s)",
            'src_ip_nunique': "출발지 IP 수",
            'dst_ip_nunique': "목적지 IP 수",
            'dst_port_nunique': "목적지 포트 다양성",
        },
        "ProtoFlag": {
            'syn_flag_ratio': "SYN 플래그 비율",
            'tcp_ratio': "TCP 비중",
            'udp_ratio': "UDP 비중",
            'icmp_ratio': "ICMP 비중",
            'fwd_bwd_pkt_ratio': "송/수신 패킷 비율",
            'udp_port_53_hit_sum': "UDP 53 (DNS) 히트",
            'udp_port_123_hit_sum': "UDP 123 (NTP) 히트",
            'udp_port_1900_hit_sum': "UDP 1900 (SSDP) 히트",
            'udp_port_1434_hit_sum': "UDP 1434 (MS-SQL) 히트",
        },
        "DistAnalysis": {
            'top_src_count': "Top Src Flow 수",
            'top_dst_port_1': "최다 대상 포트",
            'top_dst_port_1_hits': "최다 포트 히트 수",
            'src_ip_entropy': "출발지 IP 엔트로피",
            'src_proto_bitmask_nunique': "Src 프로토콜 비트마스크 수",
            'src_proto_multi_protocol_fraction': "Src 다중 프로토콜 비율",
            'max_dst_persist': "최대 대상 지속 카운트",
        }
    }

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")

        self.title("🌐 AION Sentinel")
        self.geometry("1200x800")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.is_capturing = False
        self.capture_thread = None
        self.stop_event = None

        self.risk_ip_list_widgets: Dict[str, Dict[str, Any]] = {}
        self.command_queue = command_queue

        # 변수 정의
        self.api_url_var = tk.StringVar(value=API_URL)
        self.risk_json_url_var = tk.StringVar(value=RISK_JSON_UPLOAD_URL)
        self.api_key_var = tk.StringVar(value=API_KEY)
        self.auth_key_var = tk.StringVar(value=AUTH_KEY)
        self.net_iface_var = tk.StringVar(value=NETWORK_INTERFACE)
        self.chunk_duration_var = tk.StringVar(value=str(CHUNK_DURATION))
        self.inactivity_timeout_var = tk.StringVar(value=str(FLOW_INACTIVITY))
        self.ram_limit_var = tk.StringVar(value=str(RAM_USAGE_LIMIT))
        self.ip_hit_threshold_var = tk.StringVar(value=str(IP_HIT_THRESHOLD))

        self.metric_labels = {}
        self.toggle_frames = {}

        # 1. 프로그램 시작 시, 저장된 위험 IP 목록을 파일에서 로드
        capture_logic.load_risk_ips_from_file()

        self.setup_ui()
        self.load_config()

        # 2. 로드된 IP 목록을 GUI에 즉시 반영
        self.populate_risk_list_from_storage()

        self.after(100, self.poll_log_queue)
        self.after(100, self.poll_metrics_queue)
        self.after(100, self.poll_risk_update_queue)
        self.after(1000, self.update_system_status)

        # 3. 종료 시 저장 함수(on_closing) 연결
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.select_frame_by_name("Dashboard")

    # --- 설정 파일 관리 ---
    def load_config(self):
        """API 및 Flow 설정 로드"""
        global API_URL, RISK_JSON_UPLOAD_URL, API_KEY, AUTH_KEY, NETWORK_INTERFACE, CHUNK_DURATION, FLOW_INACTIVITY, RAM_USAGE_LIMIT, IP_HIT_THRESHOLD
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    API_URL = config.get('API_URL', API_URL)
                    RISK_JSON_UPLOAD_URL = config.get('RISK_JSON_UPLOAD_URL', RISK_JSON_UPLOAD_URL)
                    API_KEY = config.get('API_KEY', API_KEY)
                    AUTH_KEY = config.get('AUTH_KEY', AUTH_KEY)
                    NETWORK_INTERFACE = config.get('NETWORK_INTERFACE', NETWORK_INTERFACE)
                    CHUNK_DURATION = config.get('CHUNK_DURATION', CHUNK_DURATION)
                    FLOW_INACTIVITY = config.get('FLOW_INACTIVITY', FLOW_INACTIVITY)
                    RAM_USAGE_LIMIT = config.get('RAM_USAGE_LIMIT', RAM_USAGE_LIMIT)
                    IP_HIT_THRESHOLD = config.get('IP_HIT_THRESHOLD', IP_HIT_THRESHOLD)

                self.api_url_var.set(API_URL)
                self.risk_json_url_var.set(RISK_JSON_UPLOAD_URL)
                self.api_key_var.set(API_KEY)
                self.auth_key_var.set(AUTH_KEY)
                self.net_iface_var.set(NETWORK_INTERFACE)
                self.chunk_duration_var.set(str(CHUNK_DURATION))
                self.inactivity_timeout_var.set(str(FLOW_INACTIVITY))
                self.ram_limit_var.set(str(RAM_USAGE_LIMIT))
                self.ip_hit_threshold_var.set(str(IP_HIT_THRESHOLD))
                log_message("ℹ️ 설정 파일에서 정보를 불러왔습니다.", 'INFO')
            except Exception as e:
                log_message(f"❌ 설정 파일 로드 오류: {e}", 'ERROR')
        else:
            log_message("ℹ️ 설정 파일(config.json)이 없어 초기 상태로 시작합니다.", 'INFO')

    def save_config(self):
        """API 및 Flow 설정 저장"""
        global API_URL, RISK_JSON_UPLOAD_URL, API_KEY, AUTH_KEY, NETWORK_INTERFACE, CHUNK_DURATION, FLOW_INACTIVITY, RAM_USAGE_LIMIT, IP_HIT_THRESHOLD

        API_URL = self.api_url_var.get().strip()
        RISK_JSON_UPLOAD_URL = self.risk_json_url_var.get().strip()
        API_KEY = self.api_key_var.get().strip()
        AUTH_KEY = self.auth_key_var.get().strip()

        NETWORK_INTERFACE = self.net_iface_var.get().strip()

        if not NETWORK_INTERFACE:
            log_message("❌ 네트워크 인터페이스를 설정해야 합니다.", 'ERROR')
            return False

        try:
            chunk_val = float(self.chunk_duration_var.get())
            inactivity_val = float(self.inactivity_timeout_var.get())
            ram_limit_val = float(self.ram_limit_var.get())
            ip_hit_val = float(self.ip_hit_threshold_var.get())
        except ValueError:
            log_message("❌ 시간제한 및 임계값은 유효한 숫자여야 합니다. 저장 실패.", 'ERROR')
            return False

        CHUNK_DURATION = chunk_val
        FLOW_INACTIVITY = inactivity_val
        RAM_USAGE_LIMIT = ram_limit_val
        IP_HIT_THRESHOLD = ip_hit_val

        config = {
            'API_URL': API_URL,
            'RISK_JSON_UPLOAD_URL': RISK_JSON_UPLOAD_URL,
            'API_KEY': API_KEY,
            'AUTH_KEY': AUTH_KEY,
            'NETWORK_INTERFACE': NETWORK_INTERFACE,
            'CHUNK_DURATION': CHUNK_DURATION,
            'FLOW_INACTIVITY': FLOW_INACTIVITY,
            'RAM_USAGE_LIMIT': RAM_USAGE_LIMIT,
            'IP_HIT_THRESHOLD': IP_HIT_THRESHOLD
        }

        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            log_message("✅ 모든 설정 정보가 저장되었습니다.", 'INFO')
            return True
        except Exception as e:
            log_message(f"❌ 설정 파일 저장 오류: {e}", 'ERROR')
            return False

    # --- UI 구성 ---
    def setup_ui(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#F0F0F0")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🌐 AION Sentinel",
                                       font=ctk.CTkFont(size=20, weight="bold"),
                                       text_color="#1f6aa5")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        button_font = ctk.CTkFont(size=15, weight="normal")

        # 메뉴 버튼
        self.dashboard_menu_button = self._create_nav_button("🛡️ 실시간 분석", 1, "Dashboard", button_font)
        self.status_menu_button = self._create_nav_button("📊 상태 대시보드", 2, "Status", button_font)
        self.risk_ip_button = self._create_nav_button("🚨 위험 IP 목록", 3, "RiskIPList", button_font)  # Row 변경: 4 -> 3
        self.settings_api_button = self._create_nav_button("⚙️ 설정 및 인증 관리", 4, "SettingsAndAPI",  # Row 변경: 5 -> 4
                                                           button_font)

        # 프레임 정의 (로그 프레임 정의 제거)
        self.dashboard_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="white")
        self.status_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="#ECF0F1", label_text="",
                                                   label_text_color="#1f6aa5",
                                                   label_font=ctk.CTkFont(size=16, weight="bold"))
        self.risk_ip_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="white")

        self.settings_api_frame = ctk.CTkScrollableFrame(self, corner_radius=10, fg_color="white")

        self._setup_dashboard_frame()
        self._setup_status_frame()
        self._setup_risk_ip_frame()
        self._setup_settings_api_frame()

    def _create_nav_button(self, text, row, name, font):
        btn = ctk.CTkButton(self.sidebar_frame, text=text,
                            fg_color="transparent", hover_color="#D9D9D9",
                            font=font, text_color="gray20",
                            command=lambda: self.select_frame_by_name(name),
                            anchor="w")
        btn.grid(row=row, column=0, padx=10, pady=(5, 5), sticky="ew")
        return btn

    def select_frame_by_name(self, name):
        button_map = {
            "Dashboard": self.dashboard_menu_button, "Status": self.status_menu_button,
            "RiskIPList": self.risk_ip_button, "SettingsAndAPI": self.settings_api_button
        }
        frame_map = {
            "Dashboard": self.dashboard_frame, "Status": self.status_frame,
            "RiskIPList": self.risk_ip_frame, "SettingsAndAPI": self.settings_api_frame
        }

        for btn in button_map.values(): btn.configure(fg_color="transparent")
        for frame in frame_map.values(): frame.grid_forget()

        button_map[name].configure(fg_color="#D9D9D9")
        frame_map[name].grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    def _setup_dashboard_frame(self):
        # 레이아웃 변경: 상단 요약/버튼 (Row 0) + 하단 로그 제목 (Row 1) + 하단 로그 텍스트 (Row 2)
        self.dashboard_frame.grid_rowconfigure(0, weight=0)  # 상단은 내용 크기에 맞게
        self.dashboard_frame.grid_rowconfigure(1, weight=0)  # 로그 제목은 내용 크기에 맞게
        self.dashboard_frame.grid_rowconfigure(2, weight=1)  # 로그 텍스트가 남은 공간을 모두 차지

        self.dashboard_frame.grid_columnconfigure(0, weight=1)

        # 1. 상단 상태 요약 및 버튼 통합 프레임
        summary_frame = ctk.CTkFrame(self.dashboard_frame, fg_color="#ECF0F1", corner_radius=10)
        # ➡️ 상단 상자의 하단 여백을 없애서 아래 로그 제목에 최대한 붙입니다.
        summary_frame.grid(row=0, column=0, padx=20, pady=(20, 0), sticky="ew")
        summary_frame.grid_columnconfigure(0, weight=1)
        summary_frame.grid_columnconfigure(1, weight=0)  # 버튼 영역

        # 1-1. 시스템 상태 및 탐지 레이블 (왼쪽)
        left_summary_frame = ctk.CTkFrame(summary_frame, fg_color="transparent")
        left_summary_frame.grid(row=0, column=0, padx=(15, 10), pady=10, sticky="nsew")
        left_summary_frame.grid_columnconfigure(0, weight=1)

        self.system_status_label = ctk.CTkLabel(left_summary_frame, text="시스템 상태: RAM 사용량 N/A | CPU N/A",
                                                font=ctk.CTkFont(size=14), text_color="gray40")
        self.system_status_label.grid(row=0, column=0, pady=(0, 5), sticky="w")

        self.detection_label = ctk.CTkLabel(left_summary_frame, text="최근 판정: 대기 중",
                                            font=ctk.CTkFont(size=18, weight="bold"), text_color="gray50")
        self.detection_label.grid(row=1, column=0, pady=5, sticky="w")

        self.status_label = ctk.CTkLabel(left_summary_frame, text="상태: 대기 중",
                                         font=ctk.CTkFont(size=16), text_color="gray50")
        self.status_label.grid(row=2, column=0, pady=(5, 0), sticky="w")

        # 1-2. 감지 시작/중단 버튼 (오른쪽)
        self.guard_button = ctk.CTkButton(summary_frame,
                                          text="🛡️ 감지 시작",
                                          command=lambda: self.toggle_capture(),
                                          width=150, height=80,
                                          corner_radius=10,
                                          fg_color="gray60",
                                          hover_color="gray50",
                                          font=ctk.CTkFont(size=18, weight="bold"),
                                          text_color="white",
                                          border_width=2,
                                          border_color="gray70",
                                          anchor="center")
        self.guard_button.grid(row=0, column=1, padx=(10, 15), pady=15, sticky="e")

        # 2. 실시간 로그 제목 (Row 1)
        ctk.CTkLabel(self.dashboard_frame, text="📜 실시간 로그 및 AI 분석 결과",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="gray20").grid(row=1, column=0, padx=20, pady=(5, 5),
                                               sticky="w")  # ➡️ pady를 (5, 5)로 최소화

        # 3. 로그 텍스트 박스 (Row 2)
        self.log_text = ctk.CTkTextbox(self.dashboard_frame, wrap='word', state=tk.DISABLED, fg_color="white",
                                       text_color="black")
        self.log_text.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")  # ➡️ pady=(0, 20)로 상단 여백 제거

        # 로그 텍스트 색상 태그 설정 (CustomTkinter 호환성을 위해 font 옵션 제거)
        self.log_text.tag_config("log_alert", foreground="red")
        self.log_text.tag_config("log_warn", foreground="orange")
        self.log_text.tag_config("log_error", foreground="#C0392B")
        self.log_text.tag_config("log_info", foreground="gray40")

    def _setup_status_frame(self):
        """
        상태 대시보드 프레임을 McAfee 스타일의 카드 레이아웃으로 변경
        """
        # Status 프레임의 컬럼 가중치 설정 (3열)
        self.status_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # -------------------------------------------------------------
        # 0. 상단 탐지 결과 섹션
        # -------------------------------------------------------------
        top_detect_frame = ctk.CTkFrame(self.status_frame, fg_color="white", corner_radius=10,
                                        border_color="#1f6aa5", border_width=2)
        top_detect_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=(15, 10), sticky="ew")
        top_detect_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top_detect_frame, text="📡", font=ctk.CTkFont(size=40)).grid(row=0, column=0, rowspan=2,
                                                                                 padx=(20, 10), sticky="w")

        self.status_current_label = ctk.CTkLabel(top_detect_frame, text="대기 중",
                                                 font=ctk.CTkFont(size=24, weight="bold"), text_color="gray50")
        self.status_current_label.grid(row=0, column=1, padx=(0, 20), pady=(10, 0), sticky="w")
        ctk.CTkLabel(top_detect_frame, text="[최근 AI 탐지 결과]", font=ctk.CTkFont(size=14), text_color="gray40").grid(row=1,
                                                                                                                  column=1,
                                                                                                                  padx=(
                                                                                                                      0,
                                                                                                                      20),
                                                                                                                  pady=(
                                                                                                                      0,
                                                                                                                      10),
                                                                                                                  sticky="w")

        self.metric_labels["current_label"] = self.status_current_label

        # -------------------------------------------------------------
        # 1. 핵심 지표 카드 (Core Metrics: 3x2 구조)
        # -------------------------------------------------------------
        row_idx = 1
        # 핵심 지표 6개
        core_keys = ['flow_count', 'byte_count_sum', 'packet_count_sum',
                     'src_ip_nunique', 'dst_ip_nunique', 'dst_port_nunique']

        for i, key in enumerate(core_keys):
            col = i % 3
            row = row_idx + (i // 3)

            display_name = self.METRIC_GROUPS["Core"].get(key, key)

            card_frame = ctk.CTkFrame(self.status_frame, fg_color="white", corner_radius=10, border_color="gray70",
                                      border_width=1)
            card_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nsew", ipadx=5, ipady=5)
            card_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(card_frame, text=display_name, font=ctk.CTkFont(size=12), text_color="gray50").grid(row=0,
                                                                                                             column=0,
                                                                                                             padx=10,
                                                                                                             pady=(10,
                                                                                                                   0),
                                                                                                             sticky="nw")

            value_label = ctk.CTkLabel(card_frame, text="0.00", font=ctk.CTkFont(size=22, weight="bold"),
                                       text_color="#1f6aa5")
            value_label.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="se")

            self.metric_labels[key] = value_label

        current_row = row_idx + 2  # Core Metrics는 2줄 사용 (1행, 2행)

        # -------------------------------------------------------------
        # 2. 상세 분석 지표 그룹 카드 배치
        # -------------------------------------------------------------

        # --- 2-1. ProtoFlag (9개 지표, 3x3 배열) ---
        ctk.CTkLabel(self.status_frame, text="--- 🟡 프로토콜 · 플래그 이상 감지 ---", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#F39C12").grid(row=current_row, column=0, columnspan=3, padx=10, pady=(20, 10),
                                                sticky="w")
        current_row += 1
        current_row = self._create_detail_group(self.status_frame, "ProtoFlag", current_row, 3, "#F39C12")

        # --- 2-2. DistAnalysis (7개 지표, 4+3 배열) ---
        ctk.CTkLabel(self.status_frame, text="--- 🔴 분산성 · 공격원 분석 ---", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#E74C3C").grid(row=current_row, column=0, columnspan=3, padx=10, pady=(20, 10),
                                                sticky="w")
        current_row += 1
        current_row = self._create_detail_group(self.status_frame, "DistAnalysis", current_row, 4, "#E74C3C")

    def _create_detail_group(self, parent_frame, group_key, start_row, cards_per_row, color):
        """
        상세 지표 그룹을 카드 레이아웃으로 배치
        """
        metrics = list(self.METRIC_GROUPS[group_key].items())
        current_row = start_row

        if group_key == "DistAnalysis":
            # DistAnalysis 특수 처리: 4개 (Row 1), 3개 (Row 2)
            metrics_1st_row = metrics[:4]
            metrics_2nd_row = metrics[4:]

            # 첫 번째 줄 (4칸)
            for i, (key, display_name) in enumerate(metrics_1st_row):
                col = i % cards_per_row  # 4
                row = start_row

                card_frame = ctk.CTkFrame(parent_frame, fg_color="white", corner_radius=8,
                                          border_color=color, border_width=1)
                card_frame.grid(row=row, column=col, padx=8, pady=5, sticky="nsew", ipadx=5, ipady=5)
                card_frame.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(card_frame, text=display_name, font=ctk.CTkFont(size=11), text_color="gray50").grid(row=0,
                                                                                                                 column=0,
                                                                                                                 padx=8,
                                                                                                                 pady=(
                                                                                                                     8,
                                                                                                                     0),
                                                                                                                 sticky="nw")
                value_label = ctk.CTkLabel(card_frame, text="0.00", font=ctk.CTkFont(size=18, weight="bold"),
                                           text_color=color)
                value_label.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="se")
                self.metric_labels[key] = value_label

            current_row += 1

            # 두 번째 줄 (3칸)
            for i, (key, display_name) in enumerate(metrics_2nd_row):
                col = i % 3
                row = current_row

                card_frame = ctk.CTkFrame(parent_frame, fg_color="white", corner_radius=8,
                                          border_color=color, border_width=1)
                card_frame.grid(row=row, column=col, padx=8, pady=5, sticky="nsew", ipadx=5, ipady=5)
                card_frame.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(card_frame, text=display_name, font=ctk.CTkFont(size=11), text_color="gray50").grid(row=0,
                                                                                                                 column=0,
                                                                                                                 padx=8,
                                                                                                                 pady=(
                                                                                                                     8,
                                                                                                                     0),
                                                                                                                 sticky="nw")
                value_label = ctk.CTkLabel(card_frame, text="0.00", font=ctk.CTkFont(size=18, weight="bold"),
                                           text_color=color)
                value_label.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="se")
                self.metric_labels[key] = value_label

            return current_row + 1

        else:  # ProtoFlag (3x3 배열)의 경우
            for i, (key, display_name) in enumerate(metrics):
                col = i % cards_per_row  # 3
                row = start_row + (i // cards_per_row)

                if row > current_row:
                    current_row = row

                card_frame = ctk.CTkFrame(parent_frame, fg_color="white", corner_radius=8,
                                          border_color=color, border_width=1)
                card_frame.grid(row=row, column=col, padx=8, pady=5, sticky="nsew", ipadx=5, ipady=5)
                card_frame.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(card_frame, text=display_name, font=ctk.CTkFont(size=11), text_color="gray50").grid(row=0,
                                                                                                                 column=0,
                                                                                                                 padx=8,
                                                                                                                 pady=(
                                                                                                                     8,
                                                                                                                     0),
                                                                                                                 sticky="nw")
                value_label = ctk.CTkLabel(card_frame, text="0.00", font=ctk.CTkFont(size=18, weight="bold"),
                                           text_color=color)
                value_label.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="se")
                self.metric_labels[key] = value_label

            return current_row + 1

    def _setup_risk_ip_frame(self):
        self.risk_ip_frame.grid_rowconfigure(0, weight=0)
        self.risk_ip_frame.grid_rowconfigure(2, weight=1)
        self.risk_ip_frame.grid_columnconfigure(0, weight=7)
        self.risk_ip_frame.grid_columnconfigure(1, weight=3)

        ctk.CTkLabel(self.risk_ip_frame, text="🚨 실시간 위험 IP 탐지 목록",
                     font=ctk.CTkFont(size=20, weight="bold"), text_color="#E74C3C"
                     ).grid(row=0, column=0, columnspan=2, padx=10, pady=(15, 5), sticky="w")

        ctk.CTkLabel(self.risk_ip_frame, text="실시간 탐지 상세 로그",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color="gray20"
                     ).grid(row=1, column=0, padx=10, pady=(10, 5), sticky="w")

        self.risk_ip_log_text = ctk.CTkTextbox(self.risk_ip_frame,
                                               wrap='word',
                                               state=tk.DISABLED,
                                               fg_color="white",
                                               text_color="black",
                                               )
        self.risk_ip_log_text.grid(row=2, column=0, padx=(10, 5), pady=(0, 10), sticky="nsew")

        ctk.CTkLabel(self.risk_ip_frame, text="위험 IP 요약",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color="gray20"
                     ).grid(row=1, column=1, padx=10, pady=(10, 5), sticky="w")

        self.risk_ip_list_frame = ctk.CTkScrollableFrame(self.risk_ip_frame,
                                                         fg_color="#ECF0F1",
                                                         corner_radius=8)
        self.risk_ip_list_frame.grid(row=2, column=1, padx=(5, 10), pady=(0, 10), sticky="nsew")
        self.risk_ip_list_frame.grid_columnconfigure(0, weight=1)

        self.risk_ip_log_text.tag_config("ip_alert", foreground="red")
        self.risk_ip_log_text.tag_config("ip_type", foreground="#E74C3C")
        self.risk_ip_log_text.tag_config("log_info", foreground="gray40")

        self.risk_ip_log_text.configure(state=tk.NORMAL)
        self.risk_ip_log_text.insert(tk.END, "--- 프로그램 시작. 저장된 로그를 불러왔습니다. ---\n\n", "log_info")
        self.risk_ip_log_text.configure(state=tk.DISABLED)

    def _setup_settings_api_frame(self):
        # (이전과 동일: RISK_JSON_UPLOAD_URL 입력란 포함)
        self.settings_api_frame.grid_columnconfigure(0, weight=1)
        self.settings_api_frame.grid_columnconfigure(1, weight=3)
        ctk.CTkLabel(self.settings_api_frame, text="⚙️ 설정 및 인증 관리", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="gray20").grid(row=0, column=0, columnspan=2, padx=30, pady=(30, 20), sticky="w")

        row_idx = 1

        ctk.CTkLabel(self.settings_api_frame, text="--- 🔑 AI 분석 서버 인증 ---", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#1f6aa5").grid(row=row_idx, column=0, columnspan=2, padx=30, pady=(20, 10), sticky="w")
        row_idx += 1

        self._create_input_row(self.settings_api_frame, "API Key (Hash):", self.api_key_var,
                               "AI 모델 접근 키 해시값", row_idx)
        row_idx += 1
        self._create_input_row(self.settings_api_frame, "인증 Key (AUTH):", self.auth_key_var,
                               "사용자 인증 및 JSON 전송 인증 키", row_idx)
        row_idx += 1

        ctk.CTkLabel(self.settings_api_frame, text="--- 📡 네트워크 Flow 분석 설정 ---",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color="#1f6aa5").grid(row=row_idx, column=0,
                                                                                          columnspan=2, padx=30,
                                                                                          pady=(30, 10), sticky="w")
        row_idx += 1

        ctk.CTkLabel(self.settings_api_frame, text="네트워크 인터페이스:", anchor="w", text_color="gray20").grid(row=row_idx,
                                                                                                        column=0,
                                                                                                        padx=(30, 10),
                                                                                                        pady=15,
                                                                                                        sticky="w")
        iface_options = ["Wi-Fi", "이더넷"]
        self.net_iface_combobox = ctk.CTkComboBox(self.settings_api_frame, values=iface_options,
                                                  variable=self.net_iface_var, state="normal", width=300)
        self.net_iface_combobox.grid(row=row_idx, column=1, padx=(10, 30), pady=15, sticky="ew")
        row_idx += 1

        self._create_input_row(self.settings_api_frame, "윈도우 집계 시간 (초):", self.chunk_duration_var, "5.0", row_idx, True)
        row_idx += 1
        self._create_input_row(self.settings_api_frame, "Flow 비활성 제한 시간 (초):", self.inactivity_timeout_var, "10.0",
                               row_idx, True)
        row_idx += 1
        self._create_input_row(self.settings_api_frame, "RAM 사용량 경고 기준 (%):", self.ram_limit_var, "90.0", row_idx, True)
        row_idx += 1

        ctk.CTkLabel(self.settings_api_frame, text="--- 🚨 위험 IP 임계값 설정 ---",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color="#E74C3C").grid(row=row_idx, column=0,
                                                                                          columnspan=2, padx=20,
                                                                                          pady=(30, 10), sticky="w")
        row_idx += 1
        self._create_input_row(self.settings_api_frame, "IP 접속 횟수 임계값 (Window):", self.ip_hit_threshold_var, "1000",
                               row_idx, True)
        ctk.CTkLabel(self.settings_api_frame, text="(0 입력 시 비활성화)", anchor="w", text_color="gray50",
                     font=ctk.CTkFont(size=14)).grid(row=row_idx, column=0, padx=(30, 10), pady=(55,10), sticky="nw")
        row_idx += 1

        self.save_settings_button = ctk.CTkButton(self.settings_api_frame, text="✅ 모든 설정 저장 및 반영",
                                                  command=lambda: self.save_config(), fg_color="#1f6aa5",
                                                  hover_color="#3085C9")
        self.save_settings_button.grid(row=row_idx, column=0, columnspan=2, padx=20, pady=40)
        row_idx += 1

    # --- 실시간 대시보드 업데이트 ---
    def update_metrics(self, features: Dict[str, Any]):
        # ... (원본과 동일) ...
        label = features.get("Label", None)
        if label is not None:
            if label not in ["BENIGN", "IDLE", "정상"]:
                self.metric_labels["current_label"].configure(text=label, text_color="#E74C3C")
                self.detection_label.configure(text=f"최근 판정: 🚨 {label} 공격 의심", text_color="#E74C3C")
            elif label in ["BENIGN", "정상"]:
                self.metric_labels["current_label"].configure(text=label, text_color="#27AE60")
                self.detection_label.configure(text=f"최근 판정: ✅ 정상 트래픽", text_color="#27AE60")
            else:
                self.metric_labels["current_label"].configure(text="대기 중", text_color="gray50")
                self.detection_label.configure(text="최근 판정: 대기 중", text_color="gray50")

        for key, value_label in self.metric_labels.items():
            if key == "current_label": continue

            value = features.get(key)
            if value is not None:
                if key in ['packet_count_sum', 'byte_count_sum', 'top_dst_port_1', 'top_dst_port_1_hits', 'flow_count',
                           'udp_port_53_hit_sum', 'udp_port_123_hit_sum', 'udp_port_1900_hit_sum',
                           'udp_port_1434_hit_sum', 'top_src_count', 'max_dst_persist']:
                    formatted_value = f"{int(value):,}"
                else:
                    formatted_value = f"{value:.2f}"
                value_label.configure(text=formatted_value)

    # --- [수정] 프로그램 시작 시, 저장된 IP 목록을 GUI에 채우는 함수 ---
    def populate_risk_list_from_storage(self):
        """
        capture_logic에 로드된 RISK_IP_STORAGE의 모든 내용을 가져와
        GUI의 위험 IP 요약 목록을 채웁니다. (프로그램 시작 시 1회 호출)
        """
        try:
            current_ip_data = capture_logic.get_current_risk_ips()

            if not current_ip_data:
                log_message("GUI: 이전에 저장된 위험 IP가 없습니다.", 'INFO')
                return

            log_message(f"GUI: {len(current_ip_data)}개의 저장된 위험 IP를 목록에 표시합니다.", 'INFO')

            # (IP, data) 쌍을 튜플 리스트로 변환
            # <<< [수정] total_hits 계산 방식 변경 (Counter -> list) >>>
            sorted_ips = sorted(
                current_ip_data.items(),
                key=lambda item: sum(event['count'] for event in item[1].get('events', [])),
                reverse=True
            )

            for ip, data in sorted_ips:
                # <<< [수정] total_hits 계산 방식 변경 >>>
                total_hits = sum(event['count'] for event in data.get('events', []))

                ip_data_dict = {
                    'ip': ip,
                    'total_hits': total_hits
                }
                self.update_risk_ip_list(ip_data_dict)

        except Exception as e:
            log_message(f"❌ 저장된 위험 IP 목록 GUI 반영 중 오류: {e}", 'ERROR')

    # --- 실시간 위험 IP 탭 - 왼쪽 상세 로그 업데이트 ---
    def update_risk_ip_log(self, ip_data: Dict[str, Any]):
        """'위험 IP 목록' 탭의 왼쪽 상세 로그 텍스트박스에 내용을 추가합니다."""

        ip = ip_data.get('ip', 'N/A')
        attack_type = ip_data.get('attack_type', 'N/A')
        total_hits = ip_data.get('total_hits', 0)  # total_hits는 이제 누적 총합
        last_seen = ip_data.get('last_seen', 'N/A')
        count_value = ip_data.get('count_value', 1)  # 이번 이벤트의 횟수

        # <<< [수정] 로그 메시지 변경 >>>
        if attack_type == "IP_Threshold_Exceeded":
            attack_name = f"IP 임계값 초과 ({count_value}회)"
        elif attack_type == "Port_Scan":
            attack_name = "Port Scan (AI)"
        elif attack_type == "Slowloris_Attack":
            attack_name = "Slowloris (AI)"
        else:
            attack_name = attack_type

        self.risk_ip_log_text.configure(state=tk.NORMAL)

        log_entry = f"[{last_seen}] ", ("log_info")
        self.risk_ip_log_text.insert(tk.END, log_entry[0], log_entry[1])

        log_entry = f"UPDATE: {ip} ", ("ip_alert")
        self.risk_ip_log_text.insert(tk.END, log_entry[0], log_entry[1])

        log_entry = f"({attack_name} 탐지) ", ("ip_type")
        self.risk_ip_log_text.insert(tk.END, log_entry[0], log_entry[1])

        log_entry = f"-> 총 {total_hits:,}회\n", ("log_info")
        self.risk_ip_log_text.insert(tk.END, log_entry[0], log_entry[1])

        self.risk_ip_log_text.see(tk.END)
        self.risk_ip_log_text.configure(state=tk.DISABLED)

    # --- 실시간 위험 IP 탭 - 오른쪽 요약 목록 업데이트 ---
    def update_risk_ip_list(self, ip_data: Dict[str, Any]):
        """'위험 IP 목록' 탭의 오른쪽 요약 목록을 생성하거나 업데이트합니다."""

        ip = ip_data.get('ip')
        if not ip:
            return

        total_hits = ip_data.get('total_hits', 1)  # 누적 총합

        if ip in self.risk_ip_list_widgets:
            widget_dict = self.risk_ip_list_widgets[ip]
            widget_dict['hits_label'].configure(text=f"총 {total_hits:,}회")  # 1,000단위 콤마

        else:
            entry_frame = ctk.CTkFrame(self.risk_ip_list_frame, fg_color="white", corner_radius=5)
            entry_frame.grid(sticky="ew", pady=(0, 5))
            entry_frame.grid_columnconfigure(0, weight=1)
            entry_frame.grid_columnconfigure(1, weight=0)
            entry_frame.grid_columnconfigure(2, weight=0)

            ip_label = ctk.CTkLabel(entry_frame, text=ip, font=ctk.CTkFont(size=14, weight="bold"),
                                    text_color="#E74C3C")
            ip_label.grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")

            hits_label = ctk.CTkLabel(entry_frame, text=f"총 {total_hits:,}회", font=ctk.CTkFont(size=12),
                                      text_color="gray20")
            hits_label.grid(row=0, column=1, padx=5, pady=5, sticky="e")

            remove_button = ctk.CTkButton(entry_frame, text="X", width=25, height=25, fg_color="gray70",
                                          hover_color="gray50",
                                          command=partial(self.remove_risk_ip, ip))
            remove_button.grid(row=0, column=2, padx=(5, 10), pady=5, sticky="e")

            self.risk_ip_list_widgets[ip] = {
                'frame': entry_frame,
                'hits_label': hits_label
            }

    # --- 위험 IP 목록에서 IP 제거 ---
    def remove_risk_ip(self, ip_to_remove: str):
        """(X 버튼 클릭 시) GUI 목록에서 IP를 제거하고, 백그라운드에 삭제 명령을 전송합니다."""

        if ip_to_remove in self.risk_ip_list_widgets:
            self.risk_ip_list_widgets[ip_to_remove]['frame'].destroy()
            del self.risk_ip_list_widgets[ip_to_remove]
            log_message(f"GUI: {ip_to_remove}를 목록에서 제거합니다.", 'INFO')

        send_command(f"GUI: Remove IP {ip_to_remove}", {'ip': ip_to_remove})

    # --- 캡처 제어 (capture_logic 모듈 호출) ---
    def toggle_capture(self):
        """캡처 시작/중단 토글"""

        if not self.is_capturing and not self.save_config():
            messagebox.showerror("오류", "설정 오류로 인해 캡처를 시작할 수 없습니다. '설정 및 인증 관리' 탭을 확인해주세요.")
            self.select_frame_by_name("SettingsAndAPI")
            return

        if self.is_capturing:
            log_message("🔥 캡처 중단 요청...")
            if self.stop_event: self.stop_event.set()
            self.is_capturing = False
            self.guard_button.configure(text="🛡️ 감지 시작", fg_color="gray60", hover_color="gray50",
                                        border_color="gray70")
            self.status_label.configure(text="상태: 정리 중...", text_color="orange")
            self.after(500, self.check_thread_completion)
        else:
            log_message("--------------------------------------------------")
            log_message(f"✨ 네트워크 Flow 분석 및 AI 전송 시작 (Window: {CHUNK_DURATION}s, Idle: {FLOW_INACTIVITY}s)...", 'INFO')

            self.is_capturing = True
            self.guard_button.configure(text="🛡️✅ 감지 중", fg_color="#1f6aa5", hover_color="#3085C9",
                                        border_color="#1f6aa5")
            self.status_label.configure(text="상태: 정상 작동", text_color="#1f6aa5")

            self.stop_event = threading.Event()

            self.capture_thread = threading.Thread(target=capture_logic.capture_logic,
                                                   args=(self.stop_event,
                                                         API_URL,
                                                         RISK_JSON_UPLOAD_URL,
                                                         API_KEY,
                                                         AUTH_KEY,
                                                         NETWORK_INTERFACE,
                                                         CHUNK_DURATION,
                                                         FLOW_INACTIVITY,
                                                         IP_HIT_THRESHOLD,
                                                         log_queue,
                                                         metrics_queue,
                                                         risk_update_queue,
                                                         command_queue
                                                         ),
                                                   daemon=True)
            self.capture_thread.start()

    def check_thread_completion(self):
        """캡처 스레드 종료 확인"""
        if self.capture_thread and self.capture_thread.is_alive():
            self.after(500, self.check_thread_completion)
        else:
            self.is_capturing = False
            self.status_label.configure(text="상태: 대기 중", text_color="gray50")
            log_message("=== 모든 프로세스 종료 완료 ===", 'INFO')
            self.capture_thread = None
            self.stop_event = None

    # --- 로그 출력 ---
    def log_to_gui(self, message_type, message, data: Dict[str, Any]):
        self.log_text.configure(state=tk.NORMAL)

        if message_type == 'ATTACK':
            timestamp = time.strftime('[%H:%M:%S]')
            self.log_text.insert(tk.END, f"{timestamp} {message}\n", "log_alert")

        elif message_type == 'SERVER_RESPONSE':
            # ... (기존 SERVER_RESPONSE 로직 동일) ...
            result = data
            category = result.get('category', 'Unknown')
            detection = result.get('detection_result', 'N/A')
            confidence = result.get('confidence', '0.00%')

            timestamp = time.strftime('[%H:%M:%S]')
            log_lines = []
            log_tag = "log_info"

            log_lines.append("\n" + "-" * 50 + "\n")

            if category not in ["BENIGN", "정상"]:
                log_lines.append(f"{timestamp} 🚨 [AI-공격 탐지!] -> [{detection}] ({confidence})\n")
                log_tag = "log_alert"
            else:
                log_lines.append(f"{timestamp} ✅ [AI-정상 트래픽] -> [{detection}] ({confidence})\n")
                log_tag = "log_info"

            features = result.get('key_features_evidence', {})

            core = features.get('core_metrics', {})
            log_lines.append(
                f"     [핵심 지표] Flows: {core.get('flow_count', '?')}, Pkts: {core.get('packet_count_sum', '?')}, Bytes: {core.get('byte_count_sum', '?')}\n")
            log_lines.append(
                f"     [분산성] Src IPs: {core.get('src_ip_nunique', '?')}, Dst Ports: {core.get('dst_port_nunique', '?')}\n")

            signals = features.get('protocol_signals', {})
            tcp_r = signals.get('tcp_ratio', 0) * 100
            udp_r = signals.get('udp_ratio', 0) * 100
            icmp_r = signals.get('icmp_ratio', 0) * 100
            log_lines.append(
                f"     [프로토콜] TCP: {tcp_r:.1f}%, UDP: {udp_r:.1f}%, ICMP: {icmp_r:.1f}%\n")

            analysis = features.get('source_analysis', {})
            log_lines.append(
                f"     [공격 분석] Top Dst Port: {analysis.get('top_dst_port_1', '?')} ({analysis.get('top_dst_port_1_hits', '?')} hits)\n")

            log_lines.append("-" * 50 + "\n")

            self.log_text.insert(tk.END, "".join(log_lines), log_tag)

        else:
            timestamp = time.strftime("[%H:%M:%S]")
            tag = "log_info"
            if message_type == 'WARNING':
                tag = "log_warn"
            elif message_type == 'ERROR':
                tag = "log_error"
            if message_type != 'COMMAND':
                self.log_text.insert(tk.END, f"{timestamp} {message}\n", tag)

        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def poll_log_queue(self):
        """주기적으로 로그 큐를 확인하여 GUI에 출력"""
        try:
            while True:
                message_type, message, data = log_queue.get_nowait()
                self.log_to_gui(message_type, message, data)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.poll_log_queue)

    def poll_metrics_queue(self):
        """주기적으로 지표 큐를 확인하여 GUI에 업데이트"""
        try:
            while True:
                features = metrics_queue.get_nowait()
                self.update_metrics(features)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.poll_metrics_queue)

    def poll_risk_update_queue(self):
        """주기적으로 위험 IP 큐를 확인하여 '위험 IP 목록' 탭을 실시간 업데이트합니다."""
        try:
            while True:
                ip_data = risk_update_queue.get_nowait()

                self.update_risk_ip_log(ip_data)
                self.update_risk_ip_list(ip_data)

        except queue.Empty:
            pass
        except Exception as e:
            log_message(f"❌ 위험 IP 큐 처리 오류: {e}", 'ERROR')
        finally:
            self.after(100, self.poll_risk_update_queue)

    def on_closing(self):
        """프로그램 종료 시 캡처 스레드 안전 종료 및 위험 IP 목록 저장"""

        log_message("ℹ️ 프로그램을 종료합니다. 위험 IP 목록을 저장 중...", 'INFO')
        capture_logic.save_risk_ips_to_file()

        if self.capture_thread and self.capture_thread.is_alive():
            log_message("창 종료... 캡처 스레드 중지 요청.", 'INFO')
            self.toggle_capture()
            self.after(1000, self.destroy)
        else:
            self.destroy()

    def update_net_iface_from_manual(self, var_name, index, mode):
        pass

            

    def update_system_status(self):
        try:
            ram_percent = psutil.virtual_memory().percent
            cpu_percent = psutil.cpu_percent(interval=None)

            ram_color = "red" if ram_percent >= RAM_USAGE_LIMIT else "gray40"

            self.system_status_label.configure(
                text=f"시스템 상태: RAM 사용량 {ram_percent:.1f}% | CPU {cpu_percent:.1f}%",
                text_color=ram_color
            )

            if ram_percent >= RAM_USAGE_LIMIT and self.is_capturing:
                log_message(f"⚠️ 경고: RAM 사용량({ram_percent:.1f}%)이 {RAM_USAGE_LIMIT}%를 초과했습니다. 성능 저하 우려.", 'WARNING')

        except Exception:
            pass

        self.after(2000, self.update_system_status)

    def _create_input_row(self, frame, label_text, textvariable, placeholder, row_idx, is_number_field=False):
        ctk.CTkLabel(frame, text=label_text, anchor="w", text_color="gray20").grid(row=row_idx, column=0, padx=(30, 10),
                                                                                   pady=15, sticky="w")
        entry = ctk.CTkEntry(frame, textvariable=textvariable, placeholder_text=placeholder)
        entry.grid(row=row_idx, column=1, padx=(10, 30), pady=15, sticky="ew")

        if is_number_field:
            def validate_number(P):
                return P.replace('.', '', 1).isdigit() or P == ""

            vcmd = frame.register(validate_number)
            entry.configure(validate="key", validatecommand=(vcmd, '%P'))

        return entry
