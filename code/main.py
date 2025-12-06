# main.py
import os
import sys
import queue
import json
import tkinter as tk
import customtkinter as ctk

# 모듈 임포트
import gui
import capture_logic

# =================================================================
# --- 전역 설정 및 헬퍼 ---
# =================================================================
# 설정 파일
CONFIG_FILE = "config.json"

# 기본값 설정 (config.json에서 덮어씀)
DEFAULT_API_URL = "https://network-ai-analysis.onrender.com/predict"
DEFAULT_RISK_JSON_UPLOAD_URL = "https://network-security-service-ma6i.vercel.app/api-management/ip-threats"  # <<< [신규] 위험 IP 실시간 전송 URL
DEFAULT_API_KEY = ""
DEFAULT_AUTH_KEY = ""
DEFAULT_NETWORK_INTERFACE = "Wi-Fi"
DEFAULT_CHUNK_DURATION = 5.0
DEFAULT_FLOW_INACTIVITY = 10.0
DEFAULT_RAM_USAGE_LIMIT = 90.0
DEFAULT_IP_HIT_THRESHOLD = 1000.0

# gui.py의 전역 변수를 기본값으로 설정
gui.API_URL = DEFAULT_API_URL
gui.RISK_JSON_UPLOAD_URL = DEFAULT_RISK_JSON_UPLOAD_URL  # <<< [신규]
gui.API_KEY = DEFAULT_API_KEY
gui.AUTH_KEY = DEFAULT_AUTH_KEY
gui.NETWORK_INTERFACE = DEFAULT_NETWORK_INTERFACE
gui.CHUNK_DURATION = DEFAULT_CHUNK_DURATION
gui.FLOW_INACTIVITY = DEFAULT_FLOW_INACTIVITY
gui.RAM_USAGE_LIMIT = DEFAULT_RAM_USAGE_LIMIT
gui.IP_HIT_THRESHOLD = DEFAULT_IP_HIT_THRESHOLD

# GUI <-> 백그라운드 스레드 통신용 큐 (gui.py와 동일한 객체 사용)
gui.log_queue = queue.Queue()  # 로그 메시지용
gui.metrics_queue = queue.Queue()  # 지표 업데이트용
gui.risk_update_queue = queue.Queue()  # <<< [신규] 실시간 위험 IP 업데이트용 (json_report_queue 대체)
gui.command_queue = queue.Queue()  # <<< [신규] GUI -> 백그라운드 명령 전달용 (IP 삭제 등)

# capture_logic 모듈에도 큐 객체 동기화
capture_logic.log_queue = gui.log_queue
capture_logic.metrics_queue = gui.metrics_queue
capture_logic.risk_update_queue = gui.risk_update_queue  # <<< [신규]
capture_logic.command_queue = gui.command_queue  # <<< [신규]

# =================================================================
# --- 메인 실행 로직 ---
# =================================================================
if __name__ == "__main__":
    # Windows에서 Scapy가 Npcap을 사용하도록 설정 (선택 사항)
    if os.name == 'nt':
        try:
            # Npcap 드라이버 경로 추가 (일반적인 설치 경로)
            os.add_dll_directory(r"C:\Program Files\Npcap")
        except Exception:
            pass  # Npcap이 없거나 다른 경로에 있을 수 있음

    app = gui.FlowAnalyzerApp()

    # 로그 색상 태그 설정
    app.log_text.tag_config("log_alert", foreground="#E74C3C")
    app.log_text.tag_config("log_warn", foreground="#F39C12")
    app.log_text.tag_config("log_info", foreground="gray40")
    app.log_text.tag_config("log_error", foreground="red")

    # [신규] 위험 IP 로그 탭 색상 설정
    if hasattr(app, 'risk_ip_log_text'):
        app.risk_ip_log_text.tag_config("ip_alert", foreground="red")
        app.risk_ip_log_text.tag_config("ip_type", foreground="#E74C3C")
        app.risk_ip_log_text.tag_config("log_info", foreground="gray40")

    try:
        app.mainloop()
    except Exception as e:
        print(f"GUI 메인 루프 오류: {e}")
