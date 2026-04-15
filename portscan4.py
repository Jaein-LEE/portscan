import nmap
import pandas as pd
import socket
import requests
import paramiko
import ftplib
import os

# 1단계: Nmap 스캔
def run_nmap_scan(target):
    print(f"--- 1단계: {target} 스캔 및 포트 추출 ---")
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-F')
    
    scan_data = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]['name']
                scan_data.append({'host': host, 'port': port, 'service': service})
    return pd.DataFrame(scan_data)

# 2단계용 체크 함수들
def check_web(host, port):
    try:
        r = requests.get(f"http://{host}:{port}", timeout=1, verify=False)
        return "Success" if r.status_code < 400 else "Fail"
    except: return "Fail"

def check_ssh(host, port):
    try:
        t = paramiko.Transport((host, int(port)))
        t.connect(); t.close()
        return "Success"
    except: return "Fail"

def check_ftp(host, port):
    try:
        ftp = ftplib.FTP(); ftp.connect(host, int(port), timeout=1); ftp.quit()
        return "Success"
    except: return "Fail"

def check_telnet(host, port):
    try:
        # telnetlib 대신 socket을 이용한 배너 확인 시도 (더 안정적)
        s = socket.create_connection((host, port), timeout=2)
        s.sendall(b"\r\n")
        data = s.recv(1024)
        s.close()
        return "Success" if data else "Port Open"
    except: return "Fail"

# 3 & 4단계: 결과 분석 및 MobaXterm 전용 CSV 생성
def create_final_output(df):
    print("--- 2단계: 서비스 분석 및 MobaXterm용 CSV 생성 시작 ---")
    results = []
    moba_csv_data = []

    for _, row in df.iterrows():
        h, p, s_name = row['host'], row['port'], row['service']
        
        # 서비스 체크 수행
        web_res = check_web(h, p)
        ssh_res = check_ssh(h, p)
        ftp_res = check_ftp(h, p)
        telnet_res = check_telnet(h, p)

        # 엑셀 리포트용 데이터 저장
        status = {
            'IP': h, 'Port': p, 'Service': s_name,
            'Web_Res': web_res, 'SSH_Res': ssh_res,
            'FTP_Res': ftp_res, 'Telnet_Res': telnet_res
        }
        results.append(status)

        # 4단계: MobaXterm Import용 CSV 데이터 구성
        # 형식: SessionName, Protocol, Host, Port
        if ssh_res == "Success":
            moba_csv_data.append([f"{h}_{p}_SSH", "SSH", h, p])
        
        if web_res != "Fail":
            moba_csv_data.append([f"{h}_{p}_Web", "Browser", h, p])
            
        if ftp_res == "Success":
            moba_csv_data.append([f"{h}_{p}_FTP", "FTP", h, p])
            
        if telnet_res == "Success" and ssh_res == "Fail":
            moba_csv_data.append([f"{h}_{p}_Telnet", "Telnet", h, p])

    # 1. 일반 분석 엑셀 저장
    pd.DataFrame(results).to_excel("final_audit_report.xlsx", index=False)
    
    # 2. MobaXterm 전용 CSV 저장 (헤더 없음 - MobaXterm 임포트 규격)
    moba_df = pd.DataFrame(moba_csv_data)
    moba_df.to_csv("moba_import_list.csv", index=False, header=False, encoding='utf-8-sig')
    
    print(f"--- 완료! ---")
    print(f"1. 상세 분석 리포트: final_audit_report.xlsx")
    print(f"2. MobaXterm 임포트용 파일: moba_import_list.csv")

if __name__ == "__main__":
    target = input("대상 IP 입력: ")
    raw_df = run_nmap_scan(target)
    if not raw_df.empty:
        create_final_output(raw_df)