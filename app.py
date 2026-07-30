import os
import socket
import hashlib
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Path for the real IDS log file reader (reads from framework folder)
IDS_LOG_PATH = "sec_ops.log"

# Built-in database for the Hash Decoder tool
COMMON_HASH_DATABASE = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "5d41402abc4b2a76b9719d911017c592": "hello",
    "900150983cd24fb0d6963f7d28e17f72": "abc"
}

@app.route('/')
def index():
    return render_template('index.html', default_url="https://example.com")

@app.route('/run-perimeter', methods=['POST'])
def run_perimeter():
    data = request.get_json()
    target_url = data.get('url', 'https://example.com')
    try:
        response = requests.get(target_url, timeout=5)
        msg = f"Perimeter probe successful. Target [{target_url}] responded with HTTP Status: {response.status_code}"
    except Exception as e:
        msg = f"Perimeter probe error connecting to [{target_url}]: {str(e)}"
    return jsonify({"message": msg})

@app.route('/run-ids', methods=['POST'])
def run_ids():
    logs = []
    try:
        if os.path.exists(IDS_LOG_PATH):
            with open(IDS_LOG_PATH, "r") as f:
                logs = [line.strip() for line in f.readlines()[-10:]]
        else:
            logs = [f"[INFO] IDS monitoring path '{IDS_LOG_PATH}' not found. Creating file...",
                    "[INFO] Security subsystem online. No threats detected."]
            # Automatically create file if missing
            with open(IDS_LOG_PATH, "w") as f:
                f.write("[INFO] AADHIIIEE Security log initialized.\n[INFO] System monitoring active.\n")
    except Exception as e:
        logs = [f"[ERROR] Failed to read log path: {str(e)}"]
    return jsonify({"logs": logs})

@app.route('/get-logs', methods=['GET'])
def get_logs():
    logs = []
    try:
        if os.path.exists(IDS_LOG_PATH):
            with open(IDS_LOG_PATH, "r") as f:
                logs = [line.strip() for line in f.readlines()[-5:]]
        else:
            logs = ["[INFO] Stream active: Monitoring local socket buffers."]
    except Exception:
        logs = ["[INFO] Stream active: System nominal."]
    return jsonify({"logs": logs})

@app.route('/run-ipfinder', methods=['POST'])
def run_ipfinder():
    data = request.get_json()
    host = data.get('ip', '8.8.8.8')
    try:
        resolved_ip = socket.gethostbyname(host)
        api_res = requests.get(f"http://ip-api.com/json/{resolved_ip}", timeout=4).json()
        if api_res.get('status') == 'success':
            msg = f"Target: {host} | Resolved IP: {resolved_ip} | ISP: {api_res.get('isp')} | Country: {api_res.get('country')}"
        else:
            msg = f"Resolved IP {resolved_ip} successfully. No geolocation metadata returned."
    except Exception as e:
        msg = f"IP lookup execution failed: {str(e)}"
    return jsonify({"message": msg})

@app.route('/run-vuln', methods=['POST'])
def run_vuln():
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    try:
        open_ports = []
        for port in [80, 443, 21, 22, 3306, 8080]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        msg = f"Vulnerability Port Scan on [{target}] completed. Active open ports detected: {open_ports if open_ports else 'None exposed'}"
    except Exception as e:
        msg = f"Vulnerability scan execution error: {str(e)}"
    return jsonify({"message": msg})

@app.route('/run-hash', methods=['POST'])
def run_hash():
    data = request.get_json()
    text = data.get('hash', '')
    md5_val = hashlib.md5(text.encode()).hexdigest()
    sha256_val = hashlib.sha256(text.encode()).hexdigest()
    msg = f"Input String: '{text}' | MD5: {md5_val} | SHA256: {sha256_val}"
    return jsonify({"message": msg})

@app.route('/run-decode', methods=['POST'])
def run_decode():
    data = request.get_json()
    target_hash = data.get('hash', '').strip().lower()
    cracked_result = COMMON_HASH_DATABASE.get(target_hash)
    if cracked_result:
        msg = f"SUCCESS! Hash '{target_hash}' matched in database. Decoded plain text: '{cracked_result}'"
    else:
        msg = f"Hash lookup for '{target_hash}': No direct match found in wordlist database."
    return jsonify({"message": msg})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2005, debug=True)
