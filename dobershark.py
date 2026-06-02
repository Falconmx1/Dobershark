#!/usr/bin/env python3
# Dobershark v4.0 - HTTP file extraction + TCP session reassembly + Packet injection
# "El Doberman ahora reconstruye, extrae y muerde activamente"
# Compatible: Windows (Npcap), Linux, Termux

import sys
import os
import signal
import re
import hashlib
import threading
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

# ========== CONFIGURACIÓN ==========
SILENT_MODE = False
HTTP_DOWNLOAD_DIR = "http_downloads"
TCP_SESSION_DIR = "tcp_sessions"
SMB_FILE_DIR = "smb_extracted"
INJECTION_RULES = []

for dir_name in [HTTP_DOWNLOAD_DIR, TCP_SESSION_DIR, SMB_FILE_DIR]:
    os.makedirs(dir_name, exist_ok=True)

# ========== TCP SESSION REASSEMBLY ==========
class TCPSession:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.buffer = b''
        self.segments = {}  # seq -> data
        self.next_seq = None
        self.start_time = datetime.now()
        self.last_seen = datetime.now()
        self.bytes_received = 0
        self.bytes_sent = 0
        
    def add_segment(self, seq, data, direction='rx'):
        self.last_seen = datetime.now()
        if direction == 'rx':
            self.bytes_received += len(data)
        else:
            self.bytes_sent += len(data)
        
        # Reensamblaje simple (ordenar por seq)
        self.segments[seq] = data
        self._reassemble()
    
    def _reassemble(self):
        if not self.segments:
            return
        
        # Ordenar segmentos por número de secuencia
        sorted_seqs = sorted(self.segments.keys())
        
        # Si no tenemos next_seq, empezar con el seq más bajo
        if self.next_seq is None:
            self.next_seq = sorted_seqs[0]
            self.buffer = b''
        
        # Agregar segmentos en orden
        new_buffer = b''
        current_seq = self.next_seq
        
        for seq in sorted_seqs:
            if seq == current_seq:
                new_buffer += self.segments[seq]
                current_seq += len(self.segments[seq])
        
        if new_buffer:
            self.buffer = new_buffer
            self.next_seq = current_seq
            # Guardar sesión periódicamente
            if len(self.buffer) > 1024 * 10:  # Cada 10KB
                self.save_session()
    
    def save_session(self):
        if len(self.buffer) > 0:
            filename = f"{TCP_SESSION_DIR}/{self.key.replace(':', '_')}_{self.start_time.strftime('%Y%m%d_%H%M%S')}.bin"
            with open(filename, 'wb') as f:
                f.write(self.buffer)
            if not SILENT_MODE:
                print(f"[TCP Session] Guardada: {filename} ({len(self.buffer)} bytes)")
    
    def get_stats(self):
        return {
            'bytes_rx': self.bytes_received,
            'bytes_tx': self.bytes_sent,
            'duration': (datetime.now() - self.start_time).total_seconds(),
            'packets': len(self.segments)
        }

tcp_sessions = {}

# ========== HTTP FILE EXTRACTION ==========
class HTTPFileExtractor:
    def __init__(self):
        self.downloads = {}  # connection -> {'data': b'', 'filename': None, 'headers': {}}
        self.content_lengths = {}
        
    def extract_filename(self, headers, url):
        # Intentar extraer nombre del Content-Disposition
        if 'Content-Disposition' in headers:
            match = re.search(r'filename="?([^"]+)"?', headers['Content-Disposition'])
            if match:
                return match.group(1)
        
        # Del URL
        if url:
            filename = url.split('/')[-1].split('?')[0]
            if filename and '.' in filename and len(filename) < 255:
                return filename
        
        # Por defecto
        return f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
    
    def process_response(self, conn_key, response_data, headers, url):
        if conn_key not in self.downloads:
            self.downloads[conn_key] = {'data': b'', 'filename': None, 'headers': headers}
        
        download = self.downloads[conn_key]
        download['data'] += response_data
        download['headers'] = headers
        
        if not download['filename']:
            download['filename'] = self.extract_filename(headers, url)
        
        # Verificar si completamos la descarga (por Content-Length)
        content_length = int(headers.get('Content-Length', 0))
        if content_length > 0 and len(download['data']) >= content_length:
            self.save_file(conn_key)
        # También guardar si hay chunked encoding y vemos el final
        elif b'0\r\n\r\n' in response_data[-10:]:
            self.save_file(conn_key)
    
    def save_file(self, conn_key):
        download = self.downloads[conn_key]
        if len(download['data']) > 0:
            filepath = os.path.join(HTTP_DOWNLOAD_DIR, download['filename'])
            # Evitar sobrescritura
            counter = 1
            original = filepath
            while os.path.exists(filepath):
                name, ext = os.path.splitext(original)
                filepath = f"{name}_{counter}{ext}"
                counter += 1
            
            with open(filepath, 'wb') as f:
                f.write(download['data'])
            
            md5 = hashlib.md5(download['data']).hexdigest()
            if not SILENT_MODE:
                print(f"[📥 HTTP Download] {download['filename']} -> {filepath}")
                print(f"  Size: {len(download['data'])} bytes | MD5: {md5}")
            
            del self.downloads[conn_key]

http_extractor = HTTPFileExtractor()

# ========== PACKET INJECTION ENGINE ==========
class PacketInjector:
    def __init__(self, iface):
        self.iface = iface
        self.injected_count = 0
        self.rules = []  # (filter_function, response_packet)
        
    def add_rule(self, filter_func, response_packet):
        """Agrega una regla: si filter_func(packet) es True, inyecta response_packet"""
        self.rules.append((filter_func, response_packet))
    
    def inject_packet(self, packet):
        """Inyecta un paquete en la red"""
        try:
            sendp(packet, iface=self.iface, verbose=False)
            self.injected_count += 1
            if not SILENT_MODE:
                print(f"[💉 Injected] {packet.summary()}")
        except Exception as e:
            print(f"[!] Injection error: {e}")
    
    def check_rules(self, packet):
        """Verifica si algún paquete dispara una regla de inyección"""
        for filter_func, response in self.rules:
            if filter_func(packet):
                self.inject_packet(response)
                break

# ========== DOBERMAN BANNER ==========
BANNER = """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║         🐕‍🦺 DOBERSHARK v4.0 - TCP REASSEMBLY + HTTP EXTRACTION + INJECTION  ║
    ║   "Reconstruye, extrae y muerde activamente. El Doberman total."    ║
    ╚═══════════════════════════════════════════════════════════════════════╝

         __
        / _)   ¡GRRR-RRR! Ahora también inyecto paquetes.
       | (    
        ¯¯¯
"""

running = True
injector = None

def signal_handler(sig, frame):
    global running
    print("\n[Dobershark] Cerrando sesiones y guardando archivos...")
    
    # Guardar todas las sesiones TCP pendientes
    for session in tcp_sessions.values():
        session.save_session()
    
    if injector and injector.injected_count > 0:
        print(f"[💉] Total paquetes inyectados: {injector.injected_count}")
    
    running = False
    sys.exit(0)

def extract_http_headers(payload):
    """Extrae cabeceras HTTP de datos binarios"""
    try:
        # Buscar el final de las cabeceras (\r\n\r\n)
        header_end = payload.find(b'\r\n\r\n')
        if header_end > 0:
            headers_raw = payload[:header_end].decode('utf-8', errors='ignore')
            headers = {}
            for line in headers_raw.split('\r\n'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            # Extraer URL de la primera línea si es request
            first_line = headers_raw.split('\r\n')[0]
            if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    return headers, parts[1]
            return headers, None
    except:
        pass
    return {}, None

def packet_callback(packet):
    """Procesador principal con reassembly, extracción e inyección"""
    global injector
    
    # ========== INYECCIÓN: Verificar reglas primero ==========
    if injector:
        injector.check_rules(packet)
    
    # ========== TCP SESSION REASSEMBLY ==========
    if TCP in packet and IP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload = bytes(tcp_layer.payload)
        
        if len(payload) == 0:
            return  # Sin datos útiles
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        seq = tcp_layer.seq
        
        # Clave de sesión (bidireccional)
        session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        
        if session_key in tcp_sessions:
            session = tcp_sessions[session_key]
            session.add_segment(seq, payload, 'rx')
        elif reverse_key in tcp_sessions:
            session = tcp_sessions[reverse_key]
            session.add_segment(seq, payload, 'tx')
        else:
            # Nueva sesión
            session = TCPSession(src_ip, src_port, dst_ip, dst_port)
            session.add_segment(seq, payload, 'rx')
            tcp_sessions[session_key] = session
            
            if not SILENT_MODE:
                print(f"\n[TCP Session] Nueva: {session_key}")
        
        # ========== HTTP FILE EXTRACTION ==========
        if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
            if len(payload) > 0:
                # Intentar extraer HTTP response
                if b'HTTP/' in payload[:20] and (b'200 OK' in payload[:100] or b'206 Partial' in payload[:100]):
                    headers, _ = extract_http_headers(payload)
                    if headers:
                        # Buscar Content-Type que sugiera archivo
                        content_type = headers.get('Content-Type', '')
                        if any(x in content_type.lower() for x in ['application', 'image', 'video', 'audio', 'octet-stream']):
                            # Extraer el cuerpo después de las cabeceras
                            header_end = payload.find(b'\r\n\r\n')
                            if header_end > 0:
                                body = payload[header_end + 4:]
                                conn_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                                # Extraer URL de la request correspondiente (simplificado)
                                url = headers.get('Content-Location', headers.get('Location', '/'))
                                http_extractor.process_response(conn_key, body, headers, url)

def create_injection_packet(template_packet, modifications):
    """Crea un paquete para inyectar basado en uno capturado"""
    pkt = template_packet.copy()
    for layer, fields in modifications.items():
        if hasattr(pkt, layer):
            for field, value in fields.items():
                setattr(pkt[layer], field, value)
    return pkt

def load_injection_rules():
    """Carga reglas de inyección predefinidas (ejemplo)"""
    if not injector:
        return
    
    # Regla 1: Responder a pings ICMP (mostrar presencia)
    def icmp_filter(packet):
        return ICMP in packet and packet[ICMP].type == 8  # Echo Request
    
    # Construir respuesta ICMP Echo Reply
    def make_icmp_reply(original):
        reply = IP(src=original[IP].dst, dst=original[IP].src)/ICMP(type=0, id=original[ICMP].id, seq=original[ICMP].seq)
        return reply
    
    injector.add_rule(icmp_filter, make_icmp_reply)
    
    # Regla 2: Bloquear paquetes a cierta IP (responder con RST)
    def rst_filter(packet):
        if TCP in packet and packet[TCP].dport == 22:  # SSH
            target_ip = "192.168.1.100"  # Cambiar por IP a bloquear
            return packet[IP].dst == target_ip
    
    def make_rst_packet(original):
        rst = IP(src=original[IP].dst, dst=original[IP].src)/TCP(
            sport=original[TCP].dport,
            dport=original[TCP].sport,
            seq=original[TCP].ack,
            ack=original[TCP].seq + 1,
            flags='R'
        )
        return rst
    
    injector.add_rule(rst_filter, make_rst_packet)
    
    if not SILENT_MODE:
        print("[Injection] Reglas cargadas: ICMP reply + TCP RST a SSH")

def parse_hex_packet(hex_string):
    """Convierte string hexadecimal a paquete para inyección"""
    try:
        raw_bytes = bytes.fromhex(hex_string)
        return Ether(raw_bytes)
    except:
        return None

def main():
    global running, injector, SILENT_MODE
    
    # Parsear argumentos
    iface = None
    filtro = None
    output_file = None
    list_interfaces = False
    inject_hex = None
    custom_rule = None
    
    for i, arg in enumerate(sys.argv):
        if arg in ["--list-interfaces", "-l"]:
            list_interfaces = True
        elif arg in ["--silent", "-s"]:
            SILENT_MODE = True
        elif arg == "--bite":
            # Modo mordida activa (inyección)
            custom_rule = True
        elif arg == "--inject-hex" and i+1 < len(sys.argv):
            inject_hex = sys.argv[i+1]
        elif arg == "-i" and i+1 < len(sys.argv):
            iface = sys.argv[i+1]
        elif arg == "-f" and i+1 < len(sys.argv):
            filtro = sys.argv[i+1]
        elif arg == "-o" and i+1 < len(sys.argv):
            output_file = sys.argv[i+1]
    
    if not SILENT_MODE:
        print(BANNER)
    else:
        print("[Dobershark] Modo silencioso")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    if list_interfaces:
        print("\n[Interfaces detectadas:]")
        for iface_name in get_if_list():
            print(f"  - {iface_name}")
        return
    
    if not iface:
        print("[!] Uso: python dobershark.py -i <interfaz> [--bite] [--inject-hex <hex>]")
        print("[!] Ver interfaces: python dobershark.py --list-interfaces")
        print("\nNuevos modos:")
        print("  --bite              Activa inyección activa (responde pings, bloquea SSH)")
        print("  --inject-hex <hex>  Inyecta un paquete personalizado (hex string)")
        print("  -s                  Modo silencioso (sin banner)")
        sys.exit(1)
    
    # Inicializar inyector
    injector = PacketInjector(iface)
    
    # Inyección de paquete único
    if inject_hex:
        packet = parse_hex_packet(inject_hex)
        if packet:
            injector.inject_packet(packet)
            print(f"[*] Paquete inyectado en {iface}")
        else:
            print("[!] Hex inválido. Usa formato: '001122334455...'")
        return
    
    # Cargar reglas de inyección si está en modo bite
    if custom_rule:
        load_injection_rules()
        if not SILENT_MODE:
            print("[🐕‍🦺] Modo BITE activado - El Doberman responde activamente")
    
    # Mostrar configuración
    if not SILENT_MODE:
        print(f"[Dobershark] Capturando en: {iface}")
        print(f"[Dobershark] HTTP downloads -> {HTTP_DOWNLOAD_DIR}/")
        print(f"[Dobershark] TCP sessions   -> {TCP_SESSION_DIR}/")
        print(f"[Dobershark] SMB files      -> {SMB_FILE_DIR}/")
        if filtro:
            print(f"[Dobershark] Filtro BPF: {filtro}")
        if output_file:
            print(f"[Dobershark] Guardando a: {output_file}")
        if custom_rule:
            print(f"[🐕‍🦺] Inyección activa: ON")
        print("[Dobershark] Ctrl+C para detener...\n")
    
    try:
        sniff(iface=iface, filter=filtro, prn=packet_callback, store=False, stop_filter=lambda x: not running)
    except PermissionError:
        print("\n[!] Permisos insuficientes. Ejecuta con sudo/administrador.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
