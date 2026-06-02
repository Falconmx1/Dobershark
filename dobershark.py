#!/usr/bin/env python3
# Dobershark v3.0 - IPv6, SMB file extraction, Silent mode
# "El Doberman ahora caza en IPv6 y recupera archivos SMB"
# Compatible: Windows (Npcap), Linux, Termux

import sys
import os
import signal
import re
import hashlib
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest, ICMPv6EchoReply
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dot11 import Dot11
    from scapy.layers.smb import SMB, SMB_Header, SMB_Parameters, SMB_Data
except ImportError:
    print("[!] Scapy no instalado. Ejecuta: pip install scapy")
    sys.exit(1)

# ========== CONFIGURACIÓN ==========
SILENT_MODE = False
SMB_FILE_DIR = "smb_extracted"
os.makedirs(SMB_FILE_DIR, exist_ok=True)

# Para reconstruir archivos SMB (simple reassembly por conexión)
smb_sessions = defaultdict(lambda: {'data': b'', 'filename': None, 'size': 0})

# ========== BANNER DOBERMAN (versión silenciable) ==========
BANNER = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║         🐕‍🦺 DOBERSHARK v3.0 - IPv6 + SMB + SILENT MODE       ║
    ║   "Olfateando en IPv6, mordiendo archivos SMB en silencio"   ║
    ╚═══════════════════════════════════════════════════════════════╝

         __
        / _)   ¡GRRR! IPv6, SMB extraction y stealth mode activados.
       | (    
        ¯¯¯
"""

# =======================================

running = True

def signal_handler(sig, frame):
    global running
    if not SILENT_MODE:
        print("\n[Dobershark] Deteniendo captura...")
    running = False
    # Resumen de archivos SMB extraídos
    if not SILENT_MODE and any(s['filename'] for s in smb_sessions.values()):
        print(f"\n[📁 Archivos SMB extraídos en: {SMB_FILE_DIR}/]")
        for session, data in smb_sessions.items():
            if data['filename']:
                print(f"  - {data['filename']} ({len(data['data'])} bytes)")
    sys.exit(0)

def compress_ipv6(addr):
    """Comprime dirección IPv6 para mostrar (::)"""
    try:
        # Scapy a veces devuelve objeto, a veces string
        if hasattr(addr, 'compressed'):
            return addr.compressed
        compressed = re.sub(r':0{1,3}(?=:|$)', ':', str(addr))
        compressed = re.sub(r':{3,}', '::', compressed)
        return compressed.strip(':')
    except:
        return str(addr)

def parse_http_payload(payload_bytes):
    """Extrae método, URL, cabeceras y cuerpo de HTTP"""
    try:
        payload = payload_bytes.decode('utf-8', errors='ignore')
        if not payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT')):
            return None
        
        lines = payload.split('\r\n')
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) >= 3:
            method = parts[0]
            url = parts[1]
            version = parts[2]
            
            headers = {}
            body = ""
            body_start = False
            for line in lines[1:]:
                if line == '':
                    body_start = True
                    continue
                if not body_start and ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
                elif body_start:
                    body += line + "\n"
            
            return {
                'method': method,
                'url': url,
                'version': version,
                'headers': headers,
                'body': body.strip()
            }
    except:
        pass
    return None

def extract_smb_files(packet, src_ip, dst_ip, src_port, dst_port, payload):
    """Detecta y extrae archivos de tráfico SMB (versión simplificada)"""
    # Identificar sesiones SMB (puerto 445)
    if (src_port == 445 or dst_port == 445) and len(payload) > 0:
        session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        # Buscar nombres de archivo comunes en SMB (patrón simple)
        payload_str = payload.decode('latin-1', errors='ignore')
        
        # Buscar patrones de escritura SMB (Create AndX Request)
        if b'\\x00\\x00\\x00\\x02' in payload[:20]:  # SMB COMnand Create AndX
            # Extraer posible nombre de archivo (ASCIIZ después de ciertos offsets)
            match = re.search(b'[A-Za-z0-9_\\-\\.]+\\.[A-Za-z0-9]{2,4}', payload)
            if match and len(match.group()) > 3:
                filename = match.group().decode('latin-1', errors='ignore')
                smb_sessions[session_key]['filename'] = filename
                if not SILENT_MODE:
                    print(f"  [SMB] Detectado archivo: {filename}")
        
        # Acumular datos de escritura (WRITE AndX)
        if b'\\x00\\x00\\x00\\x0F' in payload[:20]:  # WRITE AndX command
            # Buscar datos después del encabezado (aproximado)
            if len(payload) > 100:
                file_data = payload[64:]  # Offset típico
                smb_sessions[session_key]['data'] += file_data
                smb_sessions[session_key]['size'] += len(file_data)
        
        # Si el archivo tiene datos y parece completo (fin de sesión o EOF)
        if smb_sessions[session_key]['filename'] and smb_sessions[session_key]['size'] > 0:
            filename = smb_sessions[session_key]['filename']
            filepath = os.path.join(SMB_FILE_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
            with open(filepath, 'wb') as f:
                f.write(smb_sessions[session_key]['data'][:smb_sessions[session_key]['size']])
            if not SILENT_MODE:
                print(f"  [💾 SMB] Archivo guardado: {filepath} ({smb_sessions[session_key]['size']} bytes)")
            # Limpiar sesión para no duplicar
            smb_sessions[session_key]['data'] = b''

def packet_callback(packet):
    """Procesa paquetes con IPv6, VLAN, HTTP detallado y extracción SMB"""
    global SILENT_MODE
    timestamp = datetime.now().strftime("%H:%M:%S")
    vlan_id = None
    
    # ========== VLAN (802.1Q) ==========
    if packet.haslayer(Dot1Q):
        vlan_layer = packet[Dot1Q]
        vlan_id = vlan_layer.vlan
        inner_packet = packet[Dot1Q].payload
        if not SILENT_MODE:
            print(f"\n[VLAN {vlan_id}] Prio: {vlan_layer.prio}")
    else:
        inner_packet = packet
    
    # ========== ETHERNET ==========
    if Ether in inner_packet and not SILENT_MODE:
        src_mac = inner_packet[Ether].src
        dst_mac = inner_packet[Ether].dst
        if vlan_id:
            print(f"[VLAN{vlan_id}] MAC: {src_mac} -> {dst_mac}")
        else:
            print(f"[ETHER] {src_mac} -> {dst_mac}")
    
    # ========== IPv6 (NUEVO) ==========
    if IPv6 in inner_packet:
        ip6 = inner_packet[IPv6]
        src_ip = compress_ipv6(ip6.src)
        dst_ip = compress_ipv6(ip6.dst)
        traffic_class = ip6.tc
        flow_label = ip6.fl
        next_header = ip6.nh
        hop_limit = ip6.hlim
        
        if not SILENT_MODE:
            print(f"[IPv6] {src_ip} -> {dst_ip} | TC:{traffic_class} NH:{next_header} HL:{hop_limit}")
        
        # ICMPv6 (ping6, neighbor discovery)
        if ICMPv6Unknown in inner_packet or ICMPv6EchoRequest in inner_packet:
            print(f"[ICMPv6] {src_ip} -> {dst_ip} | Echo Request/Reply")
        
        # TCP sobre IPv6
        if TCP in inner_packet:
            tcp = inner_packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = tcp.flags
            payload = bytes(tcp.payload)
            
            # HTTP sobre IPv6
            if (src_port == 80 or dst_port == 80) and payload:
                http_info = parse_http_payload(payload)
                if http_info and not SILENT_MODE:
                    print(f"[HTTPv6 {http_info['method']}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  URL: {http_info['url']}")
                    if 'Host' in http_info['headers']:
                        print(f"  Host: {http_info['headers']['Host']}")
            else:
                if not SILENT_MODE:
                    print(f"[TCPv6] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags}")
        
        # UDP sobre IPv6
        elif UDP in inner_packet:
            udp = inner_packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            if not SILENT_MODE:
                print(f"[UDPv6] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    # ========== IPv4 ==========
    elif IP in inner_packet:
        src_ip = inner_packet[IP].src
        dst_ip = inner_packet[IP].dst
        proto = inner_packet[IP].proto
        
        # TCP
        if TCP in inner_packet:
            src_port = inner_packet[TCP].sport
            dst_port = inner_packet[TCP].dport
            flags = inner_packet[TCP].flags
            payload = bytes(inner_packet[TCP].payload)
            
            # 🎯 SMB FILE EXTRACTION (nuevo)
            extract_smb_files(packet, src_ip, dst_ip, src_port, dst_port, payload)
            
            # HTTP detallado
            if (src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080) and payload:
                http_info = parse_http_payload(payload)
                if http_info and not SILENT_MODE:
                    print(f"\n[HTTP {http_info['method']}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  URL: {http_info['url']}")
                    if 'Host' in http_info['headers']:
                        print(f"  Host: {http_info['headers']['Host']}")
                    if 'User-Agent' in http_info['headers']:
                        print(f"  User-Agent: {http_info['headers']['User-Agent'][:60]}...")
                    if http_info['body']:
                        print(f"  Body: {http_info['body'][:200]}")
            else:
                if not SILENT_MODE:
                    print(f"[TCP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags} | Len: {len(payload)}")
        
        # UDP (y DNS)
        elif UDP in inner_packet:
            src_port = inner_packet[UDP].sport
            dst_port = inner_packet[UDP].dport
            if not SILENT_MODE:
                print(f"[UDP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            if inner_packet.haslayer(DNS) and inner_packet.haslayer(DNSQR):
                qname = inner_packet[DNSQR].qname.decode('utf-8')
                if not SILENT_MODE:
                    print(f"  [DNS] Consulta: {qname}")
        
        # ICMP
        elif ICMP in inner_packet:
            if not SILENT_MODE:
                print(f"[ICMP] {timestamp} | {src_ip} -> {dst_ip}")
    
    # ========== ARP ==========
    elif ARP in inner_packet and not SILENT_MODE:
        src_ip = inner_packet[ARP].psrc
        dst_ip = inner_packet[ARP].pdst
        op = "Request" if inner_packet[ARP].op == 1 else "Reply"
        print(f"[ARP] {timestamp} | {op} | {src_ip} -> {dst_ip}")

def main():
    global running, SILENT_MODE
    
    # Parseo de argumentos
    iface = None
    filtro = None
    output_file = None
    list_interfaces = False
    
    for i, arg in enumerate(sys.argv):
        if arg in ["--list-interfaces", "-l"]:
            list_interfaces = True
        elif arg in ["--silent", "-s"]:
            SILENT_MODE = True
        elif arg == "-i" and i+1 < len(sys.argv):
            iface = sys.argv[i+1]
        elif arg == "-f" and i+1 < len(sys.argv):
            filtro = sys.argv[i+1]
        elif arg == "-o" and i+1 < len(sys.argv):
            output_file = sys.argv[i+1]
    
    # Mostrar banner solo si NO está en modo silencioso
    if not SILENT_MODE:
        print(BANNER)
    else:
        print("[Dobershark] Modo silencioso activado (sin banner, solo datos críticos)")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    if list_interfaces:
        print("\n[Interfaces detectadas:]")
        for iface_name in get_if_list():
            print(f"  - {iface_name}")
        return
    
    if not iface:
        print("[!] Uso: python dobershark.py -i <interfaz> [-f 'filtro'] [-o archivo.pcap] [-s|--silent]")
        print("[!] Ver interfaces: python dobershark.py --list-interfaces")
        print("\nEjemplos:")
        print("  python dobershark.py -i eth0")
        print("  python dobershark.py -i wlan0 -f 'tcp port 80'")
        print("  python dobershark.py -i eth0 -s               # Modo silencioso")
        print("  python dobershark.py -i eth0 -f 'ip6'         # Solo IPv6")
        sys.exit(1)
    
    if not SILENT_MODE:
        print(f"[Dobershark] Capturando en: {iface}")
        if filtro:
            print(f"[Dobershark] Filtro BPF: {filtro}")
        if output_file:
            print(f"[Dobershark] Guardando a: {output_file}")
        print("[Dobershark] Ctrl+C para detener...\n")
    
    try:
        sniff(iface=iface, filter=filtro, prn=packet_callback, store=False, stop_filter=lambda x: not running)
    except PermissionError:
        print("\n[!] Permisos insuficientes. Ejecuta con sudo/administrador.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if not SILENT_MODE:
            print("[!] En Windows: asegura Npcap instalado")
            print("[!] En Linux/Termux: sudo python dobershark.py -i eth0")

if __name__ == "__main__":
    main()
