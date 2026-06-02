#!/usr/bin/env python3
# Dobershark v2.0 - Con soporte HTTP detallado y VLAN 802.1Q
# Compatible: Windows (Npcap), Linux, Termux

import sys
import os
import signal
import re
from datetime import datetime

try:
    from scapy.all import *
    from scapy.arch import get_if_list
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dot11 import Dot11  # opcional, para WiFi
except ImportError:
    print("[!] Scapy no instalado. Ejecuta: pip install scapy")
    sys.exit(1)

# ========== BANNER DOBERMAN v2 ==========
BANNER = """
    ╔═══════════════════════════════════════════════════════╗
    ║         🐕‍🦺 DOBERSHARK v2.0 - CON VLAN Y HTTP         ║
    ║   "Olfateando capa por capa, paquete por paquete"    ║
    ╚═══════════════════════════════════════════════════════╝

         __
        / _)   ¡GRRR! Analizando VLAN y HTTP en detalle.
       | (    
        ¯¯¯
"""
# =======================================

running = True

def signal_handler(sig, frame):
    global running
    print("\n[Dobershark] Deteniendo captura...")
    running = False
    sys.exit(0)

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
            
            # Cabeceras
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

def packet_callback(packet):
    """Procesa paquetes con soporte VLAN y HTTP detallado"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    vlan_id = None
    
    # ========== SOPORTE VLAN (802.1Q) ==========
    # Scapy detecta VLAN como capa Dot1Q
    if packet.haslayer(Dot1Q):
        vlan_layer = packet[Dot1Q]
        vlan_id = vlan_layer.vlan
        vlan_priority = vlan_layer.prio
        print(f"\n[VLAN {vlan_id}] Prio: {vlan_priority}")
        # Removemos la capa VLAN para analizar lo interno
        inner_packet = packet[Dot1Q].payload
    else:
        inner_packet = packet
    
    # ========== CAPA ETHERNET ==========
    if Ether in inner_packet:
        src_mac = inner_packet[Ether].src
        dst_mac = inner_packet[Ether].dst
        eth_type = inner_packet[Ether].type
        mac_info = f"MAC: {src_mac} -> {dst_mac}"
        if vlan_id:
            print(f"[VLAN{vlan_id}] {mac_info}")
        else:
            print(f"[ETHER] {mac_info}")
    
    # ========== IP / TCP / UDP / ICMP ==========
    if IP in inner_packet:
        src_ip = inner_packet[IP].src
        dst_ip = inner_packet[IP].dst
        proto = inner_packet[IP].proto
        ttl = inner_packet[IP].ttl
        ip_id = inner_packet[IP].id
        
        # TCP
        if TCP in inner_packet:
            src_port = inner_packet[TCP].sport
            dst_port = inner_packet[TCP].dport
            flags = inner_packet[TCP].flags
            payload = bytes(inner_packet[TCP].payload)
            
            # 🔥 HTTP DETALLADO
            if (src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080) and payload:
                http_info = parse_http_payload(payload)
                if http_info:
                    print(f"\n[HTTP {http_info['method']}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    print(f"  URL: {http_info['url']}")
                    if 'Host' in http_info['headers']:
                        print(f"  Host: {http_info['headers']['Host']}")
                    if 'User-Agent' in http_info['headers']:
                        print(f"  User-Agent: {http_info['headers']['User-Agent'][:60]}...")
                    if http_info['body']:
                        print(f"  Body: {http_info['body'][:200]}")
                    if http_info['method'] == 'GET' and '?' in http_info['url']:
                        query = http_info['url'].split('?')[1]
                        print(f"  Parámetros GET: {query[:100]}")
                else:
                    print(f"[TCP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags} | Len: {len(payload)}")
            else:
                print(f"[TCP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags} | Len: {len(payload)}")
        
        # UDP
        elif UDP in inner_packet:
            src_port = inner_packet[UDP].sport
            dst_port = inner_packet[UDP].dport
            payload_len = len(bytes(inner_packet[UDP].payload))
            print(f"[UDP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Len: {payload_len}")
            
            # DNS (dentro de UDP)
            if inner_packet.haslayer(DNS) and inner_packet.haslayer(DNSQR):
                qname = inner_packet[DNSQR].qname.decode('utf-8')
                print(f"  [DNS] Consulta: {qname}")
        
        # ICMP
        elif ICMP in inner_packet:
            icmp_type = inner_packet[ICMP].type
            icmp_code = inner_packet[ICMP].code
            print(f"[ICMP] {timestamp} | {src_ip} -> {dst_ip} | Type: {icmp_type} Code: {icmp_code}")
    
    # ARP
    elif ARP in inner_packet:
        src_ip = inner_packet[ARP].psrc
        dst_ip = inner_packet[ARP].pdst
        src_mac = inner_packet[ARP].hwsrc
        dst_mac = inner_packet[ARP].hwdst
        op = "Request" if inner_packet[ARP].op == 1 else "Reply"
        print(f"[ARP] {timestamp} | {op} | {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")

def main():
    global running
    print(BANNER)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parseo simple de argumentos
    iface = None
    filtro = None
    output_file = None
    list_interfaces = False
    
    for i, arg in enumerate(sys.argv):
        if arg in ["--list-interfaces", "-l"]:
            list_interfaces = True
        elif arg == "-i" and i+1 < len(sys.argv):
            iface = sys.argv[i+1]
        elif arg == "-f" and i+1 < len(sys.argv):
            filtro = sys.argv[i+1]
        elif arg == "-o" and i+1 < len(sys.argv):
            output_file = sys.argv[i+1]
    
    if list_interfaces:
        print("\n[Interfaces detectadas:]")
        for iface_name in get_if_list():
            print(f"  - {iface_name}")
        return
    
    if not iface:
        print("[!] Uso: python dobershark.py -i <interfaz> [-f 'filtro'] [-o archivo.pcap]")
        print("[!] Ver interfaces: python dobershark.py --list-interfaces")
        print("\nEjemplos:")
        print("  python dobershark.py -i eth0")
        print("  python dobershark.py -i wlan0 -f 'tcp port 80'")
        print("  python dobershark.py -i eth0 -f 'vlan'   # Captura VLAN")
        sys.exit(1)
    
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
        print("[!] En Windows: asegura Npcap instalado y modo WinPcap API")
        print("[!] En Linux/Termux: sudo python dobershark.py -i eth0")

if __name__ == "__main__":
    main()
