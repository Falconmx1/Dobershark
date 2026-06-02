#!/usr/bin/env python3
# Dobershark - Analizador de protocolos con instinto de caza
# Compatible: Windows (Npcap), Linux, Termux

import sys
import os
import signal
from datetime import datetime

try:
    from scapy.all import *
    from scapy.arch import get_if_list
except ImportError:
    print("[!] Scapy no instalado. Ejecuta: pip install scapy")
    sys.exit(1)

# ========== BANNER DOBERMAN ==========
BANNER = """
    ╔═══════════════════════════════════════╗
    ║         🐕‍🦺 DOBERSHARK v1.0           ║
    ║   "Olfateando la red con precisión"   ║
    ╚═══════════════════════════════════════╝
    
         __
        / _)   ¡Woof! Listo para cazar paquetes.
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

def packet_callback(packet):
    """Procesa cada paquete capturado"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Capa Ethernet
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        tipo = packet[Ether].type
        # print(f"[MAC] {src_mac} -> {dst_mac} | Type: {hex(tipo)}")
    
    # Capa IP
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        
        # TCP
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[TCP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {flags}")
            if packet[TCP].payload:
                try:
                    payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                    if payload.strip():
                        print(f"       Data: {payload[:100]}")
                except:
                    pass
        # UDP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[UDP] {timestamp} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        # ICMP
        elif ICMP in packet:
            print(f"[ICMP] {timestamp} | {src_ip} -> {dst_ip} (ping)")
        # Otros IP
        else:
            print(f"[IP] {timestamp} | Protocolo {proto} | {src_ip} -> {dst_ip}")
    
    # ARP (no IP)
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        op = "Request" if packet[ARP].op == 1 else "Reply"
        print(f"[ARP] {timestamp} | {op} | {src_ip} -> {dst_ip}")
    
    # DNS
    if DNS in packet and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname.decode('utf-8')
        print(f"[DNS] {timestamp} | Consulta: {qname}")

def main():
    global running
    print(BANNER)
    
    # Manejar Ctrl+C elegantemente
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parsear argumentos simples (mejor que argparse para compatibilidad)
    iface = None
    filtro = None
    output_file = None
    list_interfaces = False
    
    for i, arg in enumerate(sys.argv):
        if arg == "--list-interfaces" or arg == "-l":
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
        sys.exit(1)
    
    print(f"[Dobershark] Capturando en interfaz: {iface}")
    if filtro:
        print(f"[Dobershark] Filtro BPF: {filtro}")
    else:
        print("[Dobershark] Sin filtro (capturando todo el tráfico)")
    if output_file:
        print(f"[Dobershark] Guardando captura a: {output_file}")
    
    print("[Dobershark] Presiona Ctrl+C para detener...\n")
    
    # Función de captura (Scapy)
    try:
        sniff(iface=iface, filter=filtro, prn=packet_callback, store=False, stop_filter=lambda x: not running)
    except PermissionError:
        print("\n[!] Error: Permisos insuficientes. Ejecuta con sudo/administrador.")
    except Exception as e:
        print(f"\n[!] Error al capturar: {e}")
        print("[!] En Windows, asegúrate de tener Npcap instalado.")
        print("[!] En Linux/Termux, ejecuta: sudo python dobershark.py -i eth0")
    
    if output_file:
        print(f"[Dobershark] Captura guardada en {output_file}")

if __name__ == "__main__":
    main()
