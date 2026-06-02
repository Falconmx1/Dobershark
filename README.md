# 🐕‍🦺 Dobershark

> Analizador de protocolos con instinto de caza. Captura e inspecciona tráfico TCP/IP, ARP, DNS y HTTP en Windows, Linux y Termux. Modo monitoreo, filtros inteligentes y banner del Doberman. Olfatea la red.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-GPLv3-red)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Termux-lightgrey)

## 🎯 Características

- ✅ **Captura TCP/UDP** en tiempo real
- ✅ **Filtros estilo Wireshark** (ej. `tcp port 80`, `udp`, `arp`)
- ✅ **Banner animado del Doberman** en CLI
- ✅ **Detección automática de interfaces** de red
- ✅ **Análisis de protocolos**: IP, TCP, UDP, ARP, DNS, HTTP
- ✅ **Multiplataforma**: Windows (Npcap), Linux (libpcap), Termux (tcpdump)

🚀 Instalación completa (Windows/Linux/Termux)

Linux/Kali:

sudo apt update
sudo apt install python3 python3-pip tcpdump
pip3 install scapy flask flask-socketio eventlet mitmproxy
git clone https://github.com/Falconmx1/Dobershark.git
cd Dobershark
sudo python3 dobershark.py -i eth0 --web --https

Windows:
# Instalar Npcap desde npcap.com
pip install scapy flask flask-socketio eventlet mitmproxy
python dobershark.py -i "Ethernet" --web

Termux:
pkg install python tcpdump
pip install scapy flask flask-socketio eventlet
# mitmproxy requiere root en Termux, usar solo --web
python dobershark.py -i wlan0 --web

🎯 Ejemplos de uso FINAL v5.0
# Modo completo: captura + web + HTTPS + credenciales
sudo python dobershark.py -i eth0 --web --https

# Solo web y captura (sin HTTPS)
sudo python dobershark.py -i wlan0 --web

# Modo sigiloso + web (para servidores)
sudo python dobershark.py -i eth0 --web -s

# Captura específica con filtro + web
sudo python dobershark.py -i eth0 -f "tcp port 80 or tcp port 443" --web
