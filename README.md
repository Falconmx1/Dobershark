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

## 📸 Banner del Doberman

Al ejecutar Dobershark, verás:
╔═══════════════════════════════════════╗
║ 🐕‍🦺 DOBERSHARK v1.0 ║
║ "Olfateando la red con precisión" ║
╚═══════════════════════════════════════╝

__
/ _) ¡Woof! Listo para cazar paquetes.
| (
¯¯¯


## 🛠️ Instalación

### Windows (con Npcap)
```bash
# 1. Instalar Npcap desde https://npcap.com (marcar "WinPcap API-compatible Mode")
# 2. Instalar Python 3.7+
# 3. Clonar e instalar dependencias
git clone https://github.com/Falconmx1/Dobershark.git
cd Dobershark
pip install -r requirements.txt

Linux (Debian/Ubuntu/Kali)
sudo apt update
sudo apt install python3 python3-pip tcpdump
git clone https://github.com/Falconmx1/Dobershark.git
cd Dobershark
pip3 install -r requirements.txt

Termux (Android)
pkg update && pkg upgrade
pkg install python tcpdump git
git clone https://github.com/Falconmx1/Dobershark.git
cd Dobershark
pip install -r requirements.txt

🚀 Uso rápido
# Ver interfaces disponibles
python dobershark.py --list-interfaces

# Capturar todo el tráfico (Ctrl+C para detener)
python dobershark.py -i eth0

# Filtro TCP puerto 80 (HTTP)
python dobershark.py -i eth0 -f "tcp port 80"

# Filtro UDP puerto 53 (DNS)
python dobershark.py -i wlan0 -f "udp port 53"

# Guardar captura a archivo
python dobershark.py -i eth0 -f "tcp" -o captura.pcap
