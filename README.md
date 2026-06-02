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

🚀 Ejemplos de uso
Extraer archivos HTTP descargados
python dobershark.py -i eth0 -f "tcp port 80"
# Los archivos aparecerán en http_downloads/
Reconstruir sesiones TCP completas
python dobershark.py -i eth0 -f "tcp"
# Las sesiones se guardan en tcp_sessions/ como archivos binarios
Modo BITE (respuesta activa)
# Responde a pings y bloquea SSH a IP específica (editar IP en código)
sudo python dobershark.py -i eth0 --bite
Inyectar paquete personalizado (hex)
# Ejemplo: Inyectar un paquete Ethernet con destino específico
python dobershark.py -i eth0 --inject-hex "00112233445566778899aabb08004500001c..."
Todo junto + modo silencioso
sudo python dobershark.py -i wlan0 -f "tcp" -s --bite

## 🔥 Características v4.0 (Avanzado)

### 📥 Extracción de archivos HTTP
- Reconstruye cualquier archivo descargado por HTTP
- Detecta nombres por Content-Disposition o URL
- Calcula MD5 de cada archivo extraído

### 🔄 Reconstrucción de sesiones TCP
- Reensambla conversaciones TCP completas
- Maneja paquetes fuera de orden y retransmisiones
- Guarda sesiones en archivos binarios

### 💉 Inyección de paquetes (Modo BITE)
- **--bite**: Responde activamente a pings (ICMP Echo Reply)
- **--bite**: Envía RST para bloquear conexiones SSH no deseadas
- **--inject-hex**: Inyecta paquete personalizado desde hexadecimal

### Ejemplos avanzados
```bash
# Extraer archivos HTTP + reconstruir sesiones + modo bite
sudo python dobershark.py -i eth0 -f "tcp" --bite

# Inyección manual de paquete
python dobershark.py -i eth0 --inject-hex "0050... (tu hex aquí)"

# Modo forense (todo silencioso, solo guardar)
sudo python dobershark.py -i eth0 -f "tcp" -s -o captura.pcap
