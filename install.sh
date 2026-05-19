#!/bin/bash
# BlueStrike — Script de instalación para Kali Linux / Ubuntu
# Autor: Apo1o13
# Ejecutar con: sudo bash install.sh

set -e

echo "[*] Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y \
    bluez \
    bluez-tools \
    bluetooth \
    python3 \
    python3-pip \
    python3-bleak \
    l2ping \
    obexftp \
    obextools \
    sdpscanner \
    rfcomm \
    gatttool \
    btscanner \
    screen \
    netcat-traditional \
    2>/dev/null || true

# Herramientas opcionales de pentesting BT
echo "[*] Instalando herramientas opcionales..."
apt-get install -y \
    bluesnarfer \
    redfang \
    bluemaho \
    2>/dev/null || echo "[!] Algunas herramientas opcionales no están disponibles en los repos"

echo "[*] Instalando dependencias Python..."
# Intentar primero vía apt (recomendado en Kali)
apt-get install -y python3-bleak 2>/dev/null || true

# Si no está en apt, instalar con pip usando --break-system-packages (Kali/Debian 12+)
if ! python3 -c "import bleak" 2>/dev/null; then
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null \
    || pip3 install -r requirements.txt 2>/dev/null \
    || echo "[!] No se pudo instalar bleak — la herramienta funcionará sin soporte BLE"
fi

echo "[*] Activando servicio Bluetooth..."
systemctl enable bluetooth 2>/dev/null || true
systemctl start bluetooth 2>/dev/null || true

echo "[*] Levantando adaptador hci0..."
hciconfig hci0 up 2>/dev/null || echo "[!] No se encontró hci0 — conecta un adaptador Bluetooth"

echo ""
echo "[+] Instalación completa."
echo ""
echo "    ╔══════════════════════════════════════════════════════╗"
echo "    ║           BlueStrike — Comandos básicos              ║"
echo "    ╠══════════════════════════════════════════════════════╣"
echo "    ║  sudo python3 bluestrike.py          # Modo guiado   ║"
echo "    ║  sudo python3 bluestrike.py -i        # Info adapter ║"
echo "    ║  sudo python3 bluestrike.py -s -t 20  # Escanear     ║"
echo "    ║  sudo python3 bluestrike.py -a <MAC> -e # Explotar   ║"
echo "    ║  sudo python3 bluestrike.py --all     # Todo auto     ║"
echo "    ╚══════════════════════════════════════════════════════╝"
echo ""
