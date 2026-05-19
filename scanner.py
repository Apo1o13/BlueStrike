#!/usr/bin/env python3
"""
Módulo de escaneo Bluetooth: Classic BT y BLE.
Usa bluetoothctl como motor principal (compatible con VMware/VirtualBox).
Fallback a hcitool para entornos bare-metal.
"""

import re
import time
import subprocess
from utils import run_cmd, color


class BluetoothScanner:
    def __init__(self, timeout: int = 15, ble: bool = False, verbose: bool = False):
        self.timeout = timeout
        self.ble     = ble
        self.verbose = verbose

    # ── Info del adaptador ──────────────────────────────────────────────────
    def get_adapter_info(self) -> dict:
        info = {}

        # Primero intentar bluetoothctl show (más fiable en VM)
        _, btctl, _ = run_cmd("bluetoothctl show 2>/dev/null")
        for line in btctl.splitlines():
            line = line.strip()
            if "Address:" in line and "MAC" not in info:
                info["MAC Address"] = line.split(":", 1)[1].strip()
            if "Name:" in line and "Nombre" not in info:
                info["Nombre"] = line.split(":", 1)[1].strip()
            if "Powered:" in line:
                val = line.split(":", 1)[1].strip()
                info["Encendido"] = "sí" if val.lower() == "yes" else "no"
            if "Discoverable:" in line:
                val = line.split(":", 1)[1].strip()
                info["Visible"] = "sí" if val.lower() == "yes" else "no"
            if "Pairable:" in line:
                val = line.split(":", 1)[1].strip()
                info["Emparejable"] = "sí" if val.lower() == "yes" else "no"

        # Versión HCI vía hciconfig
        _, out, _ = run_cmd("hciconfig hci0 version 2>/dev/null")
        for line in out.splitlines():
            line = line.strip()
            if "HCI" in line:
                info["Versión HCI"] = line
            if "LMP" in line:
                info["Versión LMP"] = line

        if not info:
            return {"error": "No se encontró adaptador Bluetooth (hciconfig)"}

        return info

    # ── Escaneo principal con bluetoothctl ──────────────────────────────────
    def scan_bluetoothctl(self) -> list[dict]:
        """
        Escaneo usando bluetoothctl — funciona en VM, bare-metal y con BLE.
        Solo muestra dispositivos REALMENTE presentes durante este escaneo:
        - Apareció como [NEW] durante el escaneo (no estaba en caché antes), O
        - Actualizó su RSSI (señal real detectada), O
        - Actualizó su nombre durante el escaneo (dispositivo activo)
        Los dispositivos solo en caché (sin actividad durante el escaneo) se descartan.
        """
        print(color(f"  [~] Escaneando con bluetoothctl ({self.timeout}s)...", "yellow"))

        # Capturar dispositivos ya en caché ANTES de escanear
        _, pre_out, _ = run_cmd("bluetoothctl devices 2>/dev/null", timeout=5)
        cached_macs = set()
        for line in pre_out.splitlines():
            m = re.search(r"([0-9A-Fa-f:]{17})", line)
            if m:
                cached_macs.add(m.group(1).upper())

        devices    = {}
        seen_active = set()  # MACs con actividad real durante el escaneo

        cmd = (
            f"(echo 'power on'; sleep 1; echo 'scan on'; "
            f"sleep {self.timeout}; echo 'scan off'; echo 'exit') "
            f"| bluetoothctl 2>&1"
        )

        _, out, _ = run_cmd(cmd, timeout=self.timeout + 10)

        for line in out.splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()

            if self.verbose:
                print(f"    {line}")

            # Nuevo dispositivo: [NEW] Device AA:BB:CC:DD:EE:FF Nombre
            m = re.search(r"\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})\s*(.*)", line)
            if m:
                mac  = m.group(1).upper()
                name = m.group(2).strip()
                if mac not in devices:
                    devices[mac] = {
                        "mac":      mac,
                        "name":     name if name and not re.match(r"^[0-9A-Fa-f:]{17}$", name) else "Desconocido",
                        "type":     "BLE" if self._is_random_mac(mac) else "Classic",
                        "rssi":     "N/A",
                        "services": [],
                    }
                # Si apareció como [NEW] y NO estaba en caché → realmente nuevo → activo
                if mac not in cached_macs:
                    seen_active.add(mac)

            # Nombre actualizado durante el escaneo → dispositivo activo
            m2 = re.search(r"\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+Name:\s*(.*)", line)
            if m2:
                mac, name = m2.group(1).upper(), m2.group(2).strip()
                if mac in devices and name:
                    devices[mac]["name"] = name
                seen_active.add(mac)

            # RSSI actualizado → señal real detectada → dispositivo activo
            m3 = re.search(r"\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})\s+RSSI:\s*(-?\d+)", line)
            if m3:
                mac, rssi = m3.group(1).upper(), m3.group(2)
                if mac in devices:
                    devices[mac]["rssi"] = rssi
                seen_active.add(mac)

            # Cualquier cambio [CHG] durante el escaneo = dispositivo presente
            m4 = re.search(r"\[CHG\]\s+Device\s+([0-9A-Fa-f:]{17})", line)
            if m4:
                seen_active.add(m4.group(1).upper())

        # Filtrar: solo dispositivos con actividad real durante este escaneo
        result = [d for mac, d in devices.items() if mac in seen_active]
        return result

    def _is_random_mac(self, mac: str) -> bool:
        """MACs con segundo nibble 2,6,A,E son aleatorias → BLE."""
        try:
            first_byte = int(mac.replace(":", "")[:2], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    # ── Escaneo Classic BT (fallback hcitool) ──────────────────────────────
    def scan_classic_hcitool(self) -> list[dict]:
        """Fallback con hcitool scan para bare-metal."""
        devices = []
        print(color(f"  [~] Escaneando Classic BT con hcitool ({self.timeout}s)...", "yellow"))

        run_cmd("hciconfig hci0 up 2>/dev/null")
        run_cmd("hciconfig hci0 piscan 2>/dev/null")

        _, out, err = run_cmd(f"timeout {self.timeout} hcitool scan --flush 2>/dev/null",
                              timeout=self.timeout + 5)
        if not out:
            return devices

        for line in out.splitlines():
            line = line.strip()
            if not line or "Scanning" in line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                mac  = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else "Desconocido"
                if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                    devices.append({
                        "mac":      mac,
                        "name":     name or "Desconocido",
                        "type":     "Classic",
                        "rssi":     self._get_rssi(mac),
                        "services": self._get_services_sdptool(mac),
                    })
        return devices

    def _get_rssi(self, mac: str) -> str:
        _, out, _ = run_cmd(f"hcitool rssi {mac} 2>/dev/null")
        m = re.search(r"RSSI return value: (-?\d+)", out)
        return m.group(1) if m else "N/A"

    def _get_services_sdptool(self, mac: str) -> list[str]:
        services = []
        _, out, _ = run_cmd(f"sdptool browse {mac} 2>/dev/null", timeout=15)
        current = None
        for line in out.splitlines():
            if "Service Name:" in line:
                current = line.split(":", 1)[1].strip()
            if current and "Protocol Descriptor" in line and current not in services:
                services.append(current)
                current = None
        return services

    def _parse_manufacturer(self, metadata: dict) -> str:
        mfr_data = metadata.get("manufacturer_data", {})
        if not mfr_data:
            return "Desconocido"
        company_ids = {
            76:  "Apple",
            6:   "Microsoft",
            89:  "Nordic Semiconductor",
            117: "Samsung",
            224: "Google",
            343: "Fitbit",
        }
        for cid in mfr_data:
            return company_ids.get(cid, f"ID:{cid}")
        return "Desconocido"

    # ── Escaneo combinado ───────────────────────────────────────────────────
    def scan(self) -> list[dict]:
        """
        Motor de escaneo principal.
        Usa bluetoothctl por defecto (compatible VM + BLE).
        """
        # bluetoothctl detecta Classic y BLE juntos
        all_devices = self.scan_bluetoothctl()

        # Si bluetoothctl no encontró nada, intentar hcitool como fallback
        if not all_devices:
            print(color("  [~] Intentando fallback con hcitool...", "yellow"))
            all_devices = self.scan_classic_hcitool()

        # Filtrar BLE si el usuario no lo pidió
        if not self.ble:
            all_devices = [d for d in all_devices if d.get("type") != "BLE"]

        return all_devices
