#!/usr/bin/env python3
"""
Módulo de análisis de vulnerabilidades Bluetooth.
Detecta: BlueBorne, KNOB, BIAS, BlueSnarfing, BlueSmack, SDP enum, etc.
"""

import re
import time
from utils import run_cmd, color


# ── Base de datos de vulnerabilidades ──────────────────────────────────────
VULN_DB = [
    {
        "id":          "BLUEBORNE_RCE_LINUX",
        "name":        "BlueBorne RCE (Linux BlueZ)",
        "cve":         "CVE-2017-1000251",
        "severity":    "CRITICAL",
        "description": "Ejecución remota de código en stack L2CAP de BlueZ sin autenticación.",
        "exploit_id":  "blueborne_rce",
        "conditions":  {"os_hint": ["linux"], "lmp_max": 9},
    },
    {
        "id":          "BLUEBORNE_INFO_ANDROID",
        "name":        "BlueBorne Info Leak (Android)",
        "cve":         "CVE-2017-0785",
        "severity":    "HIGH",
        "description": "Fuga de información remota en implementación SDP de Android.",
        "exploit_id":  "blueborne_info",
        "conditions":  {"os_hint": ["android"], "lmp_max": 9},
    },
    {
        "id":          "KNOB",
        "name":        "KNOB Attack (Key Negotiation of Bluetooth)",
        "cve":         "CVE-2019-9506",
        "severity":    "HIGH",
        "description": "Reducción forzada de entropía de clave de enlace a 1 byte. "
                       "Permite descifrado de tráfico BT cifrado.",
        "exploit_id":  "knob_attack",
        "conditions":  {"lmp_max": 10},
    },
    {
        "id":          "BIAS",
        "name":        "BIAS Attack (Bluetooth Impersonation Attacks)",
        "cve":         "CVE-2020-10135",
        "severity":    "HIGH",
        "description": "Suplantación de identidad en fase de autenticación Secure Simple Pairing.",
        "exploit_id":  "bias_attack",
        "conditions":  {"lmp_max": 10},
    },
    {
        "id":          "BLUESMACK",
        "name":        "BlueSmack DoS",
        "cve":         "CVE-2004-0478",
        "severity":    "MEDIUM",
        "description": "DoS mediante paquetes L2CAP oversized (Ping of Death Bluetooth).",
        "exploit_id":  "bluesmack",
        "conditions":  {"type": "Classic", "l2cap_reachable": True},
    },
    {
        "id":          "BLUESNARFING",
        "name":        "BlueSnarfing",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "Acceso no autorizado a información (contactos, SMS) vía OBEX sin autenticación.",
        "exploit_id":  "bluesnarfer",
        "conditions":  {"service": ["OBEX", "OPP", "FTP"]},
    },
    {
        "id":          "BLUEPRINTING",
        "name":        "Bluetooth Fingerprinting / Blueprinting",
        "cve":         "N/A",
        "severity":    "LOW",
        "description": "Enumeración completa de servicios SDP expuestos sin autenticación.",
        "exploit_id":  "sdp_enum",
        "conditions":  {"type": "Classic", "service_count_min": 1},
    },
    {
        "id":          "BLE_INFO_LEAK",
        "name":        "BLE Fuga de Información sin Autenticación",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "Dispositivo BLE expone nombre, fabricante, MAC y datos HID sin requerir emparejamiento. "
                       "Pairing Just Works — sin protección MITM.",
        "exploit_id":  "ble_mitm",
        "conditions":  {"type": "BLE", "no_auth": True},
    },
    {
        "id":          "BLE_HID_INJECT",
        "name":        "BLE HID Inyección sin Autenticación (ratón/teclado)",
        "cve":         "N/A",
        "severity":    "CRITICAL",
        "description": "Dispositivo HID BLE (teclado/ratón) accesible sin autenticación. "
                       "Permite inyectar reportes HID para controlar cursor o enviar teclas de forma remota.",
        "exploit_id":  "ble_hid_inject",
        "conditions":  {"type": "BLE", "no_auth": True, "gatt_service": "hid"},
    },
    {
        "id":          "BLE_SPOOF",
        "name":        "BLE Impersonation — Suplantación de Identidad BLE",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "Dispositivo BLE con MAC visible. Es posible clonar su identidad, "
                       "desconectarlo de su host y suplantar su MAC para que el host se reconecte a nosotros. "
                       "Permite interceptar tráfico GATT sin autenticación.",
        "exploit_id":  "ble_spoof",
        "conditions":  {"type": "BLE", "ble_visible": True},
    },
    {
        "id":          "AVRCP_CONTROL",
        "name":        "AVRCP Control Remoto sin Autorización",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "El dispositivo expone el perfil AVRCP (AV Remote Control Target). "
                       "Permite controlar la reproducción de medios (play, pause, stop, next, previous) "
                       "sin autenticación ni autorización del usuario.",
        "exploit_id":  "avrcp_control",
        "conditions":  {"service": ["AV Remote Control Target", "AVRCP", "AV Remote Control",
                                    "Android TV Remote"]},
    },
    {
        "id":          "SDP_UNAUTHENTICATED",
        "name":        "SDP Enumeration sin Autenticación",
        "cve":         "N/A",
        "severity":    "MEDIUM",
        "description": "El servicio SDP responde sin requerir autenticación, exponiendo la superficie de ataque.",
        "exploit_id":  "sdp_enum",
        "conditions":  {"type": "Classic", "service_count_min": 3},
    },
    {
        "id":          "RFCOMM_OPEN_CHANNEL",
        "name":        "Canal RFCOMM Expuesto — Posible Shell/AT (pendiente de verificar)",
        "cve":         "N/A",
        "severity":    "MEDIUM",
        "description": "El dispositivo anuncia canales RFCOMM vía SDP. "
                       "Si no requieren autenticación, pueden permitir acceso AT o shell. "
                       "La severidad real depende del resultado del exploit.",
        "exploit_id":  "rfcomm_shell",
        "conditions":  {"service": ["Handsfree", "Serial Port", "Headset", "Dial-up"]},
    },
    {
        "id":          "BLUEBUGGING",
        "name":        "Posible BlueBugging — Canal AT Commands expuesto vía SDP",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "Canal Handsfree/Serial anunciado en SDP. Si acepta AT commands sin auth, "
                       "permite leer contactos, SMS, hacer llamadas y controlar el dispositivo. "
                       "Confirmación requiere ejecutar el exploit.",
        "exploit_id":  "bluebugging",
        "conditions":  {"service": ["Handsfree", "Headset", "Serial Port"]},
    },
    {
        "id":          "HID_INJECTION",
        "name":        "Bluetooth HID Injection — Inyección de Teclado",
        "cve":         "N/A",
        "severity":    "CRITICAL",
        "description": "El dispositivo acepta conexiones HID. Permite inyectar pulsaciones "
                       "de teclado para ejecutar comandos arbitrarios en el objetivo.",
        "exploit_id":  "hid_inject",
        "conditions":  {"service": ["Human Interface Device", "HID"]},
    },
    {
        "id":          "OBEX_PUSH_UNAUTH",
        "name":        "OBEX Push Expuesto — Posible envío sin autenticación",
        "cve":         "N/A",
        "severity":    "MEDIUM",
        "description": "El servicio OBEX Object Push está anunciado en SDP. "
                       "Si acepta archivos sin PIN, permite enviar payloads al dispositivo. "
                       "Requiere obexftp instalado para confirmación.",
        "exploit_id":  "obex_push",
        "conditions":  {"service": ["OBEX Object Push", "OBEX File Transfer"]},
    },
    {
        "id":          "BNEP_PAN_NETWORK",
        "name":        "Bluetooth PAN/BNEP — Posible acceso a red del dispositivo",
        "cve":         "N/A",
        "severity":    "HIGH",
        "description": "El dispositivo expone NAP/PANU (Bluetooth Personal Area Network). "
                       "Si acepta conexión sin auth, permite acceso a la red interna y pivoting. "
                       "Requiere bluez-compat (pand) para confirmación.",
        "exploit_id":  "bnep_pan",
        "conditions":  {"service": ["Android Network Access Point", "Network Access Point",
                                    "Android Network User", "PAN User"]},
    },
]


class VulnerabilityAnalyzer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def analyze(self, mac: str, dev_type: str = None) -> dict:
        """Análisis completo de un dispositivo Bluetooth.

        dev_type: 'Classic' o 'BLE' (si se omite, se infiere por la MAC).
        """
        # Inferir tipo por MAC si no se proporcionó
        if dev_type is None:
            dev_type = "BLE" if self._is_random_mac(mac) else "Classic"

        report = {
            "mac": mac,
            "type": dev_type,
            "device_info": {},
            "services": [],
            "vulnerabilities": [],
        }

        # 1. Información del dispositivo
        report["device_info"] = self._get_device_info(mac)

        # 2. Enumeración de servicios
        self._last_sdp_error = ""
        if dev_type == "BLE":
            # Para BLE usamos GATT en vez de SDP
            report["services"] = self._enumerate_gatt_services(mac)
            report["_gatt_accessible"] = len(report["services"]) > 0
        else:
            report["services"] = self._enumerate_services(mac)
            report["_gatt_accessible"] = False
            report["_sdp_error"] = self._last_sdp_error
            # Verificar conectividad L2CAP con 3 paquetes (más fiable que 1 solo)
            rc, l2out, _ = run_cmd(f"l2ping -c 3 -t 4 {mac} 2>/dev/null", timeout=15)
            responses = len(re.findall(r"bytes from", l2out))
            report["_l2cap_reachable"] = (rc == 0 and responses >= 2)

        # 3. Detección de vulnerabilidades
        report["vulnerabilities"] = self._check_vulnerabilities(report)

        return report

    def _is_random_mac(self, mac: str) -> bool:
        """MACs con segundo nibble 2,6,A,E son aleatorias → BLE. Mismo criterio que el scanner."""
        try:
            first_byte = int(mac.replace(":", "")[:2], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    # ── Info del dispositivo ────────────────────────────────────────────────
    def _get_device_info(self, mac: str) -> dict:
        info = {"MAC": mac}

        # Nombre
        _, out, _ = run_cmd(f"hcitool name {mac}", timeout=10)
        info["Nombre"] = out.strip() or "Desconocido"

        # Clase del dispositivo (CoD)
        _, out, _ = run_cmd(f"hcitool info {mac} 2>/dev/null", timeout=10)
        for line in out.splitlines():
            line = line.strip()
            if "Device Class:" in line:
                info["Clase"] = line.split(":", 1)[1].strip()
                info["Tipo detectado"] = self._classify_device(line)
            if "LMP Version:" in line:
                info["LMP Version"] = line.split(":", 1)[1].strip()
                info["Bluetooth Version"] = self._lmp_to_bt_version(line)
            if "Manufacturer:" in line:
                info["Fabricante"] = line.split(":", 1)[1].strip()
            if "Features:" in line:
                info["Features"] = line.split(":", 1)[1].strip()

        # OS Hint basado en nombre/clase
        info["OS estimado"] = self._guess_os(info)

        # LMP numérico para vulnerabilidades — extraer de (0xN) en el string
        # Formato hcitool: "LMP Version: 5.0 (0x9)  Subversion: 0x..."
        lmp_hex = re.search(r"\(0x([0-9a-f]+)\)", info.get("LMP Version", ""), re.IGNORECASE)
        info["_lmp_version_num"] = int(lmp_hex.group(1), 16) if lmp_hex else 99

        return info

    def _lmp_to_bt_version(self, lmp_line: str) -> str:
        mapping = {
            0:  "1.0b", 1:  "1.1",    2:  "1.2",
            3:  "2.0+EDR", 4: "2.1+EDR", 5: "3.0+HS",
            6:  "4.0",  7:  "4.1",    8:  "4.2",
            9:  "5.0",  10: "5.1",    11: "5.2",
            12: "5.3",  13: "5.4",    14: "6.0",
        }
        # Extraer el número hex entre paréntesis: "LMP Version: 5.0 (0x9)"
        m = re.search(r"\(0x([0-9a-f]+)\)", lmp_line, re.IGNORECASE)
        if m:
            n = int(m.group(1), 16)
            return "BT " + mapping.get(n, f"desconocida (LMP {n})")
        return "Desconocida"

    def _classify_device(self, cod_line: str) -> str:
        cod_lower = cod_line.lower()
        if "phone"      in cod_lower: return "Smartphone/Teléfono"
        if "computer"   in cod_lower: return "Computador"
        if "audio"      in cod_lower: return "Dispositivo de Audio"
        if "peripheral" in cod_lower: return "Periférico (teclado/ratón)"
        if "network"    in cod_lower: return "Dispositivo de Red"
        if "imaging"    in cod_lower: return "Cámara/Impresora"
        if "wearable"   in cod_lower: return "Wearable"
        if "toy"        in cod_lower: return "Juguete"
        return "Desconocido"

    def _guess_os(self, info: dict) -> str:
        name = info.get("Nombre", "").lower()
        mfr  = info.get("Fabricante", "").lower()
        if any(k in name for k in ["iphone", "ipad", "mac", "apple"]):    return "iOS/macOS"
        if any(k in name for k in ["android", "samsung", "pixel", "lg"]): return "Android"
        if any(k in name for k in ["windows", "pc", "laptop"]):            return "Windows"
        if any(k in name for k in ["linux", "ubuntu", "kali"]):            return "Linux"
        if "apple"   in mfr: return "iOS/macOS"
        if "samsung" in mfr: return "Android"
        if "intel"   in mfr: return "Windows/Linux"
        return "Desconocido"

    # ── Enumeración de servicios SDP (Classic BT) ──────────────────────────
    def _enumerate_services(self, mac: str) -> list[dict]:
        service_descriptions = {
            "Serial Port":                   "Canal serial (RFCOMM)",
            "OBEX Object Push":              "Transferencia de objetos sin auth",
            "OBEX File Transfer":            "Acceso al sistema de archivos",
            "Headset":                       "Auricular HSP",
            "Handsfree":                     "Manos libres HFP",
            "Audio Source":                  "Fuente de audio A2DP",
            "Audio Sink":                    "Sumidero de audio A2DP",
            "AVRCP":                         "Control de medios remotos",
            "Human Interface Device":        "Teclado/ratón (HID)",
            "PAN":                           "Red personal (PAN)",
            "Network Access Point":          "Punto de acceso de red (NAP)",
            "Android Network Access Point":  "NAP Android",
            "Android Network User":          "PAN Android",
            "PAN User":                      "Usuario PAN",
            "Message Access":                "Acceso a mensajes (MAP)",
            "Phonebook Access":              "Acceso a agenda (PBAP)",
            "SIM Access":                    "Acceso a SIM (SAP)",
        }

        def _parse_sdptool_output(raw: str) -> list[dict]:
            """Parsea la salida de sdptool browse."""
            result   = []
            current  = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("Service Name:"):
                    if current.get("name"):
                        result.append(current)
                    name = line.split(":", 1)[1].strip()
                    current = {
                        "name":        name,
                        "description": service_descriptions.get(name, ""),
                    }
                elif (line.startswith("Channel:") or line.startswith("Port:")):
                    current["port"] = line.split(":", 1)[1].strip()
                elif line.startswith("Protocol:"):
                    current["protocol"] = line.split(":", 1)[1].strip()
            if current.get("name"):
                result.append(current)
            return result

        # ── Intento 1: sdptool browse directo ──────────────────────────────
        _, out, err = run_cmd(f"sdptool browse {mac} 2>&1", timeout=25)
        services = _parse_sdptool_output(out)
        if services:
            return services

        # ── Intento 2: conectar via bluetoothctl (usa claves de emparejamiento) ──
        # Para dispositivos YA emparejados, bluetoothctl maneja la autenticación
        # correctamente antes de hacer el SDP browse.
        _, paired_out, _ = run_cmd("bluetoothctl devices Paired 2>/dev/null", timeout=5)
        is_paired = mac.upper() in paired_out.upper()

        if is_paired:
            # Conectar usando las claves almacenadas
            conn_cmd = (
                f"(echo 'power on'; sleep 0.5; echo 'connect {mac}'; sleep 5; echo 'quit') "
                f"| bluetoothctl 2>&1"
            )
            _, conn_out, _ = run_cmd(conn_cmd, timeout=12)
            time.sleep(2)
            _, out, _ = run_cmd(f"sdptool browse {mac} 2>/dev/null", timeout=25)
            services = _parse_sdptool_output(out)
            if services:
                return services
        else:
            # Dispositivo no emparejado: forzar conexión ACL directo
            run_cmd(f"hcitool cc {mac} 2>/dev/null", timeout=8)
            time.sleep(1)
            _, out, _ = run_cmd(f"sdptool browse {mac} 2>/dev/null", timeout=25)
            services = _parse_sdptool_output(out)
            if services:
                run_cmd(f"hcitool dc {mac} 2>/dev/null", timeout=5)
                return services

        # ── Intento 3: sdptool records (alternativa) ───────────────────────
        _, out, _ = run_cmd(f"sdptool records {mac} 2>/dev/null", timeout=20)
        services = _parse_sdptool_output(out)
        if services:
            return services

        # ── Intento 4: sdptool search por servicios específicos ────────────
        # Busca servicios conocidos aunque el browse general falle
        known_uuids = [
            ("0x1101", "Serial Port"),
            ("0x1105", "OBEX Object Push"),
            ("0x110B", "Audio Sink"),
            ("0x111E", "Handsfree"),
            ("0x1116", "Network Access Point"),
        ]
        found_by_search = []
        for uuid, name in known_uuids:
            rc_s, out_s, _ = run_cmd(
                f"sdptool search --bdaddr {mac} {uuid} 2>/dev/null", timeout=10
            )
            if rc_s == 0 and "Service Name" in out_s:
                partial = _parse_sdptool_output(out_s)
                found_by_search.extend(partial)
        if found_by_search:
            return found_by_search

        # ── Intento 5: sondeo RFCOMM directo en puertos conocidos ─────────
        # Cuando SDP falla (dispositivo conectado/ocupado), intenta conectar
        # directamente a puertos RFCOMM conocidos por tipo de dispositivo.
        # Permite detectar servicios sin SDP.
        known_ports = [
            (2,  "Handsfree",       "Manos libres HFP"),
            (3,  "Headset",         "Auricular HSP"),
            (1,  "Serial Port",     "Canal serial (RFCOMM)"),
            (5,  "OBEX Object Push","Transferencia de objetos sin auth"),
            (10, "Serial Port",     "Canal serial (RFCOMM)"),
            (17, "Serial Port",     "Canal serial (RFCOMM)"),
            (20, "Serial Port",     "Canal serial (RFCOMM)"),
        ]
        rfcomm_found = []
        for port, name, desc in known_ports:
            try:
                import socket as _socket
                sock = _socket.socket(
                    _socket.AF_BLUETOOTH, _socket.SOCK_STREAM, _socket.BTPROTO_RFCOMM
                )
                sock.settimeout(4)
                sock.connect((mac, port))
                # Si conecta, el puerto existe aunque SDP no respondió
                rfcomm_found.append({
                    "name":        name,
                    "description": desc,
                    "port":        str(port),
                })
                sock.close()
            except Exception:
                pass
        if rfcomm_found:
            return rfcomm_found

        # Guardar error SDP para mostrarlo en el reporte
        self._last_sdp_error = err.strip()[:200] if err else ""
        return []

    # ── Enumeración de servicios GATT (BLE) ────────────────────────────────
    def _enumerate_gatt_services(self, mac: str) -> list[dict]:
        """Lee servicios GATT vía gatttool para dispositivos BLE."""
        UUID_NAMES = {
            "00001800": "Acceso Genérico",
            "00001801": "Atributo Genérico",
            "0000180a": "Información del Dispositivo",
            "0000180d": "Frecuencia Cardíaca",
            "0000180f": "Nivel de Batería",
            "00001812": "HID (Teclado/Ratón BLE)",
            "0000fee7": "Servicio Propietario",
            "0000ae00": "Servicio Propietario",
        }
        services = []
        rc, out, _ = run_cmd(f"gatttool -b {mac} --primary 2>/dev/null", timeout=15)
        if rc != 0 or not out.strip():
            return services

        for line in out.splitlines():
            m = re.search(
                r"attr handle\s*=\s*(0x[\da-f]+).*uuid:\s*([\w-]+)",
                line, re.IGNORECASE
            )
            if m:
                uuid = m.group(2).lower()
                short = uuid[:8]
                nombre = UUID_NAMES.get(short, f"UUID {uuid[:8]}")
                services.append({
                    "name": nombre,
                    "uuid": uuid,
                    "handle": m.group(1),
                    "description": "Servicio GATT BLE",
                })
        return services

    # ── Detección de vulnerabilidades ───────────────────────────────────────
    def _check_vulnerabilities(self, report: dict) -> list[dict]:
        found   = []
        info    = report["device_info"]
        svcs    = report["services"]
        svc_names = [s.get("name", "") for s in svcs]
        lmp_ver = info.get("_lmp_version_num", 99)
        os_hint = info.get("OS estimado", "").lower()
        dev_type = report.get("type", "Classic")
        gatt_ok  = report.get("_gatt_accessible", False)

        for vuln in VULN_DB:
            cond = vuln["conditions"]
            match = True

            # Condición: LMP version máxima
            if "lmp_max" in cond and lmp_ver > cond["lmp_max"]:
                match = False

            # Condición: OS específico
            if "os_hint" in cond:
                if not any(o in os_hint for o in cond["os_hint"]):
                    match = False

            # Condición: servicio requerido
            if "service" in cond:
                if not any(svc in svc_names for svc in cond["service"]):
                    match = False

            # Condición: mínimo de servicios
            if "service_count_min" in cond:
                if len(svcs) < cond["service_count_min"]:
                    match = False

            # Condición: tipo BLE/Classic
            if "type" in cond and cond["type"] != dev_type:
                match = False

            # Condición: dispositivo BLE accesible sin auth (GATT respondió)
            if cond.get("no_auth") is True and not gatt_ok:
                match = False

            # Condición: BLE visible (dispositivo descubierto — no requiere GATT)
            if cond.get("ble_visible") is True:
                if dev_type != "BLE":
                    match = False
                # ble_visible no requiere gatt_ok — el dispositivo solo necesita ser visible

            # Condición: BLE accesible (para flood — solo si GATT responde)
            elif "type" in cond and cond["type"] == "BLE" and "no_auth" not in cond:
                if dev_type == "BLE" and not gatt_ok:
                    match = False

            # Condición: conectividad L2CAP confirmada
            if cond.get("l2cap_reachable") is True and not report.get("_l2cap_reachable"):
                match = False

            # Condición: servicio GATT específico presente
            if "gatt_service" in cond:
                need = cond["gatt_service"]
                gatt_svc_names = [s.get("name", "").lower() for s in svcs]
                gatt_uuids     = [s.get("uuid", "").lower()[:8] for s in svcs]
                if need == "hid":
                    if "00001812" not in gatt_uuids and not any("hid" in n for n in gatt_svc_names):
                        match = False
                elif need not in " ".join(gatt_svc_names):
                    match = False

            if match:
                found.append({
                    "name":        vuln["name"],
                    "cve":         vuln["cve"],
                    "severity":    vuln["severity"],
                    "description": vuln["description"],
                    "exploit_id":  vuln["exploit_id"],
                })

        return found
