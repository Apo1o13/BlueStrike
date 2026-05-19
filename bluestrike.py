#!/usr/bin/env python3
"""
BlueStrike - Herramienta de Pentesting Bluetooth
Autor: Apo1o13
Uso autorizado únicamente en dispositivos con permiso explícito.
Requiere Linux con BlueZ, ejecutar como root.
"""

import sys
import os
import argparse
import time
import json
from scanner import BluetoothScanner
from analyzer import VulnerabilityAnalyzer
from exploits import ExploitEngine, EXPLOIT_REGISTRY
from reporter import generate_html_report
from utils import banner, color, require_root


# ═══════════════════════════════════════════════════════════════════════════
# MODO INTERACTIVO GUIADO
# ═══════════════════════════════════════════════════════════════════════════

def ask(prompt: str, options: list[str] = None, default: str = None) -> str:
    """Pedir input al usuario con opciones y valor por defecto."""
    opts_str = ""
    if options:
        opts_str = " [" + "/".join(
            color(o.upper() if o == default else o, "yellow" if o == default else "white")
            for o in options
        ) + "]"
    if default:
        opts_str += f" (Enter = {default})"
    try:
        ans = input(color(f"\n  {prompt}{opts_str}: ", "cyan")).strip()
        return ans if ans else (default or "")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def separator():
    print(color("\n  " + "─" * 65, "blue"))


def interactive_mode():
    """Modo interactivo paso a paso que guía al usuario en el pentesting."""
    banner()
    require_root()

    print(color("  Bienvenido a BlueStrike — Modo Interactivo Guiado", "white"))
    print(color("  Serás guiado paso a paso por el proceso de pentesting Bluetooth.", "white"))
    separator()

    scanner  = BluetoothScanner(timeout=15, ble=False, verbose=False)
    analyzer = VulnerabilityAnalyzer(verbose=False)
    engine   = ExploitEngine(verbose=True)

    # ── PASO 0: Mostrar info del adaptador ──────────────────────────────────
    print(color("\n  [PASO 0] Verificando tu adaptador Bluetooth...", "yellow"))
    info = scanner.get_adapter_info()
    if "error" in info:
        print(color(f"\n  [✗] {info['error']}", "red"))
        print(color("  Asegúrate de tener un adaptador Bluetooth conectado y activo.", "yellow"))
        sys.exit(1)
    for k, v in info.items():
        print(f"      {color(k, 'yellow')}: {v}")
    separator()

    # ── PASO 1: Configuración del escaneo ───────────────────────────────────
    print(color("\n  [PASO 1] Configuración del escaneo", "yellow"))
    print(color("  BlueStrike puede buscar dispositivos Bluetooth Classic y/o BLE.", "white"))

    timeout_str = ask("¿Cuántos segundos quieres escanear?", default="20")
    try:
        timeout = int(timeout_str)
    except ValueError:
        timeout = 20

    ble_opt = ask("¿Incluir dispositivos BLE (Bluetooth Low Energy)?", options=["s", "n"], default="s")
    include_ble = ble_opt.lower() in ("s", "si", "sí", "y", "yes", "")

    scanner.timeout = timeout
    scanner.ble     = include_ble

    # ── PASO 2: Escaneo ─────────────────────────────────────────────────────
    separator()
    print(color(f"\n  [PASO 2] Escaneando dispositivos ({timeout}s)...", "yellow"))
    print(color("  Mantén los dispositivos objetivo encendidos y en rango.\n", "white"))

    devices = scanner.scan()

    if not devices:
        print(color("\n  [✗] No se encontraron dispositivos Bluetooth.", "red"))
        print(color("  Consejos:", "yellow"))
        print("    • Aumenta el tiempo de escaneo")
        print("    • Acércate más a los dispositivos")
        print("    • Asegúrate de que los dispositivos sean detectables")
        sys.exit(0)

    separator()
    print(color(f"\n  [+] {len(devices)} dispositivo(s) encontrado(s):\n", "green"))
    for i, dev in enumerate(devices, 1):
        tipo_color = "cyan" if dev.get("type") == "BLE" else "white"
        print(color(f"  [{i}]", "yellow") +
              f" {color(dev['name'], 'white')}"
              f"  MAC: {color(dev['mac'], 'cyan')}"
              f"  RSSI: {dev.get('rssi', 'N/A')} dBm"
              f"  [{color(dev.get('type', 'Classic'), tipo_color)}]")

    # ── PASO 3: Selección de objetivo ───────────────────────────────────────
    separator()
    print(color("\n  [PASO 3] Selección del objetivo", "yellow"))
    print(color("  Ingresa el número del dispositivo o su dirección MAC directamente.", "white"))

    sel = ask("Selecciona el dispositivo objetivo", default="1")
    target_mac  = None
    target_type = None   # 'Classic' o 'BLE'

    # Puede ser número de lista o MAC directa
    import re
    if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", sel):
        target_mac = sel.upper()
        # Buscar el tipo en la lista escaneada
        for dev in devices:
            if dev["mac"] == target_mac:
                target_type = dev.get("type")
                break
    else:
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(devices):
                target_mac  = devices[idx]["mac"]
                target_name = devices[idx]["name"]
                target_type = devices[idx].get("type")
                print(color(f"\n  [✓] Objetivo seleccionado: {target_name} ({target_mac})", "green"))
            else:
                print(color("  [✗] Número fuera de rango.", "red"))
                sys.exit(1)
        except ValueError:
            print(color("  [✗] Entrada inválida.", "red"))
            sys.exit(1)

    # ── PASO 4: Análisis de vulnerabilidades ────────────────────────────────
    separator()
    print(color(f"\n  [PASO 4] Analizando vulnerabilidades de {target_mac}...", "yellow"))
    print(color("  Recopilando información del dispositivo y enumerando servicios...\n", "white"))

    report = analyzer.analyze(target_mac, dev_type=target_type)

    # Mostrar info del dispositivo
    print(color("  Información del dispositivo:", "green"))
    for k, v in report["device_info"].items():
        if not k.startswith("_"):
            print(f"      {color(k, 'yellow')}: {v}")

    # Mostrar servicios (SDP para Classic, GATT para BLE)
    services = report.get("services", [])
    es_ble = report.get("type") == "BLE"
    tipo_svcs = "GATT" if es_ble else "SDP"
    if services:
        print(color(f"\n  Servicios {tipo_svcs} detectados ({len(services)}):", "green"))
        for svc in services:
            uuid_str = f"  UUID: {svc['uuid'][:8]}…" if svc.get("uuid") else ""
            port_str = f"  [puerto {svc['port']}]" if svc.get("port") else ""
            print(f"      • {color(svc['name'], 'white')}{port_str}{uuid_str}  "
                  f"{color(svc.get('description', ''), 'yellow')}")
    else:
        if es_ble:
            print(color("\n  [-] No se detectaron servicios GATT (dispositivo no respondió sin autenticación).", "yellow"))
        else:
            print(color("\n  [!] No se detectaron servicios SDP.", "yellow"))
            sdp_err = report.get("_sdp_error", "")
            if sdp_err:
                print(color(f"      Error: {sdp_err}", "red"))
            print(color("      Posibles causas:", "white"))
            print(color("        • El dispositivo no está en modo conectable/visible", "white"))
            print(color("        • Está emparejado con otro dispositivo y ocupa el canal", "white"))
            print(color("        • Intentá poner el dispositivo en modo discoverable y volvé a analizar", "yellow"))

    # Mostrar vulnerabilidades
    vulns = report.get("vulnerabilities", [])
    separator()
    if not vulns:
        print(color("\n  [✓] No se detectaron vulnerabilidades conocidas en este dispositivo.", "green"))
    else:
        print(color(f"\n  [!] {len(vulns)} VULNERABILIDAD(ES) DETECTADA(S):\n", "red"))
        for i, v in enumerate(vulns, 1):
            sev_color = {"CRITICAL": "red", "HIGH": "red",
                         "MEDIUM": "yellow", "LOW": "blue"}.get(v["severity"], "white")
            print(color(f"  [{i}] {v['name']}", "white") +
                  f"  [{color(v['severity'], sev_color)}]")
            print(f"       CVE      : {color(v.get('cve', 'N/A'), 'cyan')}")
            print(f"       Exploit  : {color(v.get('exploit_id', 'N/A'), 'yellow')}")
            print(f"       Detalle  : {v['description']}\n")

    # ── PASO 5: Explotación ─────────────────────────────────────────────────
    if not vulns:
        separator()
        print(color("\n  [*] No hay vulnerabilidades que explotar. Pentesting finalizado.", "yellow"))
        _save_results_prompt({target_mac: report})
        return

    separator()
    print(color("\n  [PASO 5] Explotación de vulnerabilidades", "yellow"))
    print(color("  Opciones disponibles:", "white"))
    print(color("  [A]", "yellow") + " Explotar todas las vulnerabilidades detectadas automáticamente")
    print(color("  [S]", "yellow") + " Seleccionar un exploit específico")
    print(color("  [N]", "yellow") + " Omitir explotación y solo guardar reporte")

    exp_opt = ask("¿Qué deseas hacer?", options=["a", "s", "n"], default="a")

    exploit_results = []

    if exp_opt.lower() in ("a", ""):
        # Deduplicar exploits por ID — no ejecutar el mismo dos veces
        seen_eids  = set()
        dedup_vulns = []
        for v in vulns:
            eid = v.get("exploit_id")
            if eid and eid not in seen_eids:
                seen_eids.add(eid)
                dedup_vulns.append(v)

        print(color(f"\n  [*] Iniciando explotación automática de {len(dedup_vulns)} exploit(s) únicos...\n", "cyan"))
        for vuln in dedup_vulns:
            eid = vuln.get("exploit_id")
            print(color(f"  [~] Lanzando: {vuln['name']} ({eid})", "yellow"))
            result = engine.run(eid, target_mac, report)
            status_color = "green" if result["success"] else "red"
            print(color(f"  [{'✓' if result['success'] else '✗'}] {result['message']}", status_color))
            if result.get("output"):
                for line in result["output"]:
                    print(f"      {line}")
            exploit_results.append({"exploit": eid, **result})
            separator()

    elif exp_opt.lower() == "s":
        # Selección manual
        print(color("\n  Exploits disponibles para este objetivo:\n", "white"))
        unique_eids = list({v["exploit_id"]: v for v in vulns if v.get("exploit_id")}.values())
        for i, v in enumerate(unique_eids, 1):
            print(color(f"  [{i}]", "yellow") + f" {v['exploit_id']}  — {v['name']}")

        # También mostrar todos los exploits del engine
        print(color("\n  Todos los exploits del motor:", "white"))
        for i, eid in enumerate(EXPLOIT_REGISTRY.keys(), 1):
            print(color(f"  [{i:2}]", "cyan") + f" {eid}")

        sel_exp = ask("Ingresa el ID del exploit o número de la lista", default=unique_eids[0]["exploit_id"] if unique_eids else "sdp_enum")
        # Puede ser número o nombre directo
        try:
            eid_final = unique_eids[int(sel_exp) - 1]["exploit_id"]
        except (ValueError, IndexError):
            eid_final = sel_exp

        print(color(f"\n  [~] Ejecutando exploit: {eid_final}", "yellow"))
        result = engine.run(eid_final, target_mac, report)
        status_color = "green" if result["success"] else "red"
        print(color(f"\n  [{'✓' if result['success'] else '✗'}] {result['message']}", status_color))
        if result.get("output"):
            for line in result["output"]:
                print(f"      {line}")
        exploit_results.append({"exploit": eid_final, **result})

    else:
        print(color("\n  [*] Explotación omitida.", "yellow"))

    # ── PASO 6: Guardar resultados ───────────────────────────────────────────
    report["exploit_results"] = exploit_results
    separator()
    _save_results_prompt({target_mac: report})

    print(color("\n  [✓] BlueStrike — Sesión finalizada.\n", "green"))


def _save_results_prompt(results: dict):
    """Preguntar si guardar resultados y en qué formato."""
    print(color("\n  [PASO 6] Guardar resultados", "yellow"))
    save = ask("¿Deseas guardar el reporte?", options=["s", "n"], default="s")
    if save.lower() not in ("s", "si", "sí", "y", "yes", ""):
        return

    fmt = ask("¿Formato del reporte?", options=["html", "json", "ambos"], default="html")

    base = ask("Nombre base del archivo", default="reporte_bluestrike")
    # Quitar extensiones si el usuario las puso
    base = base.replace(".html", "").replace(".json", "")

    if fmt in ("html", "ambos", ""):
        fname_html = base + ".html"
        try:
            generate_html_report(results, fname_html)
            abs_path = os.path.abspath(fname_html)
            print(color(f"\n  [✓] Reporte HTML guardado:", "green"))
            print(color(f"      Ruta    : {abs_path}", "cyan"))
            print(color(f"      Abrir   : xdg-open \"{abs_path}\"", "yellow"))
            print(color(f"      URL     : file://{abs_path}", "yellow"))
        except Exception as e:
            print(color(f"\n  [✗] Error generando HTML: {e}", "red"))

    if fmt in ("json", "ambos"):
        fname_json = base + ".json"
        with open(fname_json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        abs_json = os.path.abspath(fname_json)
        print(color(f"  [✓] Reporte JSON guardado en: {abs_json}", "green"))


# ═══════════════════════════════════════════════════════════════════════════
# MODO ARGPARSE (línea de comandos directa)
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="BlueStrike - Bluetooth Penetration Testing Tool | Autor: Apo1o13",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  sudo python3 bluestrike.py                     # Modo interactivo guiado\n"
            "  sudo python3 bluestrike.py -s -t 20 --ble      # Escanear 20s incluyendo BLE\n"
            "  sudo python3 bluestrike.py -a AA:BB:CC:DD:EE:FF -e  # Analizar y explotar\n"
            "  sudo python3 bluestrike.py --all -o reporte.json    # Modo completo\n"
        )
    )
    parser.add_argument("-s", "--scan",       action="store_true", help="Escanear dispositivos Bluetooth cercanos")
    parser.add_argument("-t", "--timeout",    type=int, default=15, help="Tiempo de escaneo en segundos (default: 15)")
    parser.add_argument("-a", "--analyze",    metavar="MAC",        help="Analizar vulnerabilidades de un dispositivo MAC")
    parser.add_argument("-e", "--exploit",    action="store_true",  help="Explotar vulnerabilidades encontradas (requiere -a)")
    parser.add_argument("-x", "--exploit-id", metavar="ID",         help="Ejecutar exploit específico por ID")
    parser.add_argument("-i", "--info",       action="store_true",  help="Mostrar info del adaptador Bluetooth local")
    parser.add_argument("--ble",              action="store_true",  help="Incluir dispositivos BLE (Bluetooth Low Energy)")
    parser.add_argument("--all",              action="store_true",  help="Escanear + analizar + explotar todos los dispositivos")
    parser.add_argument("-o", "--output",     metavar="FILE",       help="Guardar resultados en archivo JSON")
    parser.add_argument("-v", "--verbose",    action="store_true",  help="Modo verbose")
    parser.add_argument("--list-exploits",    action="store_true",  help="Listar todos los exploits disponibles")
    return parser.parse_args()


def cli_mode(args):
    """Modo de línea de comandos directa."""
    banner()
    require_root()

    scanner  = BluetoothScanner(timeout=args.timeout, ble=args.ble, verbose=args.verbose)
    analyzer = VulnerabilityAnalyzer(verbose=args.verbose)
    engine   = ExploitEngine(verbose=args.verbose)
    results  = {}

    # ── Listar exploits ──────────────────────────────────────────────────────
    if args.list_exploits:
        print(color("\n  Exploits disponibles en BlueStrike:\n", "cyan"))
        for eid in EXPLOIT_REGISTRY:
            print(f"    {color('►', 'red')} {color(eid, 'yellow')}")
        print()
        return

    # ── Info del adaptador ───────────────────────────────────────────────────
    if args.info or args.all:
        print(color("\n[*] Información del adaptador Bluetooth local:", "cyan"))
        info = scanner.get_adapter_info()
        for k, v in info.items():
            print(f"    {color(k, 'yellow')}: {v}")

    # ── Escaneo ──────────────────────────────────────────────────────────────
    devices = []
    if args.scan or args.all:
        print(color(f"\n[*] Iniciando escaneo Bluetooth ({args.timeout}s)...", "cyan"))
        devices = scanner.scan()
        if not devices:
            print(color("[-] No se encontraron dispositivos.", "red"))
        else:
            print(color(f"\n[+] {len(devices)} dispositivo(s) encontrado(s):\n", "green"))
            for i, dev in enumerate(devices, 1):
                print(color(f"  [{i}] {dev['name']}", "white") +
                      f"  MAC: {color(dev['mac'], 'yellow')}"
                      f"  RSSI: {dev.get('rssi', 'N/A')} dBm"
                      f"  Tipo: {dev.get('type', 'Classic')}")
                if args.verbose and dev.get("services"):
                    for svc in dev["services"]:
                        print(f"       Servicio: {svc}")

    # ── Análisis ─────────────────────────────────────────────────────────────
    target_mac = args.analyze
    if target_mac or args.all:
        targets = [(target_mac, None)] if target_mac else [(d["mac"], d.get("type")) for d in devices]
        for mac, dev_type in targets:
            print(color(f"\n[*] Analizando {mac}...", "cyan"))
            report = analyzer.analyze(mac, dev_type=dev_type)
            results[mac] = report

            print(color(f"\n  [+] Información del dispositivo:", "green"))
            for k, v in report["device_info"].items():
                if not k.startswith("_"):
                    print(f"      {color(k, 'yellow')}: {v}")

            print(color(f"\n  [+] Servicios detectados:", "green"))
            for svc in report.get("services", []):
                print(f"      • {svc['name']}  [{svc.get('port', '')}]  {svc.get('description', '')}")

            vulns = report.get("vulnerabilities", [])
            if vulns:
                print(color(f"\n  [!] {len(vulns)} vulnerabilidad(es) encontrada(s):", "red"))
                for v in vulns:
                    sev_color = {"CRITICAL": "red", "HIGH": "red",
                                 "MEDIUM": "yellow", "LOW": "blue"}.get(v["severity"], "white")
                    print(f"\n      {color('►', sev_color)} {color(v['name'], 'white')}  "
                          f"[{color(v['severity'], sev_color)}]")
                    print(f"        CVE     : {v.get('cve', 'N/A')}")
                    print(f"        Desc    : {v['description']}")
                    print(f"        Exploit : {color(v.get('exploit_id', 'N/A'), 'cyan')}")
            else:
                print(color("\n  [-] No se detectaron vulnerabilidades conocidas.", "yellow"))

            # Explotación automática
            if (args.exploit or args.all) and vulns:
                print(color(f"\n  [*] Iniciando explotación automática en {mac}...", "cyan"))
                for vuln in vulns:
                    eid = vuln.get("exploit_id")
                    if not eid:
                        continue
                    print(color(f"\n    [~] Ejecutando exploit: {eid}", "yellow"))
                    result = engine.run(eid, mac, report)
                    status_color = "green" if result["success"] else "red"
                    print(color(f"    [{'✓' if result['success'] else '✗'}] {result['message']}", status_color))
                    if result.get("output"):
                        for line in result["output"]:
                            print(f"        {line}")

    # ── Exploit específico ───────────────────────────────────────────────────
    if args.exploit_id and args.analyze:
        print(color(f"\n[*] Ejecutando exploit {args.exploit_id} en {args.analyze}...", "cyan"))
        report = results.get(args.analyze) or analyzer.analyze(args.analyze)
        result = engine.run(args.exploit_id, args.analyze, report)
        status_color = "green" if result["success"] else "red"
        print(color(f"[{'✓' if result['success'] else '✗'}] {result['message']}", status_color))
        if result.get("output"):
            for line in result["output"]:
                print(f"    {line}")

    # ── Guardar resultados ───────────────────────────────────────────────────
    if args.output and results:
        if args.output.endswith(".html"):
            generate_html_report(results, args.output)
            print(color(f"\n[+] Reporte HTML guardado en: {args.output}", "green"))
        else:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(color(f"\n[+] Reporte JSON guardado en: {args.output}", "green"))

    if not any([args.scan, args.analyze, args.info, args.all,
                args.exploit_id, args.list_exploits]):
        # Sin argumentos → modo interactivo
        interactive_mode()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    # Si no se pasó ningún argumento → modo interactivo guiado
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(color("\n\n  [!] Abortado por el usuario.", "yellow"))
        sys.exit(0)
