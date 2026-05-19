#!/usr/bin/env python3
"""Utilidades generales para BlueStrike."""

import os
import sys

COLORS = {
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "blue":    "\033[94m",
    "cyan":    "\033[96m",
    "white":   "\033[97m",
    "reset":   "\033[0m",
    "bold":    "\033[1m",
}


def color(text: str, c: str) -> str:
    """Colorear texto para terminal."""
    return f"{COLORS.get(c, '')}{text}{COLORS['reset']}"


def banner():
    logo = (
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⢐⡋⡄⣤⠰⣄⡆⡤⣀⢓⠂⠄⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⡀⢈⣡⣞⡽⣾⣽⣿⣿⢿⣻⣿⢷⣯⣝⣦⣌⠃⡀⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⢠⠀⣰⣯⣷⢿⣿⣟⣿⣾⠙⢿⣿⣻⣿⢯⣿⣾⣞⡷⣌⠡⡀⠀⠀⠀\n"
        "⠀⠀⠀⢈⣾⣟⣷⡿⣿⣻⣾⢿⣿⠀⠀⠙⢿⣿⡿⣯⣷⣿⢿⣽⣦⠐⡀⠀⠀\n"
        "⠀⠀⢂⣿⣟⣾⡿⣿⣟⣿⣽⣿⣯⠀⠀⣀⠀⠉⢿⣿⣿⣾⡿⣟⣾⣧⠘⠄⠀\n"
        "⠀⠤⣼⣿⢿⣿⣷⣿⢿⣿⣟⣿⣯⠀⠀⣿⣦⡀⠈⠙⢿⣯⣷⣿⣿⣻⣆⠂⠀\n"
        "⠀⢰⣿⣿⣿⣯⣿⣅⠀⠙⢿⣿⣷⠀⠀⣿⣿⣿⠂⠀⢀⣽⣿⣿⣽⣿⣿⡀⡄\n"
        "⡠⣿⣿⣿⣿⣿⣿⣿⣶⡄⠀⠙⢿⠀⠀⢿⠛⠀⢀⣴⣾⣿⣿⣿⣿⣯⣿⣇⠃\n"
        "⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣯⢀\n"
        "⢈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⠐⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀\n"
        "⠠⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠁⠀⠀⠀⡀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀\n"
        "⠢⣿⣿⣿⣿⣿⣿⣿⠟⠁⢀⣴⣿⠀⠀⣿⣦⡀⠀⠙⢿⣿⣿⣿⣿⣿⣿⡏⡀\n"
        "⠀⢼⣿⣿⣿⣿⣿⡁⢀⣴⣿⣿⣿⠀⠀⣿⣿⡿⠂⠀⢀⣽⣿⣿⣿⣿⣿⠇⠇\n"
        "⠀⢀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠿⠋⠀⢀⣴⣿⣿⣿⣿⣿⣿⡟⡀⠀\n"
        "⠀⠀⠞⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⡿⢡⠀⠀\n"
        "⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⢃⠈⠀⠀\n"
        "⠀⠀⠀⠐⠜⢿⣿⣿⣿⣿⣿⣿⣿⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⡡⠂⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠘⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠗⠋⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠁⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
    )
    print(color(logo, "red"))
    print(color(r"""
  ██████╗ ██╗     ██╗   ██╗███████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
  ██████╔╝██║     ██║   ██║█████╗  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
  ██████╔╝███████╗╚██████╔╝███████╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
""", "blue"))
    print(color("  BlueStrike v1.0  —  Bluetooth Penetration Testing Framework", "white"))
    print(color("  Autor: Apo1o13", "yellow"))
    print(color("  [!] USO EXCLUSIVO EN ENTORNOS AUTORIZADOS — SOLO PARA PENTESTING", "red"))
    print(color("  " + "─" * 75 + "\n", "blue"))


def require_root():
    if os.geteuid() != 0:
        print(color("[!] Esta herramienta requiere privilegios root.", "red"))
        print(color("    Ejecuta: sudo python3 bluestrike.py [opciones]", "yellow"))
        sys.exit(1)


def run_cmd(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Ejecutar comando del sistema y retornar (returncode, stdout, stderr)."""
    import subprocess
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)
