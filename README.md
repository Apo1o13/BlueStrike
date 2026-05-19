<div align="center">

<img src="logo.png" alt="BlueStrike Logo" width="500"/>

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)
![BlueZ](https://img.shields.io/badge/BlueZ-5.x-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Author](https://img.shields.io/badge/Autor-Apo1o13-red?style=flat-square)

> ⚠️ **USO EXCLUSIVO EN ENTORNOS AUTORIZADOS** — Esta herramienta es para pentesting profesional, CTFs e investigación de seguridad. Usar contra dispositivos sin permiso explícito es ilegal.

</div>

---

## ¿Qué es BlueStrike?

BlueStrike es un framework de pentesting Bluetooth que automatiza el proceso completo de auditoría: desde el descubrimiento de dispositivos hasta la explotación de vulnerabilidades conocidas. Compatible con Bluetooth Classic y BLE (Bluetooth Low Energy). Diseñado para ser usado tanto por pentesters experimentados como por quienes se inician en seguridad inalámbrica.

---

## Características

- **Escaneo automático** de dispositivos Bluetooth Classic y BLE vía `bluetoothctl`
- **Análisis de vulnerabilidades** basado en versión LMP/BT, servicios SDP, perfil GATT y OS detectado
- **16+ exploits integrados** listos para usar
- **Modo interactivo guiado** paso a paso — no requiere memorizar comandos
- **Modo CLI** para integración en scripts y automatización
- **Reportes HTML y JSON** con dashboard oscuro exportable
- Detección automática del tipo de dispositivo, fabricante, versión de Bluetooth y OS estimado
- Compatible con VMware / VirtualBox (usa `bluetoothctl` como motor principal)
- Sin falsos positivos — solo reporta vulnerabilidades verificadas

---

## Exploits disponibles

### Bluetooth Classic

| ID | Vulnerabilidad | CVE | Severidad |
|----|---------------|-----|-----------|
| `blueborne_rce` | BlueBorne RCE — Stack overflow L2CAP en Linux BlueZ | CVE-2017-1000251 | CRITICAL |
| `blueborne_info` | BlueBorne Info Leak — Fuga de memoria SDP Android | CVE-2017-0785 | HIGH |
| `knob_attack` | KNOB — Reducción de entropía de clave a 1 byte | CVE-2019-9506 | HIGH |
| `bias_attack` | BIAS — Suplantación en autenticación SSP | CVE-2020-10135 | HIGH |
| `bluesmack` | BlueSmack — DoS con paquetes L2CAP oversized | CVE-2004-0478 | MEDIUM |
| `bluesnarfer` | BlueSnarfing — Extracción de datos OBEX sin auth | N/A | HIGH |
| `sdp_enum` | SDP Enumeration — Blueprinting completo de servicios | N/A | LOW |
| `rfcomm_shell` | RFCOMM Shell — Acceso interactivo / comandos AT | N/A | HIGH |
| `bluebugging` | BlueBugging — Control via AT Commands (contactos, SMS, llamadas) | N/A | HIGH |
| `hid_inject` | HID Injection — Inyección de teclado sobre HID Classic | N/A | CRITICAL |
| `obex_push` | OBEX Push — Envío de archivos sin autenticación | N/A | MEDIUM |
| `bnep_pan` | BNEP/PAN — Acceso a red interna del dispositivo | N/A | HIGH |
| `avrcp_control` | AVRCP Control — Pause/play/stop remoto en Smart TVs y set-top boxes | N/A | HIGH |

### BLE (Bluetooth Low Energy)

| ID | Vulnerabilidad | CVE | Severidad |
|----|---------------|-----|-----------|
| `ble_mitm` | BLE Fuga de Información GATT sin autenticación | N/A | HIGH |
| `ble_hid_inject` | BLE HID Injection — Inyección ratón/teclado BLE sin auth | N/A | CRITICAL |
| `ble_flood` | BLE Advertisement Flood — DoS a dispositivos IoT BLE | N/A | MEDIUM |
| `ble_spoof` | BLE Impersonation — Clonar MAC, desconectar dispositivo y suplantar identidad para interceptar reconexión del host | N/A | HIGH |

---

## Requisitos

- **OS:** Kali Linux / Ubuntu — exploit `avrcp_control` compatible con Windows
- **Python:** 3.10+
- **Privilegios:** root (`sudo`)
- **Hardware:** Adaptador Bluetooth (interno o USB — compatible con VMware)
- **Dependencias:** `bluez`, `bluez-tools`, `l2ping`, `sdptool`, `gatttool`, `rfcomm`, `obexftp`, `blueman`

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Apo1o13/BlueStrike.git
cd BlueStrike

# Instalar todas las dependencias automáticamente
sudo bash install.sh
```

O manualmente:

```bash
sudo apt install -y bluez bluez-tools bluetooth l2ping rfcomm gatttool blueman
pip3 install -r requirements.txt --break-system-packages
```

---

## Uso

### Modo interactivo guiado (recomendado)

Ejecutá sin argumentos — BlueStrike te guía paso a paso:

```bash
sudo python3 bluestrike.py
```

**El flujo interactivo tiene 6 pasos:**

```
[PASO 0] Verificar adaptador Bluetooth (nombre, versión HCI/LMP, estado)
[PASO 1] Configurar tiempo de escaneo y si incluir BLE
[PASO 2] Escanear y listar dispositivos encontrados con RSSI y tipo
[PASO 3] Seleccionar objetivo por número de lista o MAC directa
[PASO 4] Analizar vulnerabilidades (servicios SDP/GATT, versión BT, OS, fabricante)
[PASO 5] Explotar: automático / seleccionar uno / saltar
[PASO 6] Guardar reporte en HTML y/o JSON con ruta absoluta
```

---

### Modo CLI

```bash
# Ver info del adaptador Bluetooth local
sudo python3 bluestrike.py -i

# Escanear 30 segundos incluyendo BLE
sudo python3 bluestrike.py -s -t 30 --ble

# Analizar un dispositivo específico por MAC
sudo python3 bluestrike.py -a AA:BB:CC:DD:EE:FF

# Analizar y explotar automáticamente
sudo python3 bluestrike.py -a AA:BB:CC:DD:EE:FF -e

# Ejecutar un exploit específico
sudo python3 bluestrike.py -a AA:BB:CC:DD:EE:FF -x ble_hid_inject

# Modo completo: escanear + analizar todos + explotar + guardar
sudo python3 bluestrike.py --all -o reporte.json

# Listar todos los exploits disponibles
sudo python3 bluestrike.py --list-exploits
```

### Referencia de argumentos

| Argumento | Descripción |
|-----------|-------------|
| `-s` / `--scan` | Escanear dispositivos cercanos |
| `-t N` / `--timeout N` | Tiempo de escaneo en segundos (default: 15) |
| `--ble` | Incluir dispositivos BLE en el escaneo |
| `-a MAC` / `--analyze MAC` | Analizar vulnerabilidades de un dispositivo |
| `-e` / `--exploit` | Explotar todas las vulnerabilidades detectadas |
| `-x ID` / `--exploit-id ID` | Ejecutar un exploit específico por ID |
| `-i` / `--info` | Mostrar info del adaptador Bluetooth local |
| `--all` | Escanear + analizar + explotar todo automáticamente |
| `-o FILE` / `--output FILE` | Guardar resultados en JSON |
| `-v` / `--verbose` | Modo verbose — más detalles en la salida |
| `--list-exploits` | Listar todos los exploits registrados |

---

## ¿Qué analiza BlueStrike?

### Para dispositivos Classic BT:
- **Versión LMP/Bluetooth** (1.0 a 6.0) para detectar CVEs aplicables
- **Servicios SDP expuestos** (RFCOMM, OBEX, HFP, A2DP, PAN, HID, etc.)
- **Canales RFCOMM** accesibles y su respuesta a comandos AT
- **OS estimado** basado en nombre y fabricante
- **Conectividad L2CAP** para validar BlueSmack antes de reportarlo

### Para dispositivos BLE:
- **Servicios GATT primarios** con sus UUIDs y rangos de handles
- **Características GATT** con permisos reales (Lectura, Escritura, Notificación, Indicación)
- **Datos accesibles sin autenticación** (nombre, fabricante, modelo, firmware, MAC)
- **Report Map HID** para identificar si es ratón, teclado, gamepad, etc.
- **Verificación de write** sin auth en handles HID para confirmar inyección real

---

## Ejemplo de salida — dispositivo BLE (ratón)

```
Servicios GATT detectados (8):
  • Acceso Genérico          UUID: 00001800…
  • Información del Dispositivo  UUID: 0000180a…
  • HID (Teclado/Ratón BLE)  UUID: 00001812…

[!] 2 VULNERABILIDAD(ES) DETECTADA(S):

[1] BLE Fuga de Información sin Autenticación  [HIGH]
     Exploit: ble_mitm

[2] BLE HID Inyección sin Autenticación        [CRITICAL]
     Exploit: ble_hid_inject

[*] Leyendo 10 handles con permiso de Lectura...
    Handle 0x0003: 46 35 37 4c  →  "F57L"
    Handle 0x002c: 7a 68 75 68...  →  "zhuhai_jieli"
    Handle 0x0030: 68 69 64 5f...  →  "hid_mouse"

[!] Datos sensibles leídos sin autenticación:
    ► 0x002c: "zhuhai_jieli"
    ► 0x0030: "hid_mouse"
    ► 0x0034: "0.0.1"
```

## Ejemplo de salida — dispositivo Classic (Android TV Box)

```
Servicios SDP detectados (11):
  • Handsfree Gateway        [puerto 3]
  • Android Network Access Point  NAP Android
  • Android Network User     PAN Android
  • OBEX Object Push         [puerto 5]
  • Android TV Remote        [puerto 6]

[!] 7 VULNERABILIDAD(ES) DETECTADA(S):

[1] BlueSmack DoS                              [MEDIUM]
[2] Bluetooth Fingerprinting / Blueprinting    [LOW]
[3] Canal RFCOMM Expuesto                      [MEDIUM]
[4] Posible BlueBugging — AT Commands          [HIGH]
[5] OBEX Push Expuesto                         [MEDIUM]
[6] Bluetooth PAN/BNEP — Acceso a red         [HIGH]
```

---

## Estructura del proyecto

```
BlueStrike/
├── bluestrike.py     # Punto de entrada + modo interactivo guiado + CLI
├── scanner.py        # Escaneo Bluetooth Classic y BLE via bluetoothctl
├── analyzer.py       # Análisis de vulnerabilidades, SDP, GATT, LMP
├── exploits.py       # Motor de exploits (16+ módulos)
├── reporter.py       # Generador de reportes HTML con dashboard oscuro
├── utils.py          # Banner, colores, helpers
├── requirements.txt  # Dependencias Python (bleak)
├── install.sh        # Script de instalación automática
└── logo.png          # Logo oficial del framework
```

---

## Aviso legal

Esta herramienta fue desarrollada con fines educativos y de investigación en seguridad. El autor **Apo1o13** no se hace responsable del uso indebido. Úsala únicamente en dispositivos de tu propiedad o con permiso escrito del propietario. El uso no autorizado puede ser ilegal en tu jurisdicción.

---

<div align="center">

Desarrollado por **Apo1o13**

</div>
