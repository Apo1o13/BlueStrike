#!/usr/bin/env python3
"""
BlueStrike — Generador de reportes HTML
"""

import json
from datetime import datetime


def generate_html_report(results: dict, output_file: str = "reporte_bluestrike.html"):
    """Genera un reporte HTML profesional a partir de los resultados del scan."""

    sev_color = {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd60a",
        "LOW":      "#30d158",
        "N/A":      "#8e8e93",
    }
    sev_bg = {
        "CRITICAL": "rgba(255,45,85,0.15)",
        "HIGH":     "rgba(255,107,53,0.15)",
        "MEDIUM":   "rgba(255,214,10,0.15)",
        "LOW":      "rgba(48,209,88,0.15)",
        "N/A":      "rgba(142,142,147,0.15)",
    }

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Estadísticas globales ────────────────────────────────────────────────
    total_devices = len(results)
    all_vulns     = []
    for mac, report in results.items():
        for v in report.get("vulnerabilities", []):
            all_vulns.append({**v, "mac": mac,
                               "device": report.get("device_info", {}).get("Nombre", mac)})

    critical = sum(1 for v in all_vulns if v["severity"] == "CRITICAL")
    high     = sum(1 for v in all_vulns if v["severity"] == "HIGH")
    medium   = sum(1 for v in all_vulns if v["severity"] == "MEDIUM")
    low      = sum(1 for v in all_vulns if v["severity"] == "LOW")

    # ── Generar cards de dispositivos ────────────────────────────────────────
    device_cards = ""
    for mac, report in results.items():
        info     = report.get("device_info", {})
        services = report.get("services", [])
        vulns    = report.get("vulnerabilities", [])
        exploits = report.get("exploit_results", [])

        # Servicios
        services_html = ""
        for svc in services:
            services_html += f"""
            <div class="service-item">
                <span class="service-name">{svc.get('name','?')}</span>
                {f'<span class="service-port">canal {svc["port"]}</span>' if svc.get('port') else ''}
                {f'<span class="service-desc">{svc["description"]}</span>' if svc.get('description') else ''}
            </div>"""

        # Vulnerabilidades
        vulns_html = ""
        for v in vulns:
            sc = sev_color.get(v["severity"], "#8e8e93")
            sb = sev_bg.get(v["severity"], "rgba(0,0,0,0.1)")
            cve_badge = f'<span class="cve-badge">{v.get("cve","N/A")}</span>' if v.get("cve","N/A") != "N/A" else ""
            vulns_html += f"""
            <div class="vuln-card" style="border-left: 3px solid {sc}; background: {sb};">
                <div class="vuln-header">
                    <span class="vuln-name">{v['name']}</span>
                    <span class="severity-badge" style="background:{sc};">{v['severity']}</span>
                </div>
                <div class="vuln-details">
                    {cve_badge}
                    <span class="exploit-id">exploit: {v.get('exploit_id','N/A')}</span>
                </div>
                <p class="vuln-desc">{v['description']}</p>
            </div>"""

        # Resultados de explotación
        exploits_html = ""
        for ex in exploits:
            status_color = "#30d158" if ex.get("success") else "#ff2d55"
            status_icon  = "✓" if ex.get("success") else "✗"
            output_lines = "\n".join(ex.get("output", []))
            exploits_html += f"""
            <div class="exploit-result" style="border-left: 3px solid {status_color};">
                <div class="exploit-header">
                    <span class="exploit-status" style="color:{status_color};">[{status_icon}]</span>
                    <span class="exploit-id-label">{ex.get('exploit','?')}</span>
                </div>
                <p class="exploit-message">{ex.get('message','')}</p>
                {f'<pre class="exploit-output">{output_lines}</pre>' if output_lines else ''}
            </div>"""

        # Info del dispositivo
        info_rows = ""
        for k, v in info.items():
            if not k.startswith("_"):
                info_rows += f'<tr><td class="info-key">{k}</td><td class="info-val">{v}</td></tr>'

        device_cards += f"""
        <div class="device-card">
            <div class="device-header">
                <div class="device-title">
                    <span class="device-icon">📡</span>
                    <div>
                        <h2 class="device-name">{info.get('Nombre', 'Desconocido')}</h2>
                        <span class="device-mac">{mac}</span>
                    </div>
                </div>
                <div class="device-stats">
                    <span class="stat-pill" style="background:rgba(255,45,85,0.2);color:#ff2d55;">
                        {sum(1 for v in vulns if v['severity']=='CRITICAL')} CRITICAL
                    </span>
                    <span class="stat-pill" style="background:rgba(255,107,53,0.2);color:#ff6b35;">
                        {sum(1 for v in vulns if v['severity']=='HIGH')} HIGH
                    </span>
                    <span class="stat-pill" style="background:rgba(255,214,10,0.2);color:#ffd60a;">
                        {sum(1 for v in vulns if v['severity']=='MEDIUM')} MEDIUM
                    </span>
                </div>
            </div>

            <div class="device-body">
                <div class="section">
                    <h3 class="section-title">Información del dispositivo</h3>
                    <table class="info-table">{info_rows}</table>
                </div>

                {f'<div class="section"><h3 class="section-title">Servicios detectados ({len(services)})</h3><div class="services-grid">{services_html}</div></div>' if services else ''}

                {f'<div class="section"><h3 class="section-title">Vulnerabilidades ({len(vulns)})</h3>{vulns_html}</div>' if vulns else '<div class="section"><p class="no-vulns">✓ No se detectaron vulnerabilidades conocidas</p></div>'}

                {f'<div class="section"><h3 class="section-title">Resultados de explotación</h3>{exploits_html}</div>' if exploits else ''}
            </div>
        </div>"""

    # ── HTML completo ────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlueStrike — Reporte de Pentesting Bluetooth</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
            background: #0a0a0f;
            color: #e5e5ea;
            min-height: 100vh;
            padding: 20px;
        }}

        /* ── Header ── */
        .header {{
            text-align: center;
            padding: 40px 20px;
            border-bottom: 1px solid #1c1c1e;
            margin-bottom: 30px;
        }}

        .logo {{
            font-size: 11px;
            color: #ff2d55;
            line-height: 1.2;
            white-space: pre;
            margin-bottom: 20px;
        }}

        .tool-name {{
            font-size: 36px;
            font-weight: 700;
            color: #fff;
            letter-spacing: 4px;
        }}

        .tool-name span {{ color: #0a84ff; }}

        .tool-subtitle {{
            color: #8e8e93;
            font-size: 14px;
            margin-top: 8px;
        }}

        .report-meta {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            font-size: 12px;
            color: #636366;
        }}

        .report-meta span {{ color: #aeaeb2; }}

        .warning-banner {{
            background: rgba(255, 45, 85, 0.1);
            border: 1px solid rgba(255, 45, 85, 0.3);
            border-radius: 8px;
            padding: 10px 20px;
            text-align: center;
            color: #ff2d55;
            font-size: 12px;
            margin: 20px auto;
            max-width: 700px;
        }}

        /* ── Stats globales ── */
        .global-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            max-width: 900px;
            margin: 0 auto 40px;
        }}

        .stat-card {{
            background: #1c1c1e;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid #2c2c2e;
        }}

        .stat-number {{
            font-size: 40px;
            font-weight: 700;
            line-height: 1;
        }}

        .stat-label {{
            font-size: 11px;
            color: #8e8e93;
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        /* ── Device cards ── */
        .devices-container {{
            max-width: 960px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        .device-card {{
            background: #1c1c1e;
            border-radius: 16px;
            border: 1px solid #2c2c2e;
            overflow: hidden;
        }}

        .device-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            background: #2c2c2e;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .device-title {{
            display: flex;
            align-items: center;
            gap: 14px;
        }}

        .device-icon {{ font-size: 28px; }}

        .device-name {{
            font-size: 20px;
            font-weight: 600;
            color: #fff;
        }}

        .device-mac {{
            font-size: 12px;
            color: #0a84ff;
            font-family: monospace;
        }}

        .device-stats {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .stat-pill {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }}

        .device-body {{
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        /* ── Sections ── */
        .section-title {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #8e8e93;
            margin-bottom: 12px;
            border-bottom: 1px solid #2c2c2e;
            padding-bottom: 8px;
        }}

        /* ── Info table ── */
        .info-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .info-table tr {{ border-bottom: 1px solid #2c2c2e; }}
        .info-table tr:last-child {{ border-bottom: none; }}
        .info-key {{ color: #8e8e93; padding: 6px 12px 6px 0; width: 180px; }}
        .info-val {{ color: #e5e5ea; padding: 6px 0; }}

        /* ── Services ── */
        .services-grid {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .service-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            padding: 6px 10px;
            background: #2c2c2e;
            border-radius: 6px;
        }}

        .service-name {{ color: #e5e5ea; font-weight: 500; }}
        .service-port {{
            background: #3a3a3c;
            color: #0a84ff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .service-desc {{ color: #636366; font-size: 12px; }}

        /* ── Vuln cards ── */
        .vuln-card {{
            padding: 14px 16px;
            border-radius: 8px;
            margin-bottom: 10px;
        }}

        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .vuln-name {{ font-weight: 600; font-size: 14px; color: #fff; }}

        .severity-badge {{
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            color: #000;
        }}

        .vuln-details {{
            display: flex;
            gap: 8px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }}

        .cve-badge {{
            background: #2c2c2e;
            color: #ffd60a;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}

        .exploit-id {{
            background: #2c2c2e;
            color: #0a84ff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}

        .vuln-desc {{ color: #aeaeb2; font-size: 13px; line-height: 1.5; }}

        .no-vulns {{
            color: #30d158;
            font-size: 14px;
            padding: 10px 0;
        }}

        /* ── Exploit results ── */
        .exploit-result {{
            padding: 12px 16px;
            border-radius: 8px;
            background: #2c2c2e;
            margin-bottom: 10px;
        }}

        .exploit-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 6px;
        }}

        .exploit-status {{ font-weight: 700; font-size: 16px; }}
        .exploit-id-label {{ font-size: 13px; color: #0a84ff; font-family: monospace; }}
        .exploit-message {{ font-size: 13px; color: #aeaeb2; margin-bottom: 8px; }}

        .exploit-output {{
            background: #0a0a0f;
            border-radius: 6px;
            padding: 12px;
            font-size: 11px;
            color: #30d158;
            overflow-x: auto;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* ── Footer ── */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #3a3a3c;
            font-size: 12px;
            margin-top: 40px;
            border-top: 1px solid #1c1c1e;
        }}

        .footer strong {{ color: #636366; }}
    </style>
</head>
<body>

    <div class="header">
        <pre class="logo">⠀⠀⠀⠀⠀⠀⠀⠀⠀⢐⡋⡄⣤⠰⣄⡆⡤⣀⢓⠂⠄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡀⢈⣡⣞⡽⣾⣽⣿⣿⢿⣻⣿⢷⣯⣝⣦⣌⠃⡀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠀⣰⣯⣷⢿⣿⣟⣿⣾⠙⢿⣿⣻⣿⢯⣿⣾⣞⡷⣌⠡⡀⠀⠀⠀
⠀⠀⠀⢈⣾⣟⣷⡿⣿⣻⣾⢿⣿⠀⠀⠙⢿⣿⡿⣯⣷⣿⢿⣽⣦⠐⡀⠀⠀
⠀⠀⢂⣿⣟⣾⡿⣿⣟⣿⣽⣿⣯⠀⠀⣀⠀⠉⢿⣿⣿⣾⡿⣟⣾⣧⠘⠄⠀
⠀⠤⣼⣿⢿⣿⣷⣿⢿⣿⣟⣿⣯⠀⠀⣿⣦⡀⠈⠙⢿⣯⣷⣿⣿⣻⣆⠂⠀
⠀⢰⣿⣿⣿⣯⣿⣅⠀⠙⢿⣿⣷⠀⠀⣿⣿⣿⠂⠀⢀⣽⣿⣿⣽⣿⣿⡀⡄
⡠⣿⣿⣿⣿⣿⣿⣿⣶⡄⠀⠙⢿⠀⠀⢿⠛⠀⢀⣴⣾⣿⣿⣿⣿⣯⣿⣇⠃
⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣯⢀
⢈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⠐⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀
⠠⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠁⠀⠀⠀⡀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀
⠢⣿⣿⣿⣿⣿⣿⣿⠟⠁⢀⣴⣿⠀⠀⣿⣦⡀⠀⠙⢿⣿⣿⣿⣿⣿⣿⡏⡀
⠀⢼⣿⣿⣿⣿⣿⡁⢀⣴⣿⣿⣿⠀⠀⣿⣿⡿⠂⠀⢀⣽⣿⣿⣿⣿⣿⠇⠇
⠀⢀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠿⠋⠀⢀⣴⣿⣿⣿⣿⣿⣿⡟⡀⠀
⠀⠀⠞⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⡿⢡⠀⠀
⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⢃⠈⠀⠀
⠀⠀⠀⠐⠜⢿⣿⣿⣿⣿⣿⣿⣿⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⡡⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠗⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀</pre>
        <div class="tool-name">BLUE<span>STRIKE</span></div>
        <div class="tool-subtitle">Bluetooth Penetration Testing Framework — Reporte de Auditoría</div>
        <div class="report-meta">
            <div>Fecha: <span>{now}</span></div>
            <div>Dispositivos analizados: <span>{total_devices}</span></div>
            <div>Vulnerabilidades totales: <span>{len(all_vulns)}</span></div>
            <div>Autor: <span>Apo1o13</span></div>
        </div>
        <div class="warning-banner">
            ⚠ CONFIDENCIAL — Reporte generado para uso exclusivo en entornos autorizados
        </div>
    </div>

    <!-- Stats globales -->
    <div class="global-stats">
        <div class="stat-card">
            <div class="stat-number" style="color:#0a84ff;">{total_devices}</div>
            <div class="stat-label">Dispositivos</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#ff2d55;">{critical}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#ff6b35;">{high}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#ffd60a;">{medium}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#30d158;">{low}</div>
            <div class="stat-label">Low</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#aeaeb2;">{len(all_vulns)}</div>
            <div class="stat-label">Total Vulns</div>
        </div>
    </div>

    <!-- Device cards -->
    <div class="devices-container">
        {device_cards}
    </div>

    <div class="footer">
        Generado por <strong>BlueStrike v1.0</strong> — Autor: <strong>Apo1o13</strong><br>
        {now} — Solo para uso en entornos autorizados
    </div>

</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    return output_file
