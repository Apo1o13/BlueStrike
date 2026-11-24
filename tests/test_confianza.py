"""Regresion: los hallazgos inferidos por version NO deben presentarse como
vulnerabilidades confirmadas.

Reproduce la entrada sintetica usada en la revision (LMP 9 + OS Linux estimado):
BlueBorne / KNOB / BIAS deben salir como 'candidato' (inferencia por version),
nunca como confirmados. Un servicio realmente anunciado sale como 'observado'.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from analyzer import VulnerabilityAnalyzer  # noqa: E402


def _check(report):
    return VulnerabilityAnalyzer()._check_vulnerabilities(report)


BASE = {
    "type": "Classic",
    "device_info": {},
    "services": [],
    "vulnerabilities": [],
    "_gatt_accessible": False,
    "_l2cap_reachable": False,
}


def test_blueborne_knob_bias_son_candidatos():
    report = {**BASE, "device_info": {"_lmp_version_num": 9, "OS estimado": "Linux"}}
    found = _check(report)
    nombres = {f["name"]: f for f in found}
    assert any("BlueBorne" in n for n in nombres), "deberia matchear por version/OS"
    assert any("KNOB" in n for n in nombres)
    assert any("BIAS" in n for n in nombres)
    # Lo central: todo lo inferido por version es 'candidato' y NO verificado.
    for f in found:
        assert f["confidence"] == "candidato", f"{f['name']} salio como {f['confidence']}"
        assert f["verified"] is False


def test_servicio_real_es_observado():
    report = {**BASE, "services": [{"name": "OBEX"}]}
    found = {f["name"]: f for f in _check(report)}
    snarf = next((f for n, f in found.items() if "BlueSnarf" in n), None)
    assert snarf is not None, "un servicio OBEX anunciado deberia detectarse"
    assert snarf["confidence"] == "observado"
    assert snarf["verified"] is False


def test_version_desconocida_no_inventa_candidatos():
    # LMP desconocido (99) y sin servicios: no debe inferir KNOB/BIAS/BlueBorne.
    report = {**BASE, "device_info": {"_lmp_version_num": 99, "OS estimado": ""}}
    found = _check(report)
    assert not any(f["confidence"] == "candidato" for f in found), \
        "sin version conocida no se deben inferir vulnerabilidades"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
