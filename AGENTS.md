# pyzk_wl10 — fork WL10/AK3750

Fork stdlib-only de pyzk con lecturas y mutaciones WL10 por TCP. Antes de tocar el protocolo, leer `specs/wl10_reengineering_review.md`; es evidencia histórica, no certificación live.

## Fuentes de verdad

- `pyzk_wl10/zk/base.py`: sesión y protocolo.
- `pyzk_wl10/zk/const.py`: comandos y tamaños.
- `pyzk_wl10/zk/tests/`: suite offline.
- `README.md`: uso y protocolo documentado.

## Reglas de seguridad

- Nunca ejecutar scripts de escritura, borrado, reboot o limpieza contra hardware sin autorización explícita.
- Para pruebas offline usar siempre la ruta `pyzk_wl10/zk/tests/`; un `pytest` desnudo puede recolectar scripts live-device.
- Lecturas bulk usan el raw TCP path. Preservar sincronización de `reply_id`; no tomar `session_id` de paquetes bulk.
- Mutaciones: preflight, `REFRESHDATA`, una sola operación y sin retry/cleanup automático si el resultado es incierto.
- Uid y badge deben ser explícitos; proteger slots de templates y fallar cerrado ante lecturas incompletas.
- No commitear capturas ni evidencia privada de dispositivos.

## Estado live

Lectura por VPN fue parcial y no certificada: el gate de templates quedó inconcluso. Escritura live continúa bloqueada hasta repetir y aprobar todos los gates.

## Verificación offline

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q
python3 -m pytest pyzk_wl10/zk/tests/ -q
```
