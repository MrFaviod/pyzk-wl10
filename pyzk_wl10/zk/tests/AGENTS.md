# pyzk_wl10/zk/tests — suite offline

Estas pruebas simulan el dispositivo; nunca deben abrir sockets reales.

## Reglas

- Ejecutar pytest con la ruta explícita. Un `pytest` desnudo desde la raíz también puede recolectar scripts que tocan hardware.
- Reutilizar fixtures de `conftest.py` y builders binarios de `helpers.py`.
- Para sesión/ACK, comprobar los internos name-mangled relevantes.
- Nuevos casos de parsing deben usar bytes o fixtures representativos.
- Los tests live-device permanecen como scripts separados en la raíz y requieren autorización.

## Verificación

```bash
python3 -m pytest pyzk_wl10/zk/tests/ --collect-only -q
python3 -m pytest pyzk_wl10/zk/tests/ -q
```
