# pyzk_wl10/zk — protocolo WL10

Este paquete contiene la sesión y el protocolo binario. El contexto operativo y los gates de hardware están en `../../../AGENTS.md`.

## Invariantes

- WL10 usa TCP (`force_udp=False`, `wl10=True`).
- Sincronizar `__reply_id` desde cada ACK de escritura y lectura bulk.
- Nunca actualizar `__session_id` desde paquetes bulk.
- Registros de usuario: 72 bytes. Marcaciones: 22 bytes.
- Escrituras requieren uid y badge explícitos; validar tamaño del payload y slots de templates antes de enviar.
- No cambiar el read path ni añadir retries de mutaciones sin tests de protocolo y revisión del riesgo de duplicación.
- `refresh_data` forma parte de la secuencia de mutación, no sustituye el preflight.

## Verificación

Desde la raíz del repo:

```bash
python3 -m pytest pyzk_wl10/zk/tests/ -q
```
