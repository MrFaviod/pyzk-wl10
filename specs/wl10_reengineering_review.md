# WL10 / AK3750 Reverse-Engineering Review — ADVERSARIAL REVISION v2

**Branch**: `reengineering` (from master @ e19b1cd)
**Date**: 2026-08-12 (v2 — adversarial pass over v1 findings)
**Scope**: `pyzk_wl10/` — fork of fananimi/pyzk, WL10/AK3750 TCP support (~3700 LOC, 115 offline tests)
**Method**: static review + 115 offline tests + read-only live checks (test devices; NOT vpn-device) + **adversarial re-testing of every v1 claim** + external research (fananimi/pyzk issues, ZK protocol docs).

> **What changed vs v1**: severity corrections (BUG-4 downgraded, fallback de get_attendance descartado como bug), 3 new findings (BUG-5 `next_uid` no actualizado → sobrescribe Admin; BUG-6 attendance uid=0; M4 linking records `NN-`), y re-clasificación de "nombres desaparecidos" como limitación del modelo de datos.

---

## 1. Resumen ejecutivo

La ruta de red WL10 es sólida (drenaje ACK-terminado, escalada MSS, retries, gates de completitud — todos verificados). Los 3 dispositivos leen correctamente. **Ninguna escritura se realizó.**

El análisis adversarial de v1 **confirma 3 bugs críticos reales** (corrupción de `user_id`, `struct.error` en escritura, truncamiento de nombres), **corrige la severidad de 2 hallazgos** (dedup de flag: teórico sin evidencia de campo; fallback de `get_attendance`: correcto, no bug), y **descubre 3 hallazgos nuevos**:

| # | Hallazgo | Severidad v2 | vs v1 |
|---|----------|--------------|-------|
| BUG-1 | `_wl10_scan_user_id` corrompe badges alfanuméricos | **CRÍTICO** | = |
| BUG-2 | `wl10_set_user` sin validar uid/card → `struct.error` a media operación | **CRÍTICO** | = |
| BUG-3 | Nombre truncado a 24 bytes corta multibyte (60% de usuarios del test-device) | **ALTO** | = |
| BUG-4 | Dedup de marcaciones ignora `flag` | **MEDIO** (bajado) | ALTO → MEDIO |
| **BUG-5 (NUEVO)** | `next_uid` NO se actualiza tras `wl10_get_users()` → `wl10_set_user(uid=None)` **sobrescribe al Admin (uid=1)** | **CRÍTICO** | — |
| **BUG-6 (NUEVO)** | Attendance con `uid=0` (usuario borrado) se parsea como válido | MEDIO | — |
| RISK-1 | `set_user`/`delete_user` nativos NO despachan a WL10 | **ALTO** | = |
| RISK-2 | Auto-incremento de badge colisiona con reales | MEDIO | = |
| **M4 (NUEVO)** | Linking records (priv=49) → `NN-<badge>` — limitación del modelo, no bug | INFORMATIVO | — |

---

## 2. Hallazgos CRÍTICOS

### BUG-1 [CRÍTICO] `_wl10_scan_user_id` corrompe badges alfanuméricos — CONFIRMADO y AGRAVADO

**Ubicación**: `pyzk_wl10/zk/base.py` L1309-1312 + L1325-1347
**Condición de disparo**: `if not name or (user_id and not user_id.isdigit())` — se activa para CUALQUIER badge no numérico, no solo linking records.

**Evidencia reproducible**:
```
name='Juan 123', user_id='AB12'  →  decoded user_id: '123'   (debería ser 'AB12')
name='Calificacion 4567 buena', user_id='XY' → user_id: '4567'
```

**Contexto real (v2)**: el test-device contiene linking records reales (uid=3, badge=101, `priv=49`, sin nombre → `NN-101`). Para esos, el scan es el ÚNICO camino y funciona. **El bug es el caso intermedio**: badge alfanumérico + nombre con dígitos, o badge alfanumérico puro.

**Impacto**: badges equivocados → marcaciones mal atribuidas; `wl10_delete_user(user_id=...)` borraría el usuario equivocado.

**Fix**: restringir el fallback al caso `not name` (linking puro) o escanear solo offsets secundarios documentados. Test: badge alfanumérico + nombre con dígitos.

---

### BUG-2 [CRÍTICO] `wl10_set_user` sin validación de rangos → `struct.error` a media operación

**Ubicación**: `pyzk_wl10/zk/base.py` L1537-1548
**Evidencia reproducible**:
```
wl10_set_user(uid=70000, ...) → struct.error: 'H' format requires 0 <= number <= 65535
wl10_set_user(card=2**40, ...) → struct.error: 'I' format requires 0 <= number <= 4294967295
```
El error ocurre DESPUÉS de `_wl10_refresh_data()` (L1554) — el dispositivo queda en estado intermedio y el caller no sabe qué falló.

**Fix**: validar `0 <= uid <= 1000` y `0 <= card <= 2**32-1` ANTES de tocar el socket.

---

### BUG-3 [ALTO] Truncamiento de nombre a 24 bytes corta multibyte — CONFIRMADO EN PRODUCCIÓN

**Ubicación**: `pyzk_wl10/zk/base.py` L1537
**Evidencia reproducible**:
```
name = 'A'*23 + 'é'  →  name_pad = b'...AAA\xc3'  (0xC3 suelto)
read-back errors='ignore' → 'AAA...' (la é desapareció)
```

**Evidencia de campo (v2)**: del test-device, **23 de 38 usuarios (60%)** tienen nombres cortados a 22-23 caracteres visibles:
- `'Amarilla Dominguez, Arn'` (23) — falta el final
- `'Schmitke Reinhard ,Egar'` (23) — la 'd' de Edgar perdida

**Impacto**: el límite de 24 bytes del campo name es REAL y ya degrada datos en producción. El corte a mitad de multibyte agrega corrupción silenciosa.

**Fix**: truncar por carácter (no byte) antes de encodear. Test: 23 ASCII + é.

---

### BUG-5 [CRÍTICO — NUEVO] `wl10_get_users()` NO actualiza `next_uid` → `wl10_set_user(uid=None)` SOBRESCRIBE AL ADMIN

**Ubicación**: `pyzk_wl10/zk/base.py` L1414-1420 (`wl10_get_users`) vs L1918-1928 (`get_users` nativo)
**Hallazgo adversarial**: el `get_users()` nativo **sí** actualiza `next_uid = max_uid + 1` (con chequeo de colisión de badge); `_wl10_get_users()` **no toca `next_uid` en absoluto**.

**Evidencia reproducible**:
```
wl10_get_users() sobre tabla con uids [1,2,3]  →  next_uid queda en 1  (NO 4)
wl10_set_user(uid=None)  →  escribe uid=1  →  ¡SOBRESCRIBE AL ADMIN!
```

**Impacto**: es la causa más plausible de "usuario que desaparece" — el flujo natural "leer usuarios → crear uno nuevo sin uid" reemplaza al primer usuario de la tabla (típicamente Admin). **Ningún test cubre esta secuencia.**

**Fix**: `wl10_get_users()` debe replicar la lógica del nativo (`next_uid = max(uid)+1` con chequeo de colisión), o `wl10_set_user(uid=None)` debe exigir badge explícito y rechazar uid=None.

---

### BUG-6 [MEDIO — NUEVO] Attendance con `uid=0` se parsea como válido

**Ubicación**: `pyzk_wl10/zk/base.py` L1369-1406
**Evidencia reproducible**:
```
record uid=0, user_id='0', ts válido → SE PARSEA (Attendance con uid=0)
```
Los dispositivos emiten records con uid=0 cuando el usuario fue borrado pero la marcación permanece. No hay filtro.

**Impacto**: marcaciones fantasma atribuidas a "nadie". Contamina reportes.

**Fix**: filtrar `uid == 0` o marcarlos como huérfanos. Test: record uid=0 → excluido.

---

## 3. Hallazgos ALTO / MEDIO

### RISK-1 [ALTO] `set_user`/`delete_user` nativos NO despachan a WL10

**Evidencia** (inspección):
```
set_user:    dispatches on self.wl10 = False  ; usa __send_command
delete_user: dispatches on self.wl10 = False  ; usa __send_command
get_users:   dispatches on self.wl10 = True   ; get_attendance: True
```
**Combinado con BUG-5**: si un flujo llama `set_user()` (nativo) en modo wl10, además de no funcionar, podría dejar estados inconsistentes.

**Fix**: despachar a `wl10_*` cuando `self.wl10` (o levantar error claro).

### BUG-4 [MEDIO — BAJADO] Dedup de marcaciones ignora `flag`

**Re-evaluación adversarial**: el byte `flag` NO es visible en los dumps (check_device solo imprime status). El colapso requiere mismo (user_id, ts, status) con flag DISTINTO en el mismo segundo — **teórico, no observable en datos reales**. Los tests cubren el caso real (duplicados exactos).

**Fix**: incluir `flag` en la clave de dedup es barato. Test: 2 records idénticos salvo flag → ambos conservados.

### RISK-2 [MEDIO] Auto-incremento de badge colisiona con reales

`wl10_set_user(uid=None)` asigna `user_id=str(next_uid)` = "1", "2"… que colisionan con badges reales (los reales usan existing-badge-range, pero "2" es legal). Se agrava con BUG-5 (next_uid incorrecto).

### M1 [BAJA] Wrap de `reply_id` en `__create_header`
L163-171: `if reply_id >= USHRT_MAX: reply_id -= USHRT_MAX` — en el borde exacto 65535 queda 0. No observado en práctica.

### M2 [BAJA] `get_attendance` nativo L2425 usa `.decode(errors='ignore')` sin encoding

### M3 [BAJA] `delete_user` nativo L1812 usa `pack('h')` (con signo) — confirmado por pyzk PR #261

### M4 [INFORMATIVO — NUEVO] Linking records (priv=49) → `NN-<badge>`
El dump real del test-device muestra 2 usuarios `NN-101`, `NN-102` con `priv=49`. **No es un bug**: son records de huella sin user completo (el nombre nunca existió en el device). Es una limitación del modelo de datos: la librería no puede mostrar un nombre que el dispositivo no tiene. Documentar para el usuario final: "NN-" = solo huella registrada.

---

## 4. Lo que el análisis adversarial DESCARTÓ (v1 estaba mal)

| Hallazgo v1 | Veredicto v2 | Por qué |
|-------------|--------------|---------|
| Fallback de `get_attendance()` deja `wl10=False` permanente | **FALSO — correcto** | Verificado: todas las rutas restauran `saved_wl10` (L2432, L2366, L2370), incluidas las excepciones |
| BUG-4 = ALTO | **MEDIO** | El flag no es observable en datos reales; caso teórico |
| Layout 22B "no corroborado" = mayor riesgo | **Matizado** | El layout ES lo que la firmware emite (validado en 3 dispositivos); drenaje + gates mitigan truncamiento |

---

## 5. Investigación externa (fuentes — librarian)

1. **Cabecera ZK TCP**: wrapper `0x5050 0x7D82` (20560/32130) + 4B longitud + (cmd u16, checksum u16, session u16, reply u16, data). Checksum LE word-sum mod 65535 ~NOT. Session = contador de segundos asignado en connect; reply se incrementa tras cada respuesta. [adriancitu/zkteco, pyzk docs]
2. **Encoding**: dispositivos de mercado chino almacenan GBK; pyzk decodifica UTF-8 → garbage (issue #250). `User.encoding='UTF-8'` default con `errors='ignore'` descarta silenciosamente (issue #190: nombres persas).
3. **Layout 72B user**: confirmado por spec pública (offsets coinciden). **Layout 22B attendance: sin corroboración pública** — pyzk usa 8/16/40/49B. El 22B es específico de esta firmware (validado empíricamente en 3 dispositivos).
4. **pyzk bugs conocidos**: #170 (Ver 6.60 → get_attendance []), #41 (AK3750WIFI_TFT lee vacío), #128 (ACK_ERROR 2001 en set_user), #219/PR#261 (delete_user signed short), #244/PR#242 (day out of range), #250/#190 (encoding).
5. **Constantes**: todas confirmadas (8, 9, 13, 18, 1004, 1013, 1500-1503, 2000, 2001, 2005; magic 20560/32130).
6. **CMD_RESTART/REFRESHDATA**: RESTART no acusado, cierra conexión, sin pérdida documentada. **REFRESHDATA requerido tras escrituras** — sin él, cambios no toman efecto → "usuario que no aparece".
7. **Lectura por chunks**: patrón canónico = `CMD_DATA_WRRQ` + buffer/read chunks; bulk único del WL10 es no estándar (mitigado por drenaje resiliente).

---

## 6. Pruebas ejecutadas

| Prueba | Resultado |
|--------|-----------|
| `python3 -m pytest pyzk_wl10/zk/tests/ -q` | **115 passed** (4.74s) |
| `check_device.py` en test-device (read-only) | OK — lecturas correctas |
| Repro BUG-1 (badge alfanumérico + dígitos en nombre) | CONFIRMADO |
| Repro BUG-2 (uid 70000 / card 2^40) | CONFIRMADO |
| Repro BUG-3 (23 ASCII + é; 60% usuarios test-device truncados) | CONFIRMADO |
| Repro BUG-5 (get_users no actualiza next_uid → sobrescribe Admin) | **CONFIRMADO (nuevo)** |
| Repro BUG-6 (attendance uid=0) | CONFIRMADO (nuevo) |
| Repro BUG-4 (flag distinto mismo segundo) | CONFIRMADO (teórico) |
| Fallback get_attendance (flag wl10 restaurado) | CORRECTO (v1 se equivocó) |
| Gates de completitud (bulk truncado 17B, 8B) | CORRECTOS — protegen |

**vpn-device NO tocado. Ninguna escritura realizada.**

---

## 7. Recomendaciones (prioridad corregida)

1. **[CRÍTICO] BUG-5**: `wl10_get_users()` debe actualizar `next_uid`/`next_user_id` (paridad con nativo) — test: leer tabla [1,2,3] → `wl10_set_user(uid=None)` → escribe uid 4, no 1.
2. **[CRÍTICO] BUG-1**: restringir scan a linking records; test badge alfanumérico.
3. **[CRÍTICO] BUG-2**: validar rangos uid/card antes de socket; test.
4. **[ALTO] BUG-3**: truncar nombre por carácter; test 23 ASCII + é.
5. **[ALTO] RISK-1**: despachar set_user/delete_user/refresh_data/restart a wl10_* cuando `self.wl10`; test.
6. **[MEDIO] BUG-6**: filtrar uid=0 en attendance; test.
7. **[MEDIO] BUG-4**: incluir flag en dedup; test.
8. **[MEDIO] RISK-2**: exigir badge explícito en wl10_set_user(uid=None).
9. **[BAJA] M1/M2/M3**: wrap reply_id, encoding consistente, pack('<H').
10. **[DOC] M4**: documentar que NN- = linking record (solo huella), no error.

**Proceso**: TDD estricto (test rojo → fix → suite 115+green), verificación read-only en test devices, NUNCA en vpn-device sin instrucción.

---

## 8. Incertidumbres restantes

- **Layout 22B sin corroboración pública** — mitigado por validación empírica en 3 dispositivos y gates de completitud. Riesgo residual: firmware variants AK3750 podrían diferir en flag/reserved.
- **BUG-4**: impacto real desconocido (flag no visible en dumps); fix preventivo barato.
- **`ruff` no ejecutable** en este entorno (binario ausente); suite pytest es el gate.
- El comportamiento del device ante `set_user()` nativo (RISK-1) no fue probado en vivo (requeriría escritura — prohibido).

---

# ANEXO v3 — INVESTIGACIÓN NN-xx (sobreescritura de nombres)

## El misterio resuelto

Los registros `NN-<scan>` observados en un dispositivo **no son usuarios con el nombre borrado**. Son **slots de plantillas de huella** que la librería interpretaba erróneamente como usuarios.

### Evidencia de dispositivo (lectura read-only)

La lectura identificó slots intercalados con `priv=0x31` que contienen múltiples plantillas de huella. Los detalles crudos y cualquier identificador extraído se conservaron únicamente en el workspace SDD ignorado por Git.

### Por qué la librería produce `NN-<scan>`

1. `_wl10_scan_user_id` escanea los 72 bytes buscando runs de 3-5 dígitos.
2. En los bytes de la plantilla encuentra un run numérico.
3. `name` está vacío (es template data) y la librería genera el placeholder `NN-<scan>`.
4. El slot de plantilla aparece como un usuario falso.

**Consecuencia**: el mapa de usuarios (`_wl10_build_users_map`) puede incluir un placeholder falso. Una eliminación o escritura dirigida a ese registro podría destruir plantillas; por eso los slots `priv=0x31` deben quedar fuera de las operaciones de usuario.

### Por qué se informó que se "sobrescribieron nombres"

**CMD_USER_WRQ (8) es un UPSERT** — verificado externamente: "used to modify info of existing users, if the user doesn't exist, then it will be created... overwrite the previous user data" [adrobinoga/zk-protocol data-user.md; corroborado por pyzk #128].

En el modelo estándar ZK, los templates viven en una tabla separada gestionada por `CMD_DATA_WRRQ`. **El modelo AK3750 con slots interleaved (`priv=0x31`) NO está documentado en ninguna fuente pública** — es RE local únicamente. El comportamiento observado muestra que los slots de plantillas están intercalados con records de usuario reales en la MISMA tabla de 72B.

- Una escritura `wl10_set_user(...)` sobre un slot de plantilla podría sobrescribirlo con datos de usuario y perder sus plantillas.
- El siguiente read podría mostrar el nombre nuevo o vacío, lo que explica la impresión de que el nombre fue reemplazado.

### El agravante BUG-5 (next_uid no actualizado)

`wl10_get_users()` no actualiza `next_uid` (queda 1). El flujo "leer → crear usuario sin uid" escribe en el primer slot y, si el operador fuerza un uid, puede aterrizar en un slot de plantilla.

### Recomendación específica de slots de plantilla (nueva, prioridad #1)

**Los slots `priv=49` (`0x31`) deben ser DETECTADOS y EXCLUIDOS del parseo de usuarios** (o marcados explícitamente como `TemplateSlot`), nunca presentados como `NN-<scan>`. La plantilla se identifica por `priv == 0x31` o el campo nombre con bytes no-texto + ausencia de user record real. Esto elimina:
- los usuarios falsos `NN-<scan>` de la tabla,
- los badges fantasma derivados del parser,
- el riesgo de `wl10_delete_user`/`wl10_set_user` sobre slots de plantilla.

**Además**: `wl10_set_user` debe (a) validar que el uid destino NO sea un slot de plantilla (chequeo read-only previo), y (b) NUNCA permitir `uid=None` con auto-incremento ciego (BUG-5).

### Confirmación externa (librarian, 6.5 min)

| Tema | Hallazgo | Fuente | Confianza |
|------|----------|--------|-----------|
| Modelo estándar | Templates en tabla SEPARADA (uid + finger-index), no interleaved | adrobinoga/zk-protocol, pyzk, zkteco-php | VERIFIED (3 impl.) |
| priv=0x31 | No documentado como privilege en ninguna fuente | búsqueda exhaustiva | NO HAY FUENTE — RE local |
| CMD_USER_WRQ | **UPSERT** — sobrescribe el user existente | adrobinoga/zk-protocol data-user.md, pyzk #128 | VERIFIED |
| save_user_template | Escribe user+templates JUNTOS (1 buffer: head III + upack + table + fpack) | pyzk L1725-1769, msaied/zkteco-php TemplateEncoder | VERIFIED |
| wl10_set_user | Solo CMD_USER_WRQ 72B, sin templates | código local | VERIFIED |
| Reportes de huellas perdidas | Ninguno público para AK3750/WL10 | búsqueda | SIN HALLAZGOS |

**Síntesis externa**: el modelo interleaved (templates en slots priv=0x31) es **RE local únicamente**; las fuentes públicas afirman lo contrario (tablas separadas). Los dos desenlaces posibles (sobrescritura destructiva o rechazo ACK_ERROR) son consistentes con la evidencia pública — solo una prueba empírica con escritura los distingue (prohibida en esta fase).

---

# ADDENDUM — 2026-09-10 UTC — TARGET <DEVICE_IP>

This dated addendum records the recovered Task 6 characterization without
rewriting the historical v2/v3 findings above. It contains no raw payload
bytes, attendance rows, badges, serials, MAC addresses, or raw capture names.

## Result

- Target: `<DEVICE_IP>`.
- The default read-only profile started at 01:55:22Z, was interrupted by the
  wrapper timeout at 01:57:22Z, and left five partial captures without a
  summary. Its prior hashes and bin lengths remain unchanged. No mutation was
  observed.
- The recovered VPN profile (`tcp-maxseg=1200`, `gap-timeout=3`) ran from
  04:57:04Z to 04:57:12Z, exited 0, and produced a summary. Its outcome was
  `ok`; `connect`, `get_device_name`, `get_platform`, and
  `get_firmware_version` each reported status `ok`.
- VPN users: status `ok`, `complete=true`, count `8`; parser declared /
  candidate / accepted = `8 / 8 / 8`.
- VPN attendance: status `ok`, `complete=true`, count `48`; parser declared /
  candidate / accepted = `813 / 813 / 48`.
- `template_uids` was present and empty (`[]`). No mutation was observed.
- Transport capture was unavailable: `tcpdump` could not run without
  `CAP_NET_RAW`.

## Sanitized capture facts

Only lengths, SHA-256 digests, and ACK metadata are recorded here. The two
588 B command-9 captures have the same SHA-256 and are deduplicated by SHA for
capture counting; this does not infer any totals beyond the sanitized summary.

| Capture ordinal | Command | Length | SHA-256 | ACK command | Reply id |
|---:|---:|---:|---|---:|---:|
| 1 | 9 | 588 B | `005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6` | 2000 | 31 |
| 2 | 9 | 588 B | `005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6` | 2000 | 32 |
| 3 | 13 | 17898 B | `a390aaf026069ae3e93a1c91ba95fddebd61d7f4bc673b67d6aa33bb0e7fcc54` | 2000 | 34 |

The VPN summary SHA-256 is
`9793f7973370047e321ca0e45096e86a95f4027c4d2fef92e4445ea17060995d`.
The default profile's five partial bins remain recorded exactly as captured:

| Capture ordinal | Length | SHA-256 |
|---:|---:|---|
| 1 | 588 B | `005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6` |
| 2 | 588 B | `005f057892da47849a982647215065a25cc1fbf1727377e7abd48298f04d8dc6` |
| 3 | 8 B | `b6f59fbbfb03ee482a941683ab267d59ecb46ee668a1fa64ecd445b946e2d4f5` |
| 4 | 0 B | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 5 | 0 B | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Safety gate

Gate assessment: identity **PASS**; complete users and attendance reads
**PASS**; parser **PASS**; baseline consistency **PASS within the VPN profile**;
template UID set **FAIL** because `template_uids` was empty. Therefore the
overall Task 6 gate is **FAILED**, and Task 7's isolated one-write operation
remains blocked. No write, delete, reboot, or cleanup was attempted.
