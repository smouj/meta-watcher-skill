---
name: meta-watcher
description: AI-powered security monitoring and automated threat response system
version: 2.4.1
author: Security Team
tags:
  - security
  - ai
  - automation
  - monitoring
  - threat-detection
requires:
  - python3.9+
  - openai-cli
  - jq
  - curl
  - sqlite3
conflicts:
  - naive-watcher
  - legacy-monitor
inputs:
  - config: Path to YAML configuration file (default: /etc/meta-watcher/config.yaml)
  - api_key: OpenAI API key for threat analysis
  - db_path: SQLite database for threat history (default: /var/lib/meta-watcher/threats.db)
outputs:
  - alerts: JSON formatted security alerts to stdout
  - logs: Structured logs to /var/log/meta-watcher/
  - actions: Automated remediation actions executed
---

# Meta Watcher

Sistema de monitorización de seguridad con IA y respuesta automatizada a amenazas que analiza continuamente registros del sistema, tráfico de red y comportamiento de aplicaciones para detectar y responder a incidentes de seguridad en tiempo real.

## Propósito

Meta Watcher cumple tres funciones críticas de seguridad:

1. **Detección de Amenazas en Tiempo Real**: Analiza syslog, registros de aplicaciones y paquetes de red utilizando IA para identificar anomalías, ataques de fuerza bruta, intentos de inyección SQL y patrones de escalada de privilegios que las herramientas tradicionales basadas en firmas no detectan.

2. **Respuesta Automatizada a Incidentes**: Ejecuta libros de estrategias de respuesta preaprobados cuando se confirman amenazas, incluyendo bloqueo de IPs con iptables/nftables, terminación de procesos, cuarentena de archivos comprometidos y alertas a Slack/Teams/PagerDuty.

3. **Monitorización de Cumplimiento**: Valida continuamente configuraciones del sistema contra benchmarks CIS, PCI-DSS, HIPAA y políticas de seguridad personalizadas, generando informes listos para auditoría.

### Casos de Uso Reales

```
# Detectar y bloquear ataques de fuerza bruta SSH en 60 segundos
meta-watcher monitor --source=journalctl -u sshd --patterns=auth,failed --ai-threshold=0.85 --auto-block

# Escanear registros de aplicaciones para vulnerabilidades OWASP Top 10
meta-watcher analyze /var/log/nginx/access.log --ruleset=owasp-top10 --mode=strict --report=html

# Aplicar cumplimiento PCI-DSS en servidores de procesamiento de pagos
meta-watcher compliance check --standard=pci-dss --target=10.0.1.0/24 --auto-fix --dry-run

# Monitorizar registros de consultas de base de datos para inyección SQL
meta-watcher tail /var/log/postgresql/query.log --detect=sqli --quarantine=true --alert-security-team
```

## Alcance

Meta Watcher opera con estos comandos principales:

### Comandos Principales
- `meta-watcher monitor [SOURCE]` - Iniciar monitorización continua
- `meta-watcher analyze [FILE/PATH]` - Análisis único de registros o archivos
- `meta-watcher tail [LOG_FILE]` - Transmisión en vivo de registros con análisis IA
- `meta-watcher compliance [CHECK/REPORT/FIX]` - Operaciones de frameworks de cumplimiento
- `meta-watcher respond [ALERT_ID]` - Activación manual o anulación de respuestas automatizadas
- `meta-watcher status` - Mostrar estado actual de monitorización y nivel de amenaza
- `meta-watcher rollback [ACTION_ID]` - Deshacer una acción automatizada específica
- `meta-watcher learn [PATTERN]` - Entrenar el modelo IA con patrones de amenaza personalizados
- `meta-watcher export [FORMAT]` - Exportar datos de inteligencia de amenazas

### Banderas Comunes
- `--source=SYSTEM` - Monitorizar journal systemd, logs Docker o archivo
- `--ruleset=NAME` - Usar conjunto de reglas específico (owasp, cis, custom, etc.)
- `--ai-threshold=N` - Umbral de confianza 0.0-1.0 para detección IA
- `--auto-block/--no-auto-block` - Activar/desactivar bloqueo automático
- `--quarantine=DIR` - Poner en cuarentena archivos sospechosos al directorio
- `--alert-channel=WEBHOOK` - Enviar alertas a Slack/Teams/PagerDuty
- `--dry-run` - Mostrar qué se haría sin ejecutar
- `--verbose` - Salida de depuración con razonamiento de IA
- `--config=FILE` - Anular configuración por defecto

## Proceso de Trabajo Detallado

### 1. Fase de Inicialización
```bash
# Cargar configuración desde YAML
meta-watcher lee /etc/meta-watcher/config.yaml o $META_WATCHER_CONFIG

# Validar dependencias
- Busca clave API OpenAI en entorno o configuración
- Verifica esquema de base de datos (crea si falta)
- Carga modelo IA (local o remoto)
- Inicializa filtros de red (conjunto de reglas iptables/nftables)
- Establece logging a /var/log/meta-watcher/

# Secuencia de inicio
1. Conectar a SQLite en $META_WATCHER_DB o por defecto
2. Cargar feeds de inteligencia de amenazas desde $META_WATCHER_INTEL
3. Calentar modelo IA con patrones de base
4. Iniciar hilos de monitorización con límites de recursos (CPU < 30%, Memoria < 500MB)
```

### 2. Recopilación e Ingesta de Datos
```bash
# Para monitorización basada en archivos
meta-watcher usa inotifywait para detectar cambios en archivos
- Lee nuevas líneas de log incrementalmente
- Temporiza y deduplica entradas

# Para journal systemd
journalctl -u SERVICE --since "1 min ago" --output=json

# Para monitorización de red (opcional)
tcpdump -i eth0 -w - -s 0 'tcp port 80 or 443' 2>/dev/null | meta-watcher parse-pcap

# Normalización
Todas las entradas convertidas a formato JSON canónico:
{
  "timestamp": "2025-03-04T14:32:10Z",
  "source": "nginx/access.log",
  "severity": "high",
  "message": "192.168.1.100 - - [04/Mar/2025:14:32:10 +0000] \"POST /admin.php HTTP/1.1\" 200 1234",
  "metadata": {...}
}
```

### 3. Análisis de Amenazas con IA
```bash
# Cada evento normalizado enviado a API OpenAI (si está habilitada)
POST https://api.openai.com/v1/chat/completions
{
  "model": "gpt-4-turbo-preview",
  "messages": [
    {"role": "system", "content": "You are a security analyst. Classify this log entry as: SAFE, SUSPICIOUS, MALICIOUS. Provide confidence 0.0-1.0 and reasoning."},
    {"role": "user", "content": "LOG: <normalized_entry>"}
  ],
  "temperature": 0.1,
  "max_tokens": 100
}

# Respaldo a motor de reglas local si IA no disponible
-
- Coincidencia de patrones regex contra /etc/meta-watcher/rules/*.yaml
- Detección de anomalías estadística usando EWMA
- Correlación con inteligencia de amenazas conocida

# Matriz de decisiones
if confidence >= ai-threshold AND classification == MALICIOUS:
  - Crear registro de alerta en base de datos
  - Ejecutar libro de respuestas basado en tipo de amenaza
  - Notificar canales de alerta
elif confidence >= ai-threshold*0.8 AND classification == SUSPICIOUS:
  - Crear alerta de baja prioridad
  - Aumentar sensibilidad de monitorización para fuente
else:
  - Registrar como informativo, sin acción
```

### 4. Ejecución de Libro de Respuestas
```bash
# Para fuerza bruta SSH (threat_type: ssh_bruteforce)
1. Extraer IP atacante de la entrada de log
2. Verificar si IP ya está en lista de bloqueo: SELECT * FROM blocks WHERE ip = '192.168.1.100'
3. Si no bloqueada:
   - iptables -I INPUT 1 -s 192.168.1.100 -j DROP
   - Registrar en tabla blocks con timestamp, razón, expires_at (24h por defecto)
   - Enviar alerta Slack: "Blocked IP 192.168.1.100 for SSH brute force"
   - Registrar acción: INSERT INTO actions (type, target, executed_by, created_at) VALUES ('iptables_block', '192.168.1.100', 'meta-watcher', NOW())

# Para cuarentena de archivos (threat_type: malware, ransomware)
1. Calcular SHA256 de archivo sospechoso
2. Consultar API VirusTotal para hash conocido
3. Si malicioso o alta sospecha:
   - mv /path/to/file /var/quarantine/$(date +%s)_$(basename file)
   - Establecer flag inmutable: chattr +i /var/quarantine/...
   - Crear registro en base de datos con ruta original, hash, quarantine_path

# Para violaciones de cumplimiento
1. Identificar control que falla
2. Aplicar corrección automática si disponible (ej. chmod 600 en archivo sensible)
3. Generar ticket de remediación vía API a Jira/ServiceNow si intervención manual necesaria
```

### 5. Operación Continua
```bash
# Estructura del bucle principal
while running:
  event = read_next_event()  # bloqueante con timeout
  if event:
    analysis = ai_analyze(event)
    if analysis.threat:
      execute_response(analysis)
  
  # Comprobación de salud cada 60s
  if time() % 60 == 0:
    - Verificar conectividad de base de datos
    - Revisar espacio en disco para logs (>10GB advertencia, >20GB error)
    - Validar cuota de API IA restante (>1000 requests/day threshold)
    - Asegurar canales de alerta accesibles (probar webhook si 5min silencio)
```

## Reglas de Oro

Estas reglas aseguran operación segura y efectiva:

1. **Nunca eliminar automáticamente datos de producción sin consentimiento explícito**
   - Cuarentena es acción por defecto para amenazas de archivos, no eliminación
   - Requiere bandera `--force-delete` para eliminación permanente
   - Mantener historial de auditoría inmutable en base de datos para siempre

2. **Limitar velocidad de todas las acciones automatizadas**
   - Máximo 100 bloques de IP por hora en todos los monitores
   - Máximo 10 archivos puestos en cuarentena por minuto
   - Mínimo 1 segundo entre llamadas API a servicios externos
   - Implementar retroceso exponencial en fallos

3. **Mantener humano-en-el-bucle para sistemas críticos**
   - `--no-auto-block` por defecto en servidores de producción sin aprobación previa
   - Requerir bandera `--approved-by=TEAM` para acciones en bases de datos, sistemas de pago
   - Enviar solicitudes de aprobación obligatorias para >5 IPs bloqueadas simultáneamente

4. **Preservar cadena de evidencia**
   - Almacenar entradas de log originales sin cambios en `$META_WATCHER_EVIDENCE` (por defecto: /var/lib/meta-watcher/evidence/)
   - Calcular SHA256 de todos los archivos de evidencia antes de modificación
   - Generar informes de integridad firmados diariamente con `meta-watcher verify --integrity`

5. **Defensa en profundidad**
   - No confiar solo en IA; siempre ejecutar motor de reglas como respaldo
   - Validar todas las respuestas de IA; rechazar sugerencias fuera del alcance de acciones permitidas
   - Usar claves API separadas con permisos mínimos para cada canal de alerta
   - Cifrar base de datos con SQLCipher si se almacenan datos sensibles

6. **Protección de recursos**
   - Aplicar límites CPU/memoria vía archivo systemd service (MemoryMax=1G, CPUQuota=50%)
   - Contrapresión:暂停监控 si acumulación de cola supera 1000 eventos
   - Autocalibrar tamaño de lote basado en carga del sistema

7. **Cumplimiento obligatorio**
   - Todas las acciones deben tener periodo de retención definido en configuración
   - Generar log de auditoría compatible SOC2 para cada decisión
   - Exportar datos en formato JSONL para integración Splunk/ELK

## Ejemplos

### Ejemplo 1: Monitorizar logs SSH para fuerza bruta
**Configuración:**
```bash
cat > /etc/meta-watcher/config.yaml << 'EOF'
monitors:
  sshd:
    source: "journalctl -u sshd -o json"
    ruleset: "ssh_bruteforce"
    ai_threshold: 0.9
    auto_block: true
    block_duration: "24h"
    alert_channels:
      - type: "slack"
        webhook: "https://hooks.slack.com/services/XXX"
      - type: "pagerduty"
        routing_key: "XXXX"
EOF
export META_WATCHER_CONFIG=/etc/meta-watcher/config.yaml
export OPENAI_API_KEY="sk-..."
```

**Comando:**
```bash
meta-watcher monitor --source=sshd --verbose
```

**Salida de Ejemplo:**
```
[2025-03-04 14:32:10] INFO: Starting monitor 'sshd'
[2025-03-04 14:33:45] WARNING: Detected potential SSH brute force from 192.168.1.100 (12 failures in 60s)
[2025-03-04 14:33:46] AI Analysis: MALICIOUS (confidence: 0.96) - Pattern matches credential stuffing
[2025-03-04 14:33:47] ACTION: Blocking IP 192.168.1.100 via iptables (expires: 2025-03-05 14:33:47)
[2025-03-04 14:33:47] ALERT: Sent to Slack (#security-alerts) and PagerDuty (incident ID: INC12345)
[2025-03-04 14:33:48] EVIDENCE: Saved 15 log lines to /var/lib/meta-watcher/evidence/abc123.json
```

**Registro en Base de Datos (tabla threats):**
```json
{
  "id": "threat_abc123",
  "timestamp": "2025-03-04T14:33:45Z",
  "source": "sshd",
  "threat_type": "brute_force",
  "source_ip": "192.168.1.100",
  "confidence": 0.96,
  "ai_reasoning": "Multiple failed authentication attempts from single IP within short timeframe, typical of credential stuffing attacks.",
  "action_taken": "iptables_block",
  "action_id": "action_def456",
  "quarantined_files": null,
  "alert_sent": true,
  "evidence_hash": "sha256:3a7bd3e236..."
}
```

### Ejemplo 2: Análisis único de logs web
**Comando:**
```bash
meta-watcher analyze /var/log/nginx/access.log \
  --ruleset=owasp-top10 \
  --ai-threshold=0.8 \
  --report=html \
  --output=report.html
```

**Informe de Ejemplo (extracto HTML):**
```html
<h2>OWASP Top 10 Detection Report</h2>
<p>Analyzed 15,234 entries from 2025-03-03 to 2025-03-04</p>

<h3>Critical Threats</h3>
<ul>
  <li><strong>SQL Injection (A03:2021)</strong> - Detected 3 attempts from 10.0.0.50 at 14:15:22</li>
  <li><strong>Broken Access Control (A01:2021)</strong> - Unauthorized admin panel access from 192.168.1.200</li>
</ul>

<h3>Warnings</h3>
<ul>
  <li>Suspicious user-agent string (scanner detected) - 45 occurrences</li>
  <li>High request rate from single IP - Rate limiting recommended</li>
</ul>

<h3>AI Analysis Summary</h3>
<p>The AI detected 2 confirmed attacks with 94% average confidence. Recommend blocking 10.0.0.50 immediately.</p>
```

### Ejemplo 3: Verificación de cumplimiento con corrección automática (dry run)
**Comando:**
```bash
meta-watcher compliance check \
  --standard=cis-benchmark \
  --target=/etc/ssh/sshd_config \
  --auto-fix \
  --dry-run
```

**Salida:**
```
[DRY RUN] Compliance check for CIS Benchmark v1.2.0

Checking /etc/ssh/sshd_config:

✗ FAIL: PasswordAuthentication should be disabled (currently: yes)
  Would execute: sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  Would restart: systemctl restart sshd

✗ FAIL: PermitRootLogin should be prohibited (currently: prohibit-password)
  Would execute: sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  Would restart: systemctl restart sshd

✓ PASS: Protocol 2 is enforced

Summary: 2 violations found, 2 would be fixed. (Use --no-dry-run to apply)
```

### Ejemplo 4: Revertir acción de falso positivo
**Escenario:** IP 192.168.1.100 fue bloqueada incorrectamente debido a error en monitorización.

**Comando:**
```bash
meta-watcher rollback action_def456
```

**Salida:**
```
Rollback request for action 'action_def456' (block IP 192.168.1.100)

Verifying action... ✓
Checking if block is still active... ✓ (found in iptables)
Removing iptables rule: iptables -D INPUT -s 192.168.1.100 -j DROP
✓ Rule removed
Updating database: UPDATE actions SET rolled_back=1, rolled_back_at=NOW() WHERE id='action_def456'
✓ Database updated
Notifying alert channels: "False positive alert for IP 192.168.1.100 - block has been removed"
✓ Alert sent
Rollback completed successfully.
```

**Actualización de Base de Datos:**
```sql
UPDATE actions 
SET rolled_back = 1, 
    rolled_back_at = '2025-03-04T15:00:00Z',
    rollback_reason = 'False positive - legitimate user IP'
WHERE id = 'action_def456';
```

### Ejemplo 5: Aprender patrón de amenaza personalizado
**Escenario:** Nueva firma de ataque descubierta: `" UNION SELECT * FROM users--` en registros de consultas.

**Comando:**
```bash
meta-watcher learn sqli-pattern \
  --pattern='UNION SELECT.*FROM' \
  --severity=high \
  --description="SQL injection via UNION SELECT" \
  --source=postgresql \
  --ai-compatible=true
```

**Salida:**
```
✓ Pattern added to custom rule set: /etc/meta-watcher/rules/custom_sqli.yaml
✓ Retraining AI model with new example...
✓ AI model updated (version: 2.4.1-custom.20250304)
✓ Pattern will be active in next monitoring cycle (T+60s)
To test: meta-watcher analyze test.log --ruleset=custom_sqli --verbose
```

**Archivo de Regla Generado:**
```yaml
rule:
  id: custom_sqli_001
  name: "SQL Injection via UNION SELECT"
  pattern: '(?i)UNION\s+SELECT.*FROM'
  severity: critical
  source: postgresql
  action:
    type: "quarantine"
    quarantine_dir: "/var/quarantine/sqlinjection"
    alert: true
  ai_augmentation:
    enabled: true
    confidence_boost: 0.15
    context: "Detects UNION-based SQL injection attempts targeting PostgreSQL"
```

## Comandos de Reversión

Meta Watcher proporciona capacidades de reversión quirúrgicas para todas las acciones automatizadas.

### `meta-watcher rollback ACTION_ID`
Deshacer una acción específica por su ID de base de datos.

**Entradas:**
- `ACTION_ID`: El ID de acción de base de datos (ej. `action_def456`)

**Proceso:**
1. Cargar registro de acción desde tabla `actions`
2. Verificar no estar ya revertida
3. Ejecutar operación inversa basada en `action_type`:
   - `iptables_block`: `iptables -D INPUT -s <IP> -j DROP`
   - `file_quarantine`: `mv <quarantined> <original_path>` (si archivo existe)
   - `service_stop`: `systemctl start <service>`
   - `config_change`: Restaurar desde backup en `$META_WATCHER_BACKUPS/config_YYYYMMDD_HHMMSS`
4. Actualizar base de datos: `rolled_back=1, rolled_back_at=NOW()`
5. Notificar a canales de alerta de la reversión

**Ejemplo:**
```bash
# Encontrar ID de acción
sqlite3 /var/lib/meta-watcher/threats.db "SELECT id, action_id FROM actions WHERE target_ip='192.168.1.100' ORDER BY created_at DESC LIMIT 1;"

# Revertir
meta-watcher rollback action_def456 --reason="False positive - user whitelisted"
```

### `meta-watcher rollback --ip=IP_ADDR`
Revertir todas las acciones que afectan a una IP específica dentro del plazo.

**Banderas:**
- `--ip=IP`: Dirección IP objetivo
- `--hours=N`: Buscar en últimas N horas (por defecto: 24)
- `--dry-run`: Mostrar qué se revertiría

**Ejemplo:**
```bash
meta-watcher rollback --ip=192.168.1.100 --hours=48
```

**Salida:**
```
Found 3 actions affecting 192.168.1.100 in last 48 hours:
  1. action_def456: iptables block (2025-03-04 14:33:47) - rolling back...
  2. action_def789: quarantine /tmp/suspicious.sh (2025-03-04 15:00:00) - skipping (already rolled back)
  3. action_abc123: rate_limit set (2025-03-04 16:00:00) - rolling back...
✓ 2 actions rolled back, 1 skipped (already rolled back)
```

### `meta-watcher restore FILE_PATH`
Restaurar archivo en cuarentena a su ubicación original.

**Proceso:**
1. Buscar hash de archivo en tabla `quarantine`
2. Verificar que archivo existe en directorio de cuarentena
3. Comprobar si ubicación original es segura (no maliciosa actualmente)
4. Mover archivo de vuelta con permisos originales
5. Eliminar registro de cuarentena

**Ejemplo:**
```bash
meta-watcher restore /var/quarantine/1700000000_suspicious.php
```

### `meta-watcher rollback --emergency-stop`
Parada de emergencia que inmediatamente:
- Detiene todos los hilos de monitorización
- Vuelca eventos pendientes a disco
- Crea snapshot de base de datos antes de apagado
- Deshabilita respuestas automatizadas hasta `meta-watcher resume`

**Usar solo para:** Escalación de incidente activo, cascada de falsos positivos, sospecha de compromiso del sistema.

### Respaldo y Restauración de Base de Datos

**Respaldo manual:**
```bash
sqlite3 /var/lib/meta-watcher/threats.db ".backup /backup/meta-watcher-$(date +%Y%m%d).db"
```

**Restaurar a punto en el tiempo:**
```bash
systemctl stop meta-watcher
cp /backup/meta-watcher-20250304.db /var/lib/meta-watcher/threats.db
systemctl start meta-watcher
```

**Nota:** Restaurar base de datos antigua puede duplicar alertas. Ejecutar `meta-watcher deduplicate` después de restaurar.

## Dependencias y Requisitos

### Paquetes del Sistema (Debian/Ubuntu)
```bash
apt-get install -y python3.9 python3-pip sqlite3 jq inotify-tools \
  iptables nftables systemd journalctl curl
```

### Dependencias Python (instalación automática)
```bash
pip install openai>=1.0.0 pyyaml python-dateutil psutil sqlalchemy
```

### Configuración
Config por defecto: `/etc/meta-watcher/config.yaml`

Config mínima viable:
```yaml
ai:
  provider: "openai"
  api_key: "${OPENAI_API_KEY}"  # desde entorno
  model: "gpt-4-turbo-preview"
  threshold: 0.85

monitors:
  ssh:
    source: "journalctl -u sshd -o json"
    ruleset: "ssh_bruteforce"
    auto_block: false

database:
  path: "/var/lib/meta-watcher/threats.db"
  encryption: "sqlcipher"  # opcional

alerts:
  slack:
    webhook: "https://hooks.slack.com/services/XXX"
  logfile: "/var/log/meta-watcher/alerts.log"
```

### Variables de Entorno
- `META_WATCHER_CONFIG`: Anular ruta de archivo de configuración
- `META_WATCHER_DB`: Anular ruta de base de datos
- `META_WATCHER_EVIDENCE`: Directorio de almacenamiento de evidencia (por defecto: /var/lib/meta-watcher/evidence/)
- `OPENAI_API_KEY`: Requerida para análisis IA
- `META_WATCHER_LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR (por defecto: INFO)
- `META_WATCHER_MAX_CPU`: Porcentaje límite de CPU (por defecto: 30)

### Permisos
Ejecutar como usuario dedicado `meta-watcher` con:
```bash
useradd -r -s /usr/sbin/nologin meta-watcher
usermod -aG adm meta-watcher  # para acceso a journalctl
setfacl -m u:meta-watcher:rw /var/log/auth.log
```

## Pasos de Verificación

Después de instalación o cambios de configuración:

1. **Verificar estado del servicio:**
   ```bash
   systemctl status meta-watcher
   journalctl -u meta-watcher -n 50 --no-pager
   ```

2. **Verificar integridad de base de datos:**
   ```bash
   sqlite3 /var/lib/meta-watcher/threats.db "PRAGMA integrity_check;"
   # Debería devolver: ok
   ```

3. **Probar conectividad IA:**
   ```bash
   meta-watcher test-ai --prompt="Test connection"
   # Esperado: {"status":"ok","response_received":true}
   ```

4. **Validar configuración:**
   ```bash
   meta-watcher validate-config /etc/meta-watcher/config.yaml
   # Esperado: Configuration valid
   ```

5. **Dry-run de monitor:**
   ```bash
   meta-watcher monitor --source=sshd --dry-run --verbose
   # Esperado: Muestra eventos parseados, sin acciones tomadas
   ```

6. **Verificar canales de alerta:**
   ```bash
   meta-watcher test-alert --channel=slack
   # Esperado: "Test alert sent to #security-alerts"
   ```

7. **Verificar funcionalidad de lista de bloqueo (si auto-block habilitado):**
   ```bash
   meta-watcher test-block --ip=192.168.1.1
   # Esperado: "Test IP 192.168.1.1 blocked successfully"
   iptables -L INPUT -n | grep 192.168.1.1
   meta-watcher rollback action_testXXXX  # Limpiar bloque de prueba
   ```

8. **Revisar rastro de auditoría:**
   ```bash
   meta-watcher audit --last=10 --format=json
   # Esperado: Array JSON de últimas 10 acciones con contexto completo
   ```

## Solución de Problemas Comunes

### Alto uso de CPU (>80%)
**Síntoma:** `top` muestra meta-watcher consumiendo CPU excesiva.

**Diagnóstico:**
```bash
ps aux | grep meta-watcher
# Verificar si atascado en bucle de análisis IA o parseo de logs
strace -p <PID> -f 2>&1 | head -50
```

**Soluciones:**
- Aumentar `batch_size` en configuración (procesar eventos en lotes)
- Habilitar caché: `ai: cache_ttl: 300` (cachear respuestas IA por 5min)
- Reducir fuentes monitorizadas o cambiar a `--mode=low-frequency`
- Usar modelo IA local en vez de OpenAI: `ai: provider: local-model`

### Cuota de API IA excedida
**Síntoma:** Errores en logs: `OpenAIError: Rate limit exceeded`.

**Soluciones:**
```bash
# Verificar uso actual
openai api usage.retrieve

# Deshabilitar temporalmente IA (respaldo a solo reglas)
sed -i 's/ai_threshold:.*/ai_threshold: 0.0/' /etc/meta-watcher/config.yaml
systemctl reload meta-watcher

# Mejorar cuenta OpenAI o usar modelo diferente
# En config: ai: model: "gpt-3.5-turbo"  # más barato pero menos preciso
```

### Falsos positivos saturando alertas
**Síntoma:** Inundación de alertas por actividad benigna.

**Soluciones:**
1. Aumentar umbral IA temporalmente:
   ```bash
   meta-watcher monitor --ai-threshold=0.95
   ```
2. Crear lista blanca:
   ```bash
   meta-watcher whitelist add --ip=10.0.0.100 --reason="Trusted backup server"
   ```
3. Ajustar severidad de reglas en `/etc/meta-watcher/rules/` a `severity: low` para patrones ruidosos
4. Habilitar `ai: adaptive_threshold: true` en configuración para auto-ajustar basado en tasa de falsos positivos

### Base de datos bloqueada / problemas de rendimiento
**Síntoma:** `sqlite3.OperationalError: database is locked`

**Causas:** Múltiples escritores concurrentes (múltiples monitores).

**Solución:**
```bash
# Habilitar modo WAL para mejor concurrencia
sqlite3 /var/lib/meta-watcher/threats.db "PRAGMA journal_mode=WAL;"

# Aumentar timeout en configuración:
database:
  timeout: 30  # segundos
```

### Entradas de log faltantes
**Síntoma:** Eventos de ciertas fuentes no aparecen en alertas.

**Lista de verificación:**
1. Permisos: `ls -l /var/log/application.log` - ¿está usuario `meta-watcher` en grupo correcto?
2. Rotación de archivos: ¿Aplicación usa copytruncate? Meta-watcher pierde manejo de archivo en rotación. Usar manejo `inotifywait -e move` (implementado en v2.4+).
3. Acceso journalctl: `sudo -u meta-watcher journalctl -u sshd -n 10` - debería devolver entradas.
4. Comando fuente en configuración debe devolver JSON válido. Probar manualmente:
   ```bash
   journalctl -u sshd -o json --since "1 min ago" | jq empty && echo "Valid JSON"
   ```

### Lista de bloqueo no aplicándose
**Síntoma:** IPs detectadas pero no bloqueadas.

**Diagnóstico:**
```bash
# Verificar si auto-block habilitado en configuración y banderas CLI
grep auto_block /etc/meta-watcher/config.yaml

# Verificar iptables/nftables
iptables -L INPUT -n --line-numbers | grep DROP
# O
nft list ruleset | grep drop

# Comprobar si meta-watcher tiene capacidad CAP_NET_ADMIN
getcap /usr/bin/meta-watcher
# Si vacío: setcap cap_net_admin+ep /usr/bin/meta-watcher
```

### Canales de alerta fallando silenciosamente
**Síntoma:** Amenazas detectadas pero sin notificaciones Slack/PagerDuty.

**Depurar:**
```bash
# Probar webhook manualmente
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test from meta-watcher"}' \
  https://hooks.slack.com/services/XXX

# Revisar logs de meta-watcher para errores de alerta
grep "alert" /var/log/meta-watcher/meta-watcher.log | tail -20

# Validar URL de webhook en configuración
meta-watcher validate-alerts
```

### Errores de sintaxis en configuración
**Síntoma:** Servicio falla al iniciar con error de análisis YAML.

**Recuperación:**
```bash
# Validar sintaxis YAML
python3 -c 'import yaml; yaml.safe_load(open("/etc/meta-watcher/config.yaml"))'

# Usar configuración por defecto temporalmente
cp /etc/meta-watcher/config.yaml.default /etc/meta-watcher/config.yaml
systemctl start meta-watcher

# Fusionar configuración personalizada incrementalmente
```

## Ajuste de Rendimiento

Para entornos de alto volumen (>10k eventos/día):

1. **Habilitar caché Redis** (si disponible):
   ```yaml
   cache:
     backend: "redis"
     host: "localhost"
     port: 6379
     ttl: 600
   ```

2. **Procesamiento por lotes:**
   ```yaml
   processing:
     batch_size: 100  # eventos por llamada IA
     batch_timeout: 5.0  # segundos
   ```

3. **Monitorización selectiva:**
   - Usar `--exclude-patterns` para filtrar tráfico benigno conocido
   - Muestreo reducido: `monitor --sample-rate=0.1` (10% muestreo) para fuentes de bajo riesgo

4. **Escalado horizontal:**
   Ejecutar múltiples instancias meta-watcher con fuentes particionadas:
   ```bash
   # Instancia 1: logs SSH
   meta-watcher monitor --source=sshd --instance-id=1
   
   # Instancia 2: logs web
   meta-watcher monitor --source=nginx --instance-id=2
   
   # Base de datos compartida con columna de instancia para filtrado
   ```

## Consideraciones de Seguridad

1. **Ejecutar como no-root**: Meta-watcher escalan via sudoers solo para comandos iptables específicos.
   ```
   meta-watcher ALL=(root) NOPASSWD: /sbin/iptables -I INPUT, /sbin/iptables -D INPUT
   ```

2. **Protección de clave API**: Almacenar clave OpenAI en `/etc/meta-watcher/secrets.env` con permisos 0400.

3. **Cifrado de base de datos**: Habilitar SQLCipher si se almacenan IPs sensibles/datos de usuario.

4. **Sanitización de logs**: Meta-watcher enmascara contraseñas/tokens de logs antes de enviar a IA:
   ```yaml
   sanitization:
     patterns:
       - 'password"[^>]*>([^<]+)'  # Reemplazar valores de contraseña con <REDACTED>
       - 'Authorization: Bearer \S+'
     replace_with: "<REDACTED>"
   ```

5. **Aislamiento de red**: Ejecutar en VPC/subred separada; restringir salida solo a IPs OpenAI (si se usa IA remota).

## Soporte y Mantenimiento

**Rotación de logs:**
```bash
# /etc/logrotate.d/meta-watcher
/var/log/meta-watcher/*.log {
  daily
  rotate 30
  compress
  delaycompress
  missingok
  notifempty
  create 640 meta-watcher adm
  sharedscripts
  postrotate
    systemctl reload meta-watcher > /dev/null 2>&1 || true
  endscript
}
```

**Mantenimiento de base de datos (semanal):**
```bash
sqlite3 /var/lib/meta-watcher/threats.db "VACUUM;"
sqlite3 /var/lib/meta-watcher/threats.db "ANALYZE;"
# Archivar registros antiguos (>90 días) a almacenamiento frío
```

**Actualizaciones de modelo:**
```bash
# Modelo IA se actualiza automáticamente semanalmente
# Forzar actualización:
meta-watcher update-model --force

# Fijar versión específica de modelo en configuración:
ai:
  model: "gpt-4-turbo-preview-2024-04-09"
```

---

## Referencia Rápida

| Comando | Propósito | Ejemplo |
|---------|-----------|---------|
| `monitor` | Iniciar vigilancia continua | `meta-watcher monitor --source=sshd` |
| `analyze` | Escaneo único de logs | `meta-watcher analyze /var/log/auth.log` |
| `status` | Mostrar estado actual | `meta-watcher status` |
| `rollback` | Deshacer acción | `meta-watcher rollback action_123` |
| `compliance` | Verificar estándares | `meta-watcher compliance check --standard=cis` |
| `learn` | Entrenar IA | `meta-watcher learn pattern_name` |
| `test-alert` | Verificar canales | `meta-watcher test-alert --channel=slack` |

**Códigos de salida:**
- 0: Éxito
- 1: Error de configuración
- 2: Fallo IA/red
- 3: Acción fallida (pero registrada)
- 4: Parada de emergencia activada

**Archivos:**
- `/etc/meta-watcher/config.yaml` - Configuración principal
- `/var/lib/meta-watcher/threats.db` - Base de datos SQLite
- `/var/lib/meta-watcher/evidence/` - Evidencia de logs crudos
- `/var/log/meta-watcher/` - Logs de aplicación
- `/etc/meta-watcher/rules/` - Definiciones de reglas YAML
```
```