I notice this is about generating documentation content, not about executing code or working with an existing codebase. This is a content creation task where I need to produce a SKILL.md file based on the description provided.

Let me generate the complete SKILL.md file:

```markdown
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

AI-powered security monitoring and automated threat response system that continuously analyzes system logs, network traffic, and application behavior to detect and respond to security incidents in real-time.

## Purpose

Meta Watcher serves three critical security functions:

1. **Real-time Threat Detection**: Analyzes syslog, application logs, and network packets using AI to identify anomalies, brute force attacks, SQL injection attempts, and privilege escalation patterns that traditional signature-based tools miss.

2. **Automated Incident Response**: Executes pre-approved response playbooks when threats are confirmed, including IP blocking with iptables/nftables, process termination, quarantine of compromised files, and alerting to Slack/Teams/PagerDuty.

3. **Compliance Monitoring**: Continuously validates system configurations against CIS benchmarks, PCI-DSS, HIPAA, and custom security policies, generating audit-ready reports.

### Real Use Cases

```
# Detect and block SSH brute force attacks within 60 seconds
meta-watcher monitor --source=journalctl -u sshd --patterns=auth,failed --ai-threshold=0.85 --auto-block

# Scan application logs for OWASP Top 10 vulnerabilities
meta-watcher analyze /var/log/nginx/access.log --ruleset=owasp-top10 --mode=strict --report=html

# Enforce PCI-DSS compliance on payment processing servers
meta-watcher compliance check --standard=pci-dss --target=10.0.1.0/24 --auto-fix --dry-run

# Monitor database query logs for SQL injection
meta-watcher tail /var/log/postgresql/query.log --detect=sqli --quarantine=true --alert-security-team
```

## Scope

Meta Watcher operates on these core commands:

### Main Commands
- `meta-watcher monitor [SOURCE]` - Start continuous monitoring
- `meta-watcher analyze [FILE/PATH]` - One-time analysis of logs or files
- `meta-watcher tail [LOG_FILE]` - Live log streaming with AI analysis
- `meta-watcher compliance [CHECK/REPORT/FIX]` - Compliance framework operations
- `meta-watcher respond [ALERT_ID]` - Manual trigger or override of automated responses
- `meta-watcher status` - Show current monitoring state and threat level
- `meta-watcher rollback [ACTION_ID]` - Undo a specific automated action
- `meta-watcher learn [PATTERN]` - Train the AI model on custom threat patterns
- `meta-watcher export [FORMAT]` - Export threat intelligence data

### Common Flags
- `--source=SYSTEM` - Monitor systemd journal, Docker logs, or file
- `--ruleset=NAME` - Use specific rule set (owasp, cis, custom, etc.)
- `--ai-threshold=N` - Confidence threshold 0.0-1.0 for AI detection
- `--auto-block/--no-auto-block` - Enable/disable automatic blocking
- `--quarantine=DIR` - Quarantine suspicious files to directory
- `--alert-channel=WEBHOOK` - Send alerts to Slack/Teams/PagerDuty
- `--dry-run` - Show what would be done without executing
- `--verbose` - Debug output with AI reasoning
- `--config=FILE` - Override default configuration

## Detailed Work Process

### 1. Initialization Phase
```bash
# Load configuration from YAML
meta-watcher reads /etc/meta-watcher/config.yaml or $META_WATCHER_CONFIG

# Validate dependencies
- Checks for OpenAI API key in environment or config
- Verifies database schema (creates if missing)
- Loads AI model (local or remote)
- Initializes network filters (iptables/nftables ruleset)
- Establishes logging to /var/log/meta-watcher/

# Startup sequence
1. Connect to SQLite database at $META_WATCHER_DB or default
2. Load threat intelligence feeds from $META_WATCHER_INTEL
3. Warm up AI model with baseline patterns
4. Start monitoring threads with resource limits (CPU < 30%, Memory < 500MB)
```

### 2. Data Collection & Ingestion
```bash
# For file-based monitoring
meta-watcher uses inotifywait to detect file changes
- Reads new log lines incrementally
- Timestamps and deduplicates entries

# For systemd journal
journalctl -u SERVICE --since "1 min ago" --output=json

# For network monitoring (optional)
tcpdump -i eth0 -w - -s 0 'tcp port 80 or 443' 2>/dev/null | meta-watcher parse-pcap

# Normalization
All inputs converted to canonical JSON format:
{
  "timestamp": "2025-03-04T14:32:10Z",
  "source": "nginx/access.log",
  "severity": "high",
  "message": "192.168.1.100 - - [04/Mar/2025:14:32:10 +0000] \"POST /admin.php HTTP/1.1\" 200 1234",
  "metadata": {...}
}
```

### 3. AI Threat Analysis
```bash
# Each normalized event sent to OpenAI API (if enabled)
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

# Fallback to local rule engine if AI unavailable
- Regex pattern matching against /etc/meta-watcher/rules/*.yaml
- Statistical anomaly detection using EWMA
- Correlation with known threat intelligence

# Decision matrix
if confidence >= ai-threshold AND classification == MALICIOUS:
  - Create alert record in database
  - Exec response playbook based on threat type
  - Notify alert channels
elif confidence >= ai-threshold*0.8 AND classification == SUSPICIOUS:
  - Create low-priority alert
  - Increase monitoring sensitivity for source
else:
  - Log as informational, no action
```

### 4. Response Playbook Execution
```bash
# For SSH brute force (threat_type: ssh_bruteforce)
1. Extract attacking IP from log entry
2. Check if IP already in blocklist: SELECT * FROM blocks WHERE ip = '192.168.1.100'
3. If not blocked:
   - iptables -I INPUT 1 -s 192.168.1.100 -j DROP
   - Record in blocks table with timestamp, reason, expires_at (24h default)
   - Send Slack alert: "Blocked IP 192.168.1.100 for SSH brute force"
   - Log action: INSERT INTO actions (type, target, executed_by, created_at) VALUES ('iptables_block', '192.168.1.100', 'meta-watcher', NOW())

# For file quarantine (threat_type: malware, ransomware)
1. Compute SHA256 of suspicious file
2. Check VirusTotal API for known hash
3. If malicious or high suspicion:
   - mv /path/to/file /var/quarantine/$(date +%s)_$(basename file)
   - Set immutable flag: chattr +i /var/quarantine/...
   - Create database record with original path, hash, quarantine_path

# For compliance violations
1. Identify failing control
2. Apply automatic fix if available (e.g., chmod 600 on sensitive file)
3. Generate remediation ticket via API to Jira/ServiceNow if manual intervention needed
```

### 5. Continuous Operation
```bash
# Main loop structure
while running:
  event = read_next_event()  # blocking with timeout
  if event:
    analysis = ai_analyze(event)
    if analysis.threat:
      execute_response(analysis)
  
  # Health check every 60s
  if time() % 60 == 0:
    - Verify database connectivity
    - Check disk space for logs (>10GB warning, >20GB error)
    - Validate AI API quota remaining (>1000 requests/day threshold)
    - Ensure alert channels reachable (test webhook if 5min silence)
```

## Golden Rules

These rules ensure safe and effective operation:

1. **Never auto-delete production data without explicit opt-in**
   - Quarantine is default action for file threats, not deletion
   - Require `--force-delete` flag for permanent removal
   - Keep immutable audit trail in database forever

2. **Rate-limit all automated actions**
   - Maximum 100 IP blocks per hour across all monitors
   - Maximum 10 file quarantines per minute
   - Minimum 1 second between API calls to external services
   - Implement exponential backoff on failures

3. **Always maintain human-in-the-loop for critical systems**
   - `--no-auto-block` default on production servers without prior approval
   - Require `--approved-by=TEAM` flag for actions on databases, payment systems
   - Send mandatory approval requests for >5 IPs blocked simultaneously

4. **Preserve evidence chain**
   - Store original log entries unchanged in `$META_WATCHER_EVIDENCE` (default: /var/lib/meta-watcher/evidence/)
   - Compute SHA256 of all evidence files before modification
   - Generate signed integrity reports daily with `meta-watcher verify --integrity`

5. **Defense in depth**
   - Never rely solely on AI; always run rule-engine as fallback
   - Validate all AI responses; reject suggestions outside allowed action scope
   - Use separate API keys with minimal permissions for each alert channel
   - Encrypt database with SQLCipher if storing sensitive data

6. **Resource protection**
   - Enforce CPU/memory limits via systemd service file (MemoryMax=1G, CPUQuota=50%)
   - Backpressure:暂停监控如果队列积压超过1000 events
   - Auto-calibrate batch size based on system load

7. **Compliance mandatory**
   - All actions must have retention period defined in config
   - Generate SOC2-compatible audit log for every decision
   - Export data in JSONL format for Splunk/ELK integration

## Examples

### Example 1: Monitor SSH logs for brute force
**Setup:**
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

**Command:**
```bash
meta-watcher monitor --source=sshd --verbose
```

**Sample Output:**
```
[2025-03-04 14:32:10] INFO: Starting monitor 'sshd'
[2025-03-04 14:33:45] WARNING: Detected potential SSH brute force from 192.168.1.100 (12 failures in 60s)
[2025-03-04 14:33:46] AI Analysis: MALICIOUS (confidence: 0.96) - Pattern matches credential stuffing
[2025-03-04 14:33:47] ACTION: Blocking IP 192.168.1.100 via iptables (expires: 2025-03-05 14:33:47)
[2025-03-04 14:33:47] ALERT: Sent to Slack (#security-alerts) and PagerDuty (incident ID: INC12345)
[2025-03-04 14:33:48] EVIDENCE: Saved 15 log lines to /var/lib/meta-watcher/evidence/abc123.json
```

**Database Record (threats table):**
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

### Example 2: One-time analysis of web access logs
**Command:**
```bash
meta-watcher analyze /var/log/nginx/access.log \
  --ruleset=owasp-top10 \
  --ai-threshold=0.8 \
  --report=html \
  --output=report.html
```

**Sample Report (HTML excerpt):**
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

### Example 3: Compliance check with auto-fix (dry run)
**Command:**
```bash
meta-watcher compliance check \
  --standard=cis-benchmark \
  --target=/etc/ssh/sshd_config \
  --auto-fix \
  --dry-run
```

**Output:**
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

### Example 4: Rollback a false positive action
**Scenario:** IP 192.168.1.100 was incorrectly blocked due to glitch in monitoring.

**Command:**
```bash
meta-watcher rollback action_def456
```

**Output:**
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

**Database Update:**
```sql
UPDATE actions 
SET rolled_back = 1, 
    rolled_back_at = '2025-03-04T15:00:00Z',
    rollback_reason = 'False positive - legitimate user IP'
WHERE id = 'action_def456';
```

### Example 5: Learn a custom threat pattern
**Scenario:** New attack signature discovered: `" UNION SELECT * FROM users--` in query logs.

**Command:**
```bash
meta-watcher learn sqli-pattern \
  --pattern='UNION SELECT.*FROM' \
  --severity=high \
  --description="SQL injection via UNION SELECT" \
  --source=postgresql \
  --ai-compatible=true
```

**Output:**
```
✓ Pattern added to custom rule set: /etc/meta-watcher/rules/custom_sqli.yaml
✓ Retraining AI model with new example...
✓ AI model updated (version: 2.4.1-custom.20250304)
✓ Pattern will be active in next monitoring cycle (T+60s)
To test: meta-watcher analyze test.log --ruleset=custom_sqli --verbose
```

**Generated Rule File:**
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

## Rollback Commands

Meta Watcher provides surgical rollback capabilities for all automated actions.

### `meta-watcher rollback ACTION_ID`
Undo a specific action by its database ID.

**Inputs:**
- `ACTION_ID`: The action ID from database (e.g., `action_def456`)

**Process:**
1. Load action record from `actions` table
2. Verify not already rolled back
3. Execute reverse operation based on `action_type`:
   - `iptables_block`: `iptables -D INPUT -s <IP> -j DROP`
   - `file_quarantine`: `mv <quarantined> <original_path>` (if file exists)
   - `service_stop`: `systemctl start <service>`
   - `config_change`: Restore from backup in `$META_WATCHER_BACKUPS/config_YYYYMMDD_HHMMSS`
4. Update database: `rolled_back=1, rolled_back_at=NOW()`
5. Notify alert channels of rollback

**Example:**
```bash
# Find action ID
sqlite3 /var/lib/meta-watcher/threats.db "SELECT id, action_id FROM actions WHERE target_ip='192.168.1.100' ORDER BY created_at DESC LIMIT 1;"

# Rollback
meta-watcher rollback action_def456 --reason="False positive - user whitelisted"
```

### `meta-watcher rollback --ip=IP_ADDR`
Rollback all actions affecting a specific IP within timeframe.

**Flags:**
- `--ip=IP`: Target IP address
- `--hours=N`: Look back N hours (default: 24)
- `--dry-run`: Show what would be rolled back

**Example:**
```bash
meta-watcher rollback --ip=192.168.1.100 --hours=48
```

**Output:**
```
Found 3 actions affecting 192.168.1.100 in last 48 hours:
  1. action_def456: iptables block (2025-03-04 14:33:47) - rolling back...
  2. action_def789: quarantine /tmp/suspicious.sh (2025-03-04 15:00:00) - skipping (already rolled back)
  3. action_abc123: rate_limit set (2025-03-04 16:00:00) - rolling back...
✓ 2 actions rolled back, 1 skipped (already rolled back)
```

### `meta-watcher restore FILE_PATH`
Restore a quarantined file to its original location.

**Process:**
1. Look up file hash in `quarantine` table
2. Verify file exists in quarantine directory
3. Check if original location is safe (not currently malicious)
4. Move file back with original permissions
5. Remove quarantine record

**Example:**
```bash
meta-watcher restore /var/quarantine/1700000000_suspicious.php
```

### `meta-watcher rollback --emergency-stop`
Emergency stop that immediately:
- Stops all monitoring threads
- Flushes all pending events to disk
- Creates database snapshot before shutdown
- Disables automated responses until `meta-watcher resume`

**Use only for:** Active incident escalation, false positive cascade, or system compromise suspicion.

### Database Backup & Restore

**Manual backup:**
```bash
sqlite3 /var/lib/meta-watcher/threats.db ".backup /backup/meta-watcher-$(date +%Y%m%d).db"
```

**Restore to point-in-time:**
```bash
systemctl stop meta-watcher
cp /backup/meta-watcher-20250304.db /var/lib/meta-watcher/threats.db
systemctl start meta-watcher
```

**Note:** Restoring older database may duplicate alerts. Run `meta-watcher deduplicate` after restore.

## Dependencies & Requirements

### System Packages (Debian/Ubuntu)
```bash
apt-get install -y python3.9 python3-pip sqlite3 jq inotify-tools \
  iptables nftables systemd journalctl curl
```

### Python Dependencies (auto-installed)
```bash
pip install openai>=1.0.0 pyyaml python-dateutil psutil sqlalchemy
```

### Configuration
Default config: `/etc/meta-watcher/config.yaml`

Minimum viable config:
```yaml
ai:
  provider: "openai"
  api_key: "${OPENAI_API_KEY}"  # from environment
  model: "gpt-4-turbo-preview"
  threshold: 0.85

monitors:
  ssh:
    source: "journalctl -u sshd -o json"
    ruleset: "ssh_bruteforce"
    auto_block: false

database:
  path: "/var/lib/meta-watcher/threats.db"
  encryption: "sqlcipher"  # optional

alerts:
  slack:
    webhook: "https://hooks.slack.com/services/XXX"
  logfile: "/var/log/meta-watcher/alerts.log"
```

### Environment Variables
- `META_WATCHER_CONFIG`: Override config file path
- `META_WATCHER_DB`: Override database path
- `META_WATCHER_EVIDENCE`: Evidence storage directory (default: /var/lib/meta-watcher/evidence/)
- `OPENAI_API_KEY`: Required for AI analysis
- `META_WATCHER_LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR (default: INFO)
- `META_WATCHER_MAX_CPU`: CPU limit percentage (default: 30)

### Permissions
Run as dedicated user `meta-watcher` with:
```bash
useradd -r -s /usr/sbin/nologin meta-watcher
usermod -aG adm meta-watcher  # for journalctl access
setfacl -m u:meta-watcher:rw /var/log/auth.log
```

## Verification Steps

After installation or configuration changes:

1. **Check service status:**
   ```bash
   systemctl status meta-watcher
   journalctl -u meta-watcher -n 50 --no-pager
   ```

2. **Verify database integrity:**
   ```bash
   sqlite3 /var/lib/meta-watcher/threats.db "PRAGMA integrity_check;"
   # Should return: ok
   ```

3. **Test AI connectivity:**
   ```bash
   meta-watcher test-ai --prompt="Test connection"
   # Expected: {"status":"ok","response_received":true}
   ```

4. **Validate configuration:**
   ```bash
   meta-watcher validate-config /etc/meta-watcher/config.yaml
   # Expected: Configuration valid
   ```

5. **Dry-run a monitor:**
   ```bash
   meta-watcher monitor --source=sshd --dry-run --verbose
   # Expected: Shows events parsed, no actions taken
   ```

6. **Check alert channels:**
   ```bash
   meta-watcher test-alert --channel=slack
   # Expected: "Test alert sent to #security-alerts"
   ```

7. **Verify blocklist functionality (if auto-block enabled):**
   ```bash
   meta-watcher test-block --ip=192.168.1.1
   # Expected: "Test IP 192.168.1.1 blocked successfully"
   iptables -L INPUT -n | grep 192.168.1.1
   meta-watcher rollback action_testXXXX  # Clean up test block
   ```

8. **Review audit trail:**
   ```bash
   meta-watcher audit --last=10 --format=json
   # Expected: JSON array of last 10 actions with full context
   ```

## Troubleshooting Common Issues

### High CPU usage (>80%)
**Symptom:** `top` shows meta-watcher consuming excessive CPU.

**Diagnosis:**
```bash
ps aux | grep meta-watcher
# Check if stuck in AI analysis loop or log parsing
strace -p <PID> -f 2>&1 | head -50
```

**Fixes:**
- Increase `batch_size` in config (process events in batches)
- Enable caching: `ai: cache_ttl: 300` (cache AI responses for 5min)
- Reduce monitored sources or switch to `--mode=low-frequency`
- Use local AI model instead of OpenAI: `ai: provider: local-model`

### AI API quota exceeded
**Symptom:** Errors in logs: `OpenAIError: Rate limit exceeded`.

**Fixes:**
```bash
# Check current usage
openai api usage.retrieve

# Temporary disable AI (fallback to rules only)
sed -i 's/ai_threshold:.*/ai_threshold: 0.0/' /etc/meta-watcher/config.yaml
systemctl reload meta-watcher

# Upgrade OpenAI account or use different model
# In config: ai: model: "gpt-3.5-turbo"  # cheaper but less accurate
```

### False positives overwhelming alerts
**Symptom:** Flood of alerts for benign activity.

**Solutions:**
1. Increase AI threshold temporarily:
   ```bash
   meta-watcher monitor --ai-threshold=0.95
   ```
2. Create whitelist:
   ```bash
   meta-watcher whitelist add --ip=10.0.0.100 --reason="Trusted backup server"
   ```
3. Adjust ruleset severity in `/etc/meta-watcher/rules/` to `severity: low` for noisy patterns
4. Enable `ai: adaptive_threshold: true` in config to auto-adjust based on false positive rate

### Database locked / performance issues
**Symptom:** `sqlite3.OperationalError: database is locked`

**Causes:** Multiple concurrent writers (multiple monitors).

**Fix:**
```bash
# Enable WAL mode for better concurrency
sqlite3 /var/lib/meta-watcher/threats.db "PRAGMA journal_mode=WAL;"

# Increase timeout in config:
database:
  timeout: 30  # seconds
```

### Missing log entries
**Symptom:** Events from certain sources don't appear in alerts.

**Checklist:**
1. Permissions: `ls -l /var/log/application.log` - is `meta-watcher` user in correct group?
2. File rotation: Does application use copytruncate? Meta-watcher loses file handle on rotation. Use `inotifywait -e move` handling (implemented in v2.4+).
3. Journalctl access: `sudo -u meta-watcher journalctl -u sshd -n 10` - should return entries.
4. Source command in config must output valid JSON. Test manually:
   ```bash
   journalctl -u sshd -o json --since "1 min ago" | jq empty && echo "Valid JSON"
   ```

### Blocklist not applying
**Symptom:** IPs detected but not blocked.

**Diagnosis:**
```bash
# Check if auto-block enabled in config and CLI flags
grep auto_block /etc/meta-watcher/config.yaml

# Verify iptables/nftables
iptables -L INPUT -n --line-numbers | grep DROP
# OR
nft list ruleset | grep drop

# Check if meta-watcher has CAP_NET_ADMIN capability
getcap /usr/bin/meta-watcher
# If empty: setcap cap_net_admin+ep /usr/bin/meta-watcher
```

### Alert channels failing silently
**Symptom:** Threats detected but no Slack/PagerDuty notifications.

**Debug:**
```bash
# Test webhook manually
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test from meta-watcher"}' \
  https://hooks.slack.com/services/XXX

# Check meta-watcher logs for alert errors
grep "alert" /var/log/meta-watcher/meta-watcher.log | tail -20

# Validate webhook URL in config
meta-watcher validate-alerts
```

### Configuration syntax errors
**Symptom:** Service fails to start with YAML parse error.

**Recovery:**
```bash
# Validate YAML syntax
python3 -c 'import yaml; yaml.safe_load(open("/etc/meta-watcher/config.yaml"))'

# Use default config temporarily
cp /etc/meta-watcher/config.yaml.default /etc/meta-watcher/config.yaml
systemctl start meta-watcher

# Incrementally merge custom settings
```

## Performance Tuning

For high-volume environments (10k+ events/day):

1. **Enable Redis cache** (if available):
   ```yaml
   cache:
     backend: "redis"
     host: "localhost"
     port: 6379
     ttl: 600
   ```

2. **Batch processing:**
   ```yaml
   processing:
     batch_size: 100  # events per AI call
     batch_timeout: 5.0  # seconds
   ```

3. **Selective monitoring:**
   - Use `--exclude-patterns` to filter known benign traffic
   - Sample down: `monitor --sample-rate=0.1` (10% sampling) for low-risk sources

4. **Horizontal scaling:**
   Run multiple meta-watcher instances with partitioned sources:
   ```bash
   # Instance 1: SSH logs
   meta-watcher monitor --source=sshd --instance-id=1
   
   # Instance 2: Web logs
   meta-watcher monitor --source=nginx --instance-id=2
   
   # Shared database with instance column for filtering
   ```

## Security Considerations

1. **Run as non-root**: Meta-watcher escalates via sudoers for specific iptables commands only.
   ```
   meta-watcher ALL=(root) NOPASSWD: /sbin/iptables -I INPUT, /sbin/iptables -D INPUT
   ```

2. **API key protection**: Store OpenAI key in `/etc/meta-watcher/secrets.env` with 0400 permissions.

3. **Database encryption**: Enable SQLCipher if storing sensitive IP addresses/user data.

4. **Log sanitization**: Meta-watcher redacts passwords/tokens from logs before sending to AI:
   ```yaml
   sanitization:
     patterns:
       - 'password"[^>]*>([^<]+)'  # Replace password values with <REDACTED>
       - 'Authorization: Bearer \S+'
     replace_with: "<REDACTED>"
   ```

5. **Network isolation**: Run in separate VPC/subnet; restrict outbound to OpenAI IPs only (if using remote AI).

## Support & Maintenance

**Log rotation:**
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

**Database maintenance (weekly):**
```bash
sqlite3 /var/lib/meta-watcher/threats.db "VACUUM;"
sqlite3 /var/lib/meta-watcher/threats.db "ANALYZE;"
# Archive old records (>90 days) tocold storage
```

**Model updates:**
```bash
# AI model automatically updates weekly
# Force update:
meta-watcher update-model --force

# Pin specific model version in config:
ai:
  model: "gpt-4-turbo-preview-2024-04-09"
```

---

## Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `monitor` | Start continuous watching | `meta-watcher monitor --source=sshd` |
| `analyze` | One-time log scan | `meta-watcher analyze /var/log/auth.log` |
| `status` | Show current state | `meta-watcher status` |
| `rollback` | Undo action | `meta-watcher rollback action_123` |
| `compliance` | Check standards | `meta-watcher compliance check --standard=cis` |
| `learn` | Train AI | `meta-watcher learn pattern_name` |
| `test-alert` | Verify channels | `meta-watcher test-alert --channel=slack` |

**Exit codes:**
- 0: Success
- 1: Configuration error
- 2: AI/network failure
- 3: Action failed (but logged)
- 4: Emergency stop triggered

**Files:**
- `/etc/meta-watcher/config.yaml` - Main configuration
- `/var/lib/meta-watcher/threats.db` - SQLite database
- `/var/lib/meta-watcher/evidence/` - Raw log evidence
- `/var/log/meta-watcher/` - Application logs
- `/etc/meta-watcher/rules/` - YAML rule definitions
```