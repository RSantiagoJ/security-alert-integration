# Security Alert Integration

A Docker Compose demo of a security alert pipeline. Three mock security tools (WAF, vulnerability scanner, IDS) emit alerts in their own formats. A central integration service normalizes and enriches them, then forwards them to a mock SIEM for aggregation.

```
mock-waf :5000 ──┐
mock-vuln-scanner :5001 ──┼──> integration-service :8000 ──> mock-siem :3000
mock-ids :5002 ──┘
```

## Services

| Service | Port | Role |
|---|---|---|
| `mock-waf` | 5000 | Emits web attack alerts (`GET /trigger-alert`) |
| `mock-vuln-scanner` | 5001 | Emits CVE findings (`GET /trigger-scan`) |
| `mock-ids` | 5002 | Emits network intrusion detections (`GET /trigger-detection`) |
| `integration-service` | 8000 | Receives alerts at `POST /webhook/security-alert`, normalizes, enriches, forwards to the SIEM |
| `mock-siem` | 3000 | Ingests events; exposes `GET /api/events` and `GET /api/dashboard` |

Every service also exposes `GET /health`.

## Integration service

For each incoming alert the service:

1. **Normalizes** it to a common schema: `event_id`, `timestamp`, `source_system`, `alert_type`, `severity` (0-10), `description`, `affected_asset`, `attacker_info`, `remediation`, and the original payload in `raw_data`.
2. **Enriches** it with `threat_level`, `requires_response` (severity >= 7), and `response_priority` (1-3).
3. **Forwards** it to the SIEM at `POST /api/events/ingest`. It returns `503` if the SIEM is unreachable.

Severity mapping: `CRITICAL` = 9, `HIGH` = 7, `MEDIUM` = 5, `LOW` = 3, `INFO` = 1.

## Running the demo

Requires Docker and Python 3 with `requests` (`pip install requests`).

```bash
docker compose up --build
```

In another terminal:

```bash
python trigger_demo.py
```

The script checks service health, triggers each mock tool five times (each picks an alert type at random), then prints the SIEM's aggregated events and dashboard.

You can also trigger a single alert by hand, for example `curl http://localhost:5000/trigger-alert`, and inspect results at `http://localhost:3000/api/events`.

## Configuration

| Variable | Service | Default |
|---|---|---|
| `SIEM_URL` | integration-service | `http://siem:3000` |
| `INTEGRATION_URL` | WAF, scanner, IDS | `http://integration:8000` |
| `PORT` | integration-service | `8000` |

## Project layout

```
docker-compose.yml
trigger_demo.py
integration-service/   # normalization + enrichment webhook
mock-waf/
mock-vuln-scanner/
mock-ids/
mock-siem/
```

All data is simulated; this is a demo, not a production system.
