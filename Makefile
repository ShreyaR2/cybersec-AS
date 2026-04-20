CXX      = g++
CXXFLAGS = -std=c++17 -Wall -O2 -pthread
LDFLAGS  = -lssl -lcrypto -pthread

TARGET  = anagha_ransomware
SOURCES = src/main.cpp src/encryption.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	@$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)
	@echo "[+] Built: $(TARGET)"

# ── Create test files with enough content for reliable entropy detection ──────
# Each file needs ~1KB+ of realistic content so AES entropy jump reads cleanly.
# Honeyfiles are NOT created here — run: python app.py seed
setup:
	@mkdir -p test_files

	@printf 'Project Budget Report - FY2026\n\
Prepared by: Finance Division\n\
\n\
Total Allocated Budget : USD 1,500,000\n\
Q1 Spend               : USD 312,450\n\
Q2 Spend               : USD 287,900\n\
Q3 Forecast            : USD 410,000\n\
Q4 Forecast            : USD 489,650\n\
\n\
Department Breakdown:\n\
  Engineering          : USD 620,000\n\
  Marketing            : USD 280,000\n\
  Operations           : USD 350,000\n\
  HR & Admin           : USD 250,000\n\
\n\
Notes:\n\
  - Engineering overspend flagged in Q1 (hardware procurement)\n\
  - Marketing budget reallocated from events to digital spend\n\
  - Headcount freeze in effect until Q3 review\n\
  - All capital expenses require CFO sign-off above USD 50,000\n\
  - Next review scheduled: 2026-07-01\n\
  - Contact: finance-ops@internal.corp\n\
  - Confidential: Do not distribute outside finance leadership\n\
  - Document ID: FIN-2026-BUD-001\n' > test_files/budget.txt

	@printf 'API Configuration — Internal Services\n\
Environment: Production\n\
Last Updated: 2026-03-15\n\
\n\
[PRIMARY]\n\
API_KEY        = sk-abc123xyz789prod\n\
API_SECRET     = 8f2a9c1d7e4b6f3a\n\
BASE_URL       = https://api.internal.corp/v2\n\
TIMEOUT_MS     = 5000\n\
RETRY_LIMIT    = 3\n\
\n\
[SECONDARY]\n\
API_KEY        = sk-fallback456uvw\n\
BASE_URL       = https://api-backup.internal.corp/v2\n\
TIMEOUT_MS     = 8000\n\
\n\
[DATABASE]\n\
DB_HOST        = db-prod-01.internal.corp\n\
DB_PORT        = 5432\n\
DB_NAME        = core_production\n\
DB_USER        = svc_appuser\n\
DB_PASS        = Xk9#mP2$vL7nQ\n\
DB_SSL         = required\n\
\n\
[CACHE]\n\
REDIS_HOST     = cache-01.internal.corp\n\
REDIS_PORT     = 6379\n\
REDIS_AUTH     = rX4$kL9mN2pQ\n\
\n\
WARNING: Rotate all keys after any suspected breach.\n\
Contact: devops-security@internal.corp\n' > test_files/api_config.txt

	@printf 'Credential Store — Privileged Access\n\
Classification: CONFIDENTIAL\n\
Owner: IT Security Team\n\
\n\
[ADMIN ACCOUNTS]\n\
root_password        = CyberSec2026!@#\n\
backup_admin         = Adm1n$Backup99\n\
deploy_user          = D3pl0y#Secure\n\
\n\
[SERVICE ACCOUNTS]\n\
svc_monitor          = M0n1tor$Pass\n\
svc_backup           = B@ckup$2026\n\
svc_deploy           = D3pl0y$Key77\n\
\n\
[VPN]\n\
vpn_psk              = VpnSecr3t!Key\n\
vpn_user_default     = Usr$VPN2026\n\
\n\
[CERTIFICATES]\n\
cert_passphrase      = C3rtP@ss!2026\n\
p12_export_key       = Exp0rt$Cert99\n\
\n\
[MFA BACKUP CODES]\n\
admin_mfa_backup     = 8472-1930-5564-2871\n\
\n\
Last rotation: 2026-02-01\n\
Next rotation: 2026-08-01\n\
Rotation policy: every 180 days\n\
Escrow: IT-VAULT-03 (offline)\n' > test_files/credentials.txt

	@printf 'Secret: XJ-987\n\
Internal Memo — Security Operations\n\
Date: 2026-04-01\n\
Subject: Q2 Penetration Test Findings\n\
\n\
Executive Summary:\n\
The Q2 red team exercise identified 3 critical and 7 medium severity findings.\n\
All critical findings have been remediated as of 2026-04-10.\n\
\n\
Critical Findings:\n\
  1. Unauthenticated SSRF on internal API gateway (CVE-pending)\n\
     Remediation: Input validation patched, deployed 2026-04-05\n\
  2. Hardcoded credentials in deployment scripts\n\
     Remediation: Secrets moved to vault, scripts updated 2026-04-07\n\
  3. Insecure direct object reference on document endpoint\n\
     Remediation: Authorization checks added 2026-04-10\n\
\n\
Medium Findings:\n\
  - Verbose error messages exposing stack traces (4 endpoints)\n\
  - Missing rate limiting on authentication endpoint\n\
  - Outdated TLS 1.1 support on legacy load balancer\n\
\n\
Next scheduled test: 2026-10-01\n\
Contact: secops@internal.corp\n\
Report ID: PENTEST-2026-Q2-007\n' > test_files/test.txt

	@printf '%%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n\
/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n\
4 0 obj\n<< /Length 200 >>\nstream\n\
BT /F1 12 Tf 72 720 Td\n\
(Confidential Contract Agreement) Tj\n\
0 -20 Td (Parties: Acme Corp and Internal Division) Tj\n\
0 -20 Td (Effective Date: 2026-01-15) Tj\n\
0 -20 Td (Term: 24 months) Tj\n\
0 -20 Td (Value: USD 850000) Tj\n\
0 -20 Td (Governing Law: Delaware, USA) Tj\n\
0 -20 Td (Signatures required before 2026-05-01) Tj\n\
ET\nendstream\nendobj\n\
5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n\
xref\n0 6\ntrailer\n<< /Root 1 0 R /Size 6 >>\nstartxref\n400\n%%%%EOF\n' > test_files/document.pdf

	@printf '<!DOCTYPE html>\n\
<html lang="en">\n\
<head>\n\
  <meta charset="UTF-8">\n\
  <title>Internal Dashboard</title>\n\
</head>\n\
<body>\n\
  <h1>Operations Dashboard</h1>\n\
  <p>Environment: Production</p>\n\
  <p>Server: app-prod-01.internal.corp</p>\n\
  <p>DB Status: Connected (db-prod-01:5432)</p>\n\
  <p>Last Deploy: 2026-04-10 14:32 UTC by deploy_user</p>\n\
  <p>Active Sessions: 142</p>\n\
  <p>Uptime: 47 days 3 hours</p>\n\
  <h2>Recent Alerts</h2>\n\
  <ul>\n\
    <li>2026-04-10 09:12 — High CPU on worker-03 (resolved)</li>\n\
    <li>2026-04-09 22:45 — Failed login attempts from 192.168.4.21</li>\n\
    <li>2026-04-08 14:00 — Scheduled backup completed successfully</li>\n\
  </ul>\n\
  <p class="confidential">INTERNAL USE ONLY — DO NOT DISTRIBUTE</p>\n\
</body>\n\
</html>\n' > test_files/webpage.html

	@printf '#!/usr/bin/env python3\n\
"""\n\
data_pipeline.py — Internal ETL script\n\
Pulls from production DB, transforms, pushes to warehouse.\n\
"""\n\
import os\n\
import json\n\
import logging\n\
from datetime import datetime\n\
\n\
DB_HOST     = os.environ.get("DB_HOST", "db-prod-01.internal.corp")\n\
DB_PORT     = int(os.environ.get("DB_PORT", 5432))\n\
WAREHOUSE   = os.environ.get("WAREHOUSE_URL", "wh-prod.internal.corp")\n\
API_KEY     = os.environ.get("PIPELINE_KEY", "pk-xyz987internal")\n\
\n\
logging.basicConfig(level=logging.INFO)\n\
log = logging.getLogger("pipeline")\n\
\n\
def extract(table: str) -> list:\n\
    log.info(f"Extracting from {table} on {DB_HOST}:{DB_PORT}")\n\
    return []\n\
\n\
def transform(records: list) -> list:\n\
    return [{**r, "processed_at": datetime.utcnow().isoformat()} for r in records]\n\
\n\
def load(records: list, destination: str) -> bool:\n\
    log.info(f"Loading {len(records)} records to {destination}")\n\
    return True\n\
\n\
if __name__ == "__main__":\n\
    for table in ["users", "transactions", "audit_log"]:\n\
        records = extract(table)\n\
        records = transform(records)\n\
        load(records, WAREHOUSE)\n\
    log.info("Pipeline complete")\n' > test_files/code.py

	@printf '#include <iostream>\n\
#include <string>\n\
#include <vector>\n\
#include <fstream>\n\
#include <ctime>\n\
\n\
// Internal utility: system health monitor\n\
// Build: g++ -std=c++17 -o monitor program.cpp\n\
\n\
struct HealthRecord {\n\
    std::string service;\n\
    bool        online;\n\
    double      latency_ms;\n\
    std::time_t checked_at;\n\
};\n\
\n\
std::vector<std::string> SERVICES = {\n\
    "db-prod-01.internal.corp:5432",\n\
    "cache-01.internal.corp:6379",\n\
    "api.internal.corp:443",\n\
    "wh-prod.internal.corp:5432"\n\
};\n\
\n\
HealthRecord check(const std::string& svc) {\n\
    return { svc, true, 12.4, std::time(nullptr) };\n\
}\n\
\n\
int main() {\n\
    std::cout << "System Health Monitor v1.2\\n";\n\
    for (auto& svc : SERVICES) {\n\
        auto rec = check(svc);\n\
        std::cout << "[" << (rec.online ? "UP" : "DOWN") << "] "\n\
                  << rec.service << " "\n\
                  << rec.latency_ms << "ms\\n";\n\
    }\n\
    return 0;\n\
}\n' > test_files/program.cpp

	@echo "[+] Test files created in test_files/"
	@echo "[!] Honeyfiles not created here — run: python app.py seed"

# ── Full reset ────────────────────────────────────────────────────────────────
clean:
	@rm -f $(TARGET) c2_server.log session_history.log attack_metrics.log
	@rm -f system_restore.log temp_key_backup.key
	@rm -f test_files/*.encrypted
	@rm -rf test_files
	@rm -f ~/.honeyfile_registry.json
	@rm -rf ~/honeyfile_evidence
	@echo "[+] Clean complete"

run: $(TARGET)
	@./$(TARGET)

.PHONY: all clean setup run