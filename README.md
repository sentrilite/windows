# Sentrilite EDR/XDR for Windows — Threat-Detection-as-Code, Observability, Runtime-Security, Live Telemetry, Misconfig Scanner with AI/LLM insights.

# Sentrilite Alert Report
![Sentrilite PDF_Report](./Sample_Alert_Report.png)
# CI/CD Workflow
![Sentrilite_CI_CD_Workflow](./CI_CD_Workflow.png)
# Main Dashboard
![Sentrilite Main Dashboard](./main_dashboard.png)
# Live Server Dashboard
![Sentrilite Server_Dashboard](./live_dashboard.png)

Sentrilite EDR/XDR for Windows is a lightweight Detection-as-Code (DAC), real-time runtime endpoint security and observability platform that streams structured system events to a live dashboard where custom rules determine risk scoring, tagging, alerting, and reporting.

It provides a low-overhead endpoint security layer for Windows servers and workstations without relying on Sysmon or heavyweight EDR tools.

Sentrilite captures all process creation and termination (PROC_CREATE / PROC_TERMINATE), enriching events with:
- Process Activity Monitoring (full executable path, parent PID, User/SID, timestamps, tags)
  Rules can be created for: 
  - Suspicious binaries (e.g., powershell.exe, wscript.exe, certutil.exe)
  - LOLBins and lateral-movement tools
  - Obfuscated or encoded script execution
  - Unexpected parent-child process chains
- File Access Monitoring (Rule-Driven): The Windows agent detects sensitive file usage via process arguments and custom file rules.
  - Rules allow:
    - High-risk alerts for reads/writes to sensitive paths
    - Tagging events with categories such as exfiltration, credential-access, or custom tags
- Network Activity Monitoring: Sentrilite monitors outbound connections via Windows networking APIs (GetExtendedTcpTable), producing events that include:
  - Local/remote address + port
  - Owning process
  - Protocol
  - User context
- Detection-as-Code (DAC)
  - Rules are simple JSON documents (custom_rules.json, security_rules.json):
  - Hot reload on every modification
  - No rebuilds, no restarts
  - Match on any event field: cmd, arg1, user, ip, msg_type, tags, file, etc.
  - Assign risk levels (1=high, 2=medium, 3=low)
  - Add custom tags and metadata
  - Trigger alerts automatically when conditions match
  - This gives Windows administrators full programmability over detection logic.

---

## 🔐 Licensing

The project is currently using a trial license.key .

---

## 🛠️ Third-Party Integrations (PagerDuty & Alertmanager)

- PagerDuty
- Alertmanager (Prometheus ecosystem)
- SIEM forwarding (JSON events)

---

## 🛠️ Installation Steps

In a Powershell Terminal run:
```
.\sentrilite.exe
```
Open the dashboard.html to check live telemetry:

---

## Configuration

- license.key — place in the current directory (baked in image or mounted as Secret).
- sys.conf — network config, placed in the current directory (baked in image or mounted as ConfigMap).
- Rule files - (custom_rules.json, sensitive_files.json, windows_security_rules.json) reside in the working dir; rules can be managed via the dashboard.

---

## Alerts

When a rule marks an event as high-risk, Sentrilite:
- Creates a structured alert (JSON)
- Pushes it in real time to the dashboard
- Saves it to alerts.json
- Marks the node as “high risk” (risk-level = 1)
- Can forward to external systems (PagerDuty, AlertManager)

Alerts include:
- Process info
- User identity
- Risk reasoning via tags
- File paths or network destinations
- Human-readable summaries

---

## Support

For licensing, troubleshooting, or feature requests:
- 📧 info@sentrilite.com
- 🌐 https://sentrilite.com
