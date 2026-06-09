# Sample Data – Linux Hardening Assistant

## Connection Details

```json
{
  "host": "localhost",
  "port": 2222,
  "username": "demo",
  "password": "demo123"
}
```

---

## Audit Result Sample

```json
{
  "auditId": "AUDIT-2026-001",
  "timestamp": "2026-06-09T10:30:00Z",
  "targetHost": "localhost",
  "os": "Ubuntu 22.04 LTS",
  "kernelVersion": "5.15.0-140-generic",
  "securityScore": 72,
  "riskLevel": "Moderate",
  "findings": [
    {
      "check": "SSH Root Login",
      "status": "Failed",
      "severity": "High",
      "description": "Root login is enabled.",
      "recommendation": "Disable PermitRootLogin in sshd_config."
    },
    {
      "check": "Password Authentication",
      "status": "Passed",
      "severity": "Low",
      "description": "Password authentication is disabled.",
      "recommendation": "No action required."
    },
    {
      "check": "UFW Firewall",
      "status": "Failed",
      "severity": "Medium",
      "description": "Firewall is inactive.",
      "recommendation": "Enable UFW and configure rules."
    },
    {
      "check": "Fail2Ban",
      "status": "Passed",
      "severity": "Low",
      "description": "Fail2Ban service is active.",
      "recommendation": "No action required."
    },
    {
      "check": "Auditd",
      "status": "Passed",
      "severity": "Low",
      "description": "Auditd service is running.",
      "recommendation": "No action required."
    },
    {
      "check": "Open Ports",
      "status": "Warning",
      "severity": "Medium",
      "description": "Ports 22, 3306 are open.",
      "recommendation": "Close unnecessary ports."
    }
  ]
}
```

---

## Security Score Summary

| Category                | Status   |
| ----------------------- | -------- |
| SSH Root Login          | Failed   |
| Password Authentication | Passed   |
| Firewall (UFW)          | Failed   |
| Fail2Ban                | Passed   |
| Auditd                  | Passed   |
| Open Ports              | Warning  |
| Security Score          | 72 / 100 |
| Risk Level              | Moderate |

---

## AI Recommendation Sample

```text
AI Analysis:

The target system has a moderate security posture. Root SSH login and an inactive firewall significantly increase the attack surface. It is recommended to disable root login, enable UFW, and restrict unnecessary open ports. Existing protections such as Fail2Ban and Auditd should be maintained.
```

---

## Fix Script Sample

```bash
#!/bin/bash

echo "Linux Hardening Recommendations"

read -p "Apply fixes? (yes/no): " ans

if [ "$ans" = "yes" ]; then
    sudo ufw enable
    sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart ssh
    sudo systemctl enable fail2ban
    sudo systemctl enable auditd
    echo "Recommended fixes applied."
else
    echo "Operation cancelled."
fi
```

---

## PDF Report Metadata

```json
{
  "reportName": "Linux_Audit_Report.pdf",
  "generatedBy": "Linux Hardening Assistant",
  "generatedOn": "2026-06-09 10:30 AM",
  "securityScore": 72,
  "riskLevel": "Moderate"
}
```
