# azure-sentinel-detections
A collection of custom Microsoft Sentinel KQL detection rules for identifying cyber threats, identity attacks, and anomalous cloud activity.


# Microsoft Sentinel Custom Detection Rules

A collection of production-ready custom KQL (Kusto Query Language) analytics and detection rules designed for Microsoft Sentinel. These rules focus on identifying identity threats, data exfiltration, persistence, and anomalous cloud infrastructure activity.

## 🛠️ Repository Contents

| Rule Name | Target Log Sources | Severity | Description |
| :--- | :--- | :--- | :--- |
| **Password Spray Detection** | `SigninLogs` | Dynamic | Detects authentication failures across multiple accounts from a single IP. |
| **Impossible Travel Login** | `SigninLogs` | Medium | Identifies user sign-ins from geographically impossible distances within a narrow window. |
| **New Privileged Account Creation** | `AuditLogs` | High | Correlates new user creations with immediate administrative role assignments. |
| **Malicious IP Sign-in** | `SigninLogs`, `ThreatIntelligenceIndicator` | High | Flags successful logins matching active Threat Intelligence IOC feeds. |
| **Bulk SharePoint File Downloads** | `OfficeActivity` | Dynamic | Tracks rapid, high-volume file downloads indicating data exfiltration. |
| **MFA Disabled for a User** | `AuditLogs` | High | Catches explicit disablement or wiping of multi-factor authentication requirements. |
| **Mass Email Forwarding Rule** | `OfficeActivity` | Medium | Flags inbox rules routing mail out to external unauthorized domains. |
| **Unusual Azure Resource Deletion** | `AzureActivity` | Medium | Monitors high-frequency resource deletions indicative of destructive behavior. |
| **Privilege Access Granted** | `AuditLogs` | Medium | Identifies when subscription or resource ownership access is assigned. |
| **HTTP Unauthorized Brute Force** | `CommonSecurityLog` | Medium | Flags mass web server authorization failures excluding known safe hosts. |
| **External NSG Modifications** | `AzureActivity` | High | Tracks structural Network Security Group edits made from outside corporate IP spaces. |
| **Apache Security Bypass** | `CommonSecurityLog` | High | Detects specific reverse proxy exploitation patterns while filtering false domains. |
