# Windows Security Rules JSON Description

## Overview

The `windows_security_rules.json` file contains security rules for Windows host-level security posture assessment. These rules are used by the Sentrilite scanner to identify security misconfigurations, vulnerabilities, and compliance issues on Windows systems.

## File Structure

```json
{
  "windows_rules": [
    {
      "id": "unique_rule_identifier",
      "severity": 1-4,              // 1=Critical, 2=High, 3=Medium, 4=Low
      "tags": ["tag1", "tag2"],     // Categorization tags
      "cmd": "powershell_command",  // PowerShell command to execute
      "sample_limit": 8,            // Maximum number of samples to include in alert
      "description": "Human-readable description"
    }
  ]
}
```

## Rule Schema

### Structure

Each rule in the `windows_rules` array contains the following fields:

- **id**: Unique identifier for the rule (e.g., `public_tcp_listeners`)
- **severity**: Numeric severity level (1-4)
  - **1**: Critical - Immediate security risk requiring urgent action
  - **2**: High - Significant security risk requiring prompt attention
  - **3**: Medium - Moderate security risk that should be addressed
  - **4**: Low - Minor security concern
- **tags**: Array of categorization tags for filtering and grouping
- **cmd**: PowerShell command to execute for the security check
- **sample_limit**: Maximum number of sample results to include in alert messages
- **description**: Human-readable description explaining what the rule detects

## Rule Categories

### Network Security (6 rules)
- **Tags**: `network`, `posture`, `edr`, `dns`, `proxy`
- **Purpose**: Detects network configuration issues, public listeners, suspicious connections, DNS settings, and proxy configurations
- **Examples**:
  - Public TCP/UDP listeners (0.0.0.0)
  - Suspicious network connections to external IPs
  - Non-standard DNS servers
  - Proxy settings

### Firewall & Antivirus (2 rules)
- **Tags**: `firewall`, `antivirus`, `defender`, `posture`
- **Purpose**: Validates firewall and antivirus protection status
- **Examples**:
  - Windows Firewall disabled
  - Windows Defender disabled or real-time protection off

### User & Authentication (3 rules)
- **Tags**: `users`, `privileges`, `password`, `policy`, `posture`
- **Purpose**: Checks user accounts, privileges, and password policies
- **Examples**:
  - Excessive administrator users
  - Guest account enabled
  - Weak password policies (non-expiring passwords, no password required)

### Persistence Mechanisms (6 rules)
- **Tags**: `persistence`, `startup`, `scheduled_tasks`, `registry`, `wmi`
- **Purpose**: Detects various persistence mechanisms that could be used by malware
- **Examples**:
  - Suspicious startup programs
  - Scheduled tasks running as SYSTEM
  - Hidden scheduled tasks
  - Registry autorun entries (user and system level)
  - WMI event filters

### File Permissions (2 rules)
- **Tags**: `file`, `permissions`
- **Purpose**: Identifies insecure file permissions
- **Examples**:
  - World-writable files in System32
  - World-writable files in Program Files

### System Services (2 rules)
- **Tags**: `services`, `posture`
- **Purpose**: Checks for suspicious or misconfigured services
- **Examples**:
  - Services with suspicious names or paths (containing 'temp')
  - Services without descriptions

### Process Security (2 rules)
- **Tags**: `processes`, `edr`
- **Purpose**: Detects suspicious processes
- **Examples**:
  - Processes running from temporary directories
  - Processes with system-like names running from non-system locations

### File Shares (2 rules)
- **Tags**: `shares`, `posture`
- **Purpose**: Identifies insecure SMB share configurations
- **Examples**:
  - Public SMB shares
  - SMB shares with Everyone access

### Encryption & Security Features (3 rules)
- **Tags**: `encryption`, `bitlocker`, `uac`, `posture`
- **Purpose**: Validates encryption and security feature status
- **Examples**:
  - BitLocker disabled or incomplete
  - UAC disabled

### Remote Access (1 rule)
- **Tags**: `remote_access`, `rdp`
- **Purpose**: Checks remote access configuration
- **Examples**:
  - Remote Desktop enabled

### Audit & Logging (2 rules)
- **Tags**: `audit`, `logging`, `forensics`
- **Purpose**: Validates audit and logging configuration
- **Examples**:
  - Weak audit policies (No Auditing)
  - Security event log cleared

### PowerShell Security (1 rule)
- **Tags**: `powershell`, `execution`
- **Purpose**: Checks PowerShell execution policy
- **Examples**:
  - PowerShell execution policy set to Bypass or Unrestricted

### System Updates (1 rule)
- **Tags**: `updates`, `patch`
- **Purpose**: Validates Windows update configuration
- **Examples**:
  - Windows automatic updates disabled

### Protocol Security (2 rules)
- **Tags**: `smb`, `protocol`, `tls`, `encryption`
- **Purpose**: Checks for insecure protocol configurations
- **Examples**:
  - SMBv1 enabled (deprecated and vulnerable)
  - Weak TLS cipher suites (RC4, DES, MD5)

---

## Complete Rule List

### Network Security

1. **public_tcp_listeners** (Severity: 2)
   - Detects TCP services listening on all interfaces (0.0.0.0). This exposes services to the network unnecessarily.

2. **public_udp_listeners** (Severity: 2)
   - Identifies UDP services listening on all interfaces. Public UDP listeners can be exploited for amplification attacks.

3. **network_connections_suspicious** (Severity: 2)
   - Detects network connections to external (non-private) IP addresses.

4. **dns_servers_suspicious** (Severity: 2)
   - Detects non-standard DNS servers. Suspicious DNS servers may be used for DNS hijacking.

5. **proxy_settings** (Severity: 3)
   - Lists proxy settings. Suspicious proxy configurations may indicate network interception.

### Firewall & Antivirus

6. **firewall_disabled** (Severity: 3)
   - Checks if Windows Firewall is disabled. Firewalls are essential for network security.

7. **defender_disabled** (Severity: 3)
   - Detects if Windows Defender is disabled. Antivirus protection is critical for security.

### User & Authentication

8. **admin_users** (Severity: 4)
   - Lists all users in the Administrators group. Excessive admin users increase attack surface.

9. **guest_account_enabled** (Severity: 3)
   - Detects if the Guest account is enabled. Guest accounts should be disabled for security.

10. **password_policy_weak** (Severity: 3)
    - Identifies users with weak password policies (non-expiring or no password required).

### Persistence Mechanisms

11. **suspicious_startup_programs** (Severity: 2)
    - Lists programs configured to run at startup. Suspicious entries may indicate malware persistence.

12. **scheduled_tasks_system** (Severity: 3)
    - Identifies scheduled tasks running as SYSTEM. These tasks have high privileges and should be reviewed.

13. **scheduled_tasks_hidden** (Severity: 2)
    - Identifies hidden scheduled tasks. Hidden tasks may be used for persistence.

14. **registry_autorun_user** (Severity: 3)
    - Lists user-level autorun registry entries. These can be used for persistence.

15. **registry_autorun_system** (Severity: 3)
    - Lists system-level autorun registry entries.

16. **wmi_persistence** (Severity: 2)
    - Detects WMI event filters that could be used for persistence.

### File Permissions

17. **world_writable_files_system32** (Severity: 2)
    - Detects world-writable files in System32 directory. World-writable system files are security risks.

18. **world_writable_files_programfiles** (Severity: 2)
    - Identifies world-writable files in Program Files directory.

### System Services

19. **suspicious_services** (Severity: 2)
    - Detects services with suspicious names or paths (containing 'temp').

20. **services_no_description** (Severity: 4)
    - Identifies services without descriptions. Services without descriptions may be suspicious.

### Process Security

21. **processes_temp_location** (Severity: 2)
    - Detects processes running from temporary directories. This is often a sign of malware.

22. **processes_suspicious_names** (Severity: 2)
    - Identifies processes with system-like names running from non-system locations.

### File Shares

23. **shares_public** (Severity: 3)
    - Identifies public SMB shares. Public shares can expose sensitive data.

24. **shares_everyone_access** (Severity: 3)
    - Detects SMB shares with Everyone access. This allows unauthorized access.

### Encryption & Security Features

25. **bitlocker_disabled** (Severity: 3)
    - Checks if BitLocker encryption is disabled or incomplete on volumes.

26. **uac_disabled** (Severity: 3)
    - Checks if User Account Control (UAC) is disabled. UAC should be enabled for security.

### Remote Access

27. **remote_desktop_enabled** (Severity: 2)
    - Detects if Remote Desktop is enabled. RDP should be disabled if not needed.

### Audit & Logging

28. **audit_policy_weak** (Severity: 3)
    - Identifies audit policies set to 'No Auditing'. Proper auditing is essential for security.

29. **event_log_cleared** (Severity: 2)
    - Detects if security event log has been cleared. This may indicate an attempt to hide activity.

### PowerShell Security

30. **powershell_execution_policy_bypass** (Severity: 2)
    - Identifies PowerShell execution policies set to Bypass or Unrestricted. This reduces security.

### System Updates

31. **windows_updates_disabled** (Severity: 3)
    - Checks if Windows automatic updates are disabled. Regular updates are critical for security.

### Protocol Security

32. **smb_v1_enabled** (Severity: 2)
    - Detects if SMBv1 is enabled. SMBv1 is deprecated and vulnerable. Should be disabled.

33. **tls_weak_ciphers** (Severity: 2)
    - Identifies weak TLS cipher suites (RC4, DES, MD5). These should be disabled.

---

## Severity Levels

| Level | Value | Description | Example |
|-------|-------|-------------|---------|
| Critical | 1 | Immediate security risk requiring urgent action | (Not currently used, but reserved) |
| High | 2 | Significant security risk requiring prompt attention | Public listeners, suspicious processes, weak protocols |
| Medium | 3 | Moderate security risk that should be addressed | Firewall disabled, UAC disabled, weak password policies |
| Low | 4 | Minor security concern | Excessive admin users, services without descriptions |

---

## Tags Reference

### Common Tags

#### Category Tags
- `network` - Network security and configuration
- `firewall` - Firewall configuration
- `antivirus` - Antivirus/Defender status
- `defender` - Windows Defender specific
- `users` - User account and authentication
- `privileges` - User privileges and permissions
- `password` - Password policies
- `policy` - Security policies
- `persistence` - Persistence mechanisms
- `startup` - Startup programs
- `scheduled_tasks` - Scheduled tasks
- `registry` - Registry configuration
- `wmi` - Windows Management Instrumentation
- `file` - File system security
- `permissions` - File permissions
- `services` - System services
- `processes` - Running processes
- `shares` - File shares (SMB)
- `encryption` - Encryption settings
- `bitlocker` - BitLocker encryption
- `uac` - User Account Control
- `remote_access` - Remote access configuration
- `rdp` - Remote Desktop Protocol
- `audit` - Audit policies
- `logging` - Logging configuration
- `forensics` - Forensic indicators
- `powershell` - PowerShell configuration
- `execution` - Execution policies
- `updates` - Windows updates
- `patch` - Patch management
- `smb` - SMB protocol
- `protocol` - Network protocols
- `tls` - TLS/SSL configuration
- `dns` - DNS configuration
- `proxy` - Proxy settings

#### Context Tags
- `posture` - Security posture assessment
- `edr` - Endpoint Detection and Response indicators

---

## Command Execution

### PowerShell Commands

Windows security rules execute PowerShell commands on the Windows host. Commands should:

- Use PowerShell cmdlets and native Windows commands
- Be safe to run (read-only operations when possible)
- Return structured output (typically using `Format-Table` or `Select-Object`)
- Handle errors gracefully (using `-ErrorAction SilentlyContinue`)
- Filter results appropriately to identify security issues

**Example Rule Command:**
```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -eq '0.0.0.0' } | Select-Object -Property LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
```

This command:
- Gets all TCP connections
- Filters for listening connections on all interfaces (0.0.0.0)
- Selects relevant properties
- Formats output as a table

### Command Patterns

Common PowerShell patterns used in rules:

1. **Registry Checks**: `Get-ItemProperty -Path 'HKLM:\...' -Name '...'`
2. **Service Checks**: `Get-Service | Where-Object { ... }`
3. **Network Checks**: `Get-NetTCPConnection`, `Get-NetUDPEndpoint`
4. **User Checks**: `Get-LocalUser`, `Get-LocalGroupMember`
5. **Process Checks**: `Get-Process | Where-Object { ... }`
6. **File System Checks**: `Get-ChildItem -Path '...' | Get-Acl`
7. **Scheduled Task Checks**: `Get-ScheduledTask | Where-Object { ... }`
8. **WMI Checks**: `Get-WmiObject -Namespace ... -Class ...`

---

## Sample Limit

The `sample_limit` field controls how many examples are included in the alert message. If a rule finds 100 issues but `sample_limit` is 8, only the first 8 will be shown in the alert message to keep it readable.

Typical sample limits:
- **1**: For binary checks (enabled/disabled)
- **5-8**: For lists that may have many entries
- **10**: For comprehensive lists

---

## Rule Evaluation

### Execution Flow

1. Scanner loads `windows_security_rules.json`
2. For each rule in `windows_rules`:
   - Executes the PowerShell command on the Windows host
   - If command returns output (findings), creates an alert
   - Includes up to `sample_limit` examples in the alert message
   - Assigns severity based on rule configuration
3. Alerts are deduplicated and emitted

### Alert Generation

When a rule detects an issue:
- Alert includes the rule ID and description
- Sample results (up to `sample_limit`) are included
- Severity level is assigned
- Tags are included for filtering and categorization

---

## Adding New Rules

### Adding a Windows Rule

```json
{
  "id": "my_new_windows_rule",
  "severity": 2,
  "tags": ["network", "posture"],
  "cmd": "powershell Get-NetAdapter | Where-Object { $_.Status -ne 'Up' } | Select-Object -Property Name, Status | Format-Table -AutoSize",
  "sample_limit": 10,
  "description": "Detects network adapters that are not up."
}
```

### Best Practices

1. **Unique IDs**: Use descriptive, unique rule IDs (snake_case)
2. **Appropriate Severity**: Assign severity based on actual security risk
3. **Clear Descriptions**: Write clear, actionable descriptions
4. **Relevant Tags**: Use appropriate tags for filtering and categorization
5. **Safe Commands**: Commands should be read-only when possible
6. **Error Handling**: Use `-ErrorAction SilentlyContinue` for registry/file checks
7. **Sample Limits**: Set reasonable sample limits (typically 1-10)
8. **PowerShell Best Practices**: Use native PowerShell cmdlets when available

---

## Rule Statistics

- **Total Rules**: 33
- **Network Security**: 6 rules
- **Firewall & Antivirus**: 2 rules
- **User & Authentication**: 3 rules
- **Persistence Mechanisms**: 6 rules
- **File Permissions**: 2 rules
- **System Services**: 2 rules
- **Process Security**: 2 rules
- **File Shares**: 2 rules
- **Encryption & Security Features**: 2 rules
- **Remote Access**: 1 rule
- **Audit & Logging**: 2 rules
- **PowerShell Security**: 1 rule
- **System Updates**: 1 rule
- **Protocol Security**: 2 rules

---

## Hot Reload

The scanner watches the rules file and automatically reloads when changes are detected. This allows you to:
- Add new rules without restarting
- Modify existing rules on the fly
- Update severity levels dynamically
- Enable/disable rules by removing/adding them

---

## Integration

These rules are used by:
- `windows_scanner.go` - Windows scanner engine
- Windows host security checks
- Alert generation and reporting
- Security posture assessment

---

## Related Files

- `windows_scanner.go` - Windows scanner implementation
- `windows_security_rules.json` - The actual rules file
- `WINDOWS_IMPLEMENTATION_GUIDE.md` - Windows implementation guide
- `WINDOWS_LIGHTWEIGHT_COLLECTOR.md` - Windows collector documentation
- `WINDOWS_SCANNER_VALUE_PROPOSITION.md` - Windows scanner value proposition

---

## Support

For questions or issues with Windows security rules:

1. Check rule descriptions for clarification
2. Review this document for detailed rule information
3. Verify PowerShell command syntax
4. Test rules in a safe environment before production use
5. Ensure PowerShell execution policy allows script execution if needed

---

## Notes

1. **PowerShell Execution Policy**: Some rules may require PowerShell execution policy to be set appropriately. The scanner should run with sufficient privileges.

2. **Administrator Privileges**: Many rules require administrator privileges to execute properly (e.g., checking firewall status, BitLocker status, scheduled tasks).

3. **Windows Version Compatibility**: Rules are designed for modern Windows versions (Windows 10/11, Windows Server 2016+). Some cmdlets may not be available on older versions.

4. **Performance Considerations**: File system checks (e.g., world-writable files) can be resource-intensive on large directories. Consider using appropriate filters and sample limits.

5. **False Positives**: Some rules may generate false positives in specific environments. Review and tune rules based on your organization's security policies.

---

*This document describes 33 Windows security rules covering network security, system configuration, user management, persistence mechanisms, and compliance checks.*

