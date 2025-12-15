# Windows Security Rules JSON Description

## Overview

The `windows_security_rules.json` file contains security rules for Windows host-level security posture assessment. These rules are used by the Sentrilite scanner to identify security misconfigurations, vulnerabilities, and compliance issues on Windows systems.

## File Structure

```json
{
  "windows_rules": [
    {
      "id": "unique_rule_identifier",
      "severity": 1-2,              // 1=High (red), 2=Medium (blue) - rules currently use only 1 and 2
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
- **severity**: Numeric severity level (1-2)
  - **1**: High - Immediate or significant security risk requiring prompt action
  - **2**: Medium - Moderate security risk that should be addressed
- **tags**: Array of categorization tags for filtering and grouping
- **cmd**: PowerShell command to execute for the security check
- **sample_limit**: Maximum number of sample results to include in alert messages
- **description**: Human-readable description explaining what the rule detects

## Rule Categories

### Network Security (7 rules)
- **Tags**: `network`, `posture`, `edr`, `dns`, `proxy`, `exposure`
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

### User & Authentication (4 rules)
- **Tags**: `users`, `privileges`, `password`, `policy`, `posture`, `hardening`
- **Purpose**: Checks user accounts, privileges, password policies, and authentication hardening
- **Examples**:
  - Excessive administrator users
  - Guest account enabled
  - Weak password policies (non-expiring passwords, no password required)
  - Anonymous SAM enumeration allowed

### Persistence Mechanisms (9 rules)
- **Tags**: `persistence`, `scheduled_tasks`, `registry`, `wmi`, `sysmon`, `edr`
- **Purpose**: Detects various persistence mechanisms that could be used by malware
- **Examples**:
  - Scheduled tasks running as SYSTEM
  - Hidden scheduled tasks
  - Registry autorun entries (system level)
  - WMI event filters, consumers, and bindings
  - Sysmon file creation in startup paths
  - Sysmon registry autorun modifications
  - Sysmon WMI persistence events

### File Permissions (2 rules)
- **Tags**: `file`, `permissions`, `posture`
- **Purpose**: Identifies insecure file permissions
- **Examples**:
  - World-writable files in System32
  - World-writable files in Program Files

### System Services (2 rules)
- **Tags**: `services`, `posture`
- **Purpose**: Checks for suspicious or misconfigured services
- **Examples**:
  - Services running from temp/user-writable paths
  - Services without descriptions

### Process Security (2 rules)
- **Tags**: `processes`, `edr`
- **Purpose**: Detects suspicious processes
- **Examples**:
  - Processes running from temporary directories
  - Processes with system-like names running outside system directories

### File Shares (1 rule)
- **Tags**: `shares`, `posture`, `exposure`
- **Purpose**: Identifies insecure SMB share configurations
- **Examples**:
  - SMB shares with Everyone access

### Encryption & Security Features (3 rules)
- **Tags**: `encryption`, `bitlocker`, `uac`, `posture`
- **Purpose**: Validates encryption and security feature status
- **Examples**:
  - BitLocker disabled or incomplete
  - UAC disabled

### Remote Access (1 rule)
- **Tags**: `remote_access`, `rdp`, `posture`
- **Purpose**: Checks remote access configuration
- **Examples**:
  - Remote Desktop enabled

### Audit & Logging (2 rules)
- **Tags**: `audit`, `logging`, `forensics`, `tampering`, `posture`
- **Purpose**: Validates audit and logging configuration
- **Examples**:
  - Weak audit policies (No Auditing)
  - Security event log cleared

### PowerShell Security (2 rules)
- **Tags**: `powershell`, `execution`, `logging`, `posture`
- **Purpose**: Checks PowerShell execution policy and logging
- **Examples**:
  - PowerShell execution policy set to Bypass or Unrestricted
  - PowerShell transcription disabled

### System Updates (1 rule)
- **Tags**: `updates`, `patch`, `posture`
- **Purpose**: Validates Windows update configuration
- **Examples**:
  - Windows automatic updates disabled

### Protocol Security (2 rules)
- **Tags**: `smb`, `protocol`, `tls`, `encryption`, `posture`
- **Purpose**: Checks for insecure protocol configurations
- **Examples**:
  - SMBv1 enabled (deprecated and vulnerable)
  - Weak TLS cipher suites (RC4, DES, MD5)

### Sysmon Detection (8 rules)
- **Tags**: `sysmon`, `process`, `lolbins`, `network`, `dns`, `module-load`, `credential-access`, `lsass`, `persistence`, `file`, `registry`, `wmi`, `edr`
- **Purpose**: Detects security events using Sysmon event log data
- **Examples**:
  - Sysmon process creations for common LOLBins
  - Sysmon network connections initiated by suspicious tools
  - Sysmon DNS queries to suspicious domains
  - Sysmon DLL/image loads from temp locations
  - Sysmon ProcessAccess to LSASS (credential dumping)
  - Sysmon file creation in startup paths
  - Sysmon registry changes in Run/RunOnce keys
  - Sysmon WMI persistence events

### Credential Access & Hardening (3 rules)
- **Tags**: `credential-access`, `posture`, `hardening`, `lsass`
- **Purpose**: Detects credential access risks and missing security hardening
- **Examples**:
  - LSA protection (RunAsPPL) not enabled
  - WDigest UseLogonCredential enabled
  - Sysmon ProcessAccess to LSASS

---

## Complete Rule List

### Firewall & Antivirus

1. **firewall_disabled** (Severity: 1)
   - High risk: Windows Firewall disabled.

2. **defender_disabled** (Severity: 1)
   - High risk: Defender AV/real-time protection disabled.

### User & Authentication

3. **uac_disabled** (Severity: 1)
   - High risk: UAC disabled.

4. **guest_account_enabled** (Severity: 1)
   - High risk: Guest account enabled.

5. **admin_users** (Severity: 2)
   - Medium risk: Admin group membership review.

6. **password_policy_weak** (Severity: 2)
   - Medium risk: Weak local password policy settings.

7. **anonymous_sam_enumeration_allowed** (Severity: 2)
   - Medium risk: RestrictAnonymousSAM not enforced (SAM enumeration risk).

### Protocol Security

8. **smb_v1_enabled** (Severity: 1)
   - High risk: SMBv1 enabled (deprecated/vulnerable).

9. **tls_weak_ciphers_present** (Severity: 2)
   - Medium risk: Weak TLS cipher suites present.

### Audit & Logging

10. **event_log_cleared** (Severity: 1)
    - High risk: Security event log cleared (possible cover-up).

11. **audit_policy_weak** (Severity: 2)
    - Medium risk: Audit policies set to 'No Auditing'.

### WMI Persistence

12. **wmi_persistence_filters** (Severity: 1)
    - High risk: WMI event filters can be used for persistence.

13. **wmi_persistence_consumers** (Severity: 1)
    - High risk: WMI CommandLineEventConsumer (persistence/execution).

14. **wmi_persistence_bindings** (Severity: 1)
    - High risk: WMI filter-to-consumer bindings (active persistence wiring).

### Registry Persistence

15. **registry_autorun_system** (Severity: 1)
    - High risk: System-level autorun entries.

### File Shares

16. **shares_everyone_access** (Severity: 1)
    - High risk: SMB shares with Everyone access.

### File Permissions

17. **world_writable_files_system32** (Severity: 1)
    - High risk: World-writable files under System32.

18. **world_writable_files_programfiles** (Severity: 2)
    - Medium risk: World-writable files under Program Files.

### Network Security

19. **public_tcp_listeners** (Severity: 2)
    - Medium risk: TCP services listening on all interfaces.

20. **public_udp_listeners** (Severity: 2)
    - Medium risk: UDP listeners on all interfaces.

21. **network_connections_external_established** (Severity: 2)
    - Medium risk: Established outbound connections to external IPs.

22. **dns_servers_nonstandard** (Severity: 2)
    - Medium risk: DNS servers review (nonstandard DNS can indicate hijack/implant).

23. **proxy_settings** (Severity: 2)
    - Medium risk: Proxy settings review (possible interception).

### Scheduled Tasks

24. **scheduled_tasks_system_running** (Severity: 2)
    - Medium risk: Scheduled tasks running as SYSTEM (review).

25. **scheduled_tasks_hidden** (Severity: 2)
    - Medium risk: Hidden scheduled tasks.

### System Services

26. **suspicious_services_temp_path** (Severity: 2)
    - Medium risk: Services running from temp/user-writable paths.

27. **services_no_description** (Severity: 2)
    - Medium risk: Services without descriptions (review for legitimacy).

### Process Security

28. **processes_temp_location** (Severity: 2)
    - Medium risk: Processes running from temp/user-writable locations.

29. **processes_systemlike_names_non_system_path** (Severity: 2)
    - Medium risk: System-like process names running outside system directories.

### Encryption & Security Features

30. **bitlocker_not_fully_encrypted** (Severity: 2)
    - Medium risk: BitLocker disabled or incomplete.

### Remote Access

31. **remote_desktop_enabled** (Severity: 2)
    - Medium risk: RDP enabled (review if needed).

### PowerShell Security

32. **powershell_execution_policy_bypass** (Severity: 2)
    - Medium risk: PowerShell execution policy permissive.

33. **powershell_transcription_disabled** (Severity: 2)
    - Medium risk: PowerShell transcription not enabled (reduces visibility).

### System Updates

34. **windows_updates_disabled_policy** (Severity: 2)
    - Medium risk: Automatic updates disabled via policy.

### Sysmon Detection

35. **sysmon_process_create_lolbins** (Severity: 2)
    - Medium risk: Sysmon process creations for common LOLBins.

36. **sysmon_network_connect_suspicious_tools** (Severity: 2)
    - Medium risk: Sysmon network connections initiated by suspicious tools.

37. **sysmon_dns_queries_suspicious** (Severity: 2)
    - Medium risk: Sysmon DNS queries to suspicious domains/TLDs (tune per environment).

38. **sysmon_image_load_from_temp** (Severity: 2)
    - Medium risk: Sysmon DLL/image loads from temp locations.

39. **sysmon_process_access_lsass** (Severity: 1)
    - High risk: Sysmon ProcessAccess to LSASS (credential dumping indicator). Requires Sysmon Event ID 10 enabled.

40. **sysmon_file_create_in_startup_paths** (Severity: 1)
    - High risk: File created in Startup folder paths (persistence).

41. **sysmon_registry_autorun_modifications** (Severity: 1)
    - High risk: Sysmon registry changes in Run/RunOnce persistence keys.

42. **sysmon_wmi_persistence_events** (Severity: 1)
    - High risk: Sysmon WMI persistence events (19/20/21).

### Credential Access & Hardening

43. **lsa_protection_disabled** (Severity: 1)
    - High risk: LSA protection (RunAsPPL) not enabled (helps protect LSASS).

44. **wdigest_use_logoncredential_enabled** (Severity: 1)
    - High risk: WDigest UseLogonCredential enabled can expose cleartext credentials.

---

## Severity Levels

| Level | Value | Description | Example |
|-------|-------|-------------|---------|
| High | 1 | Immediate or significant security risk requiring prompt action | Firewall/Defender disabled, Guest account enabled, public SMB shares, WMI persistence, LSASS access |
| Medium | 2 | Moderate security risk that should be addressed | Public listeners, suspicious processes, weak protocols, Sysmon LOLBins |
| Low | 3 | Default runtime event level (not used in rules; shown as green in dashboard/PDF) | Non-alert background activity |

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
- `tampering` - Log tampering indicators
- `powershell` - PowerShell configuration
- `execution` - Execution policies
- `updates` - Windows updates
- `patch` - Patch management
- `smb` - SMB protocol
- `protocol` - Network protocols
- `tls` - TLS/SSL configuration
- `dns` - DNS configuration
- `proxy` - Proxy settings
- `sysmon` - Sysmon event log detection
- `lolbins` - Living Off The Land Binaries
- `module-load` - DLL/module loading
- `credential-access` - Credential access techniques
- `lsass` - Local Security Authority Subsystem Service
- `exposure` - Security exposure indicators
- `hardening` - Security hardening checks

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
2. **Service Checks**: `Get-Service | Where-Object { ... }` or `Get-CimInstance Win32_Service`
3. **Network Checks**: `Get-NetTCPConnection`, `Get-NetUDPEndpoint`
4. **User Checks**: `Get-LocalUser`, `Get-LocalGroupMember`
5. **Process Checks**: `Get-Process | Where-Object { ... }`
6. **File System Checks**: `Get-ChildItem -Path '...' | Get-Acl`
7. **Scheduled Task Checks**: `Get-ScheduledTask | Where-Object { ... }`
8. **WMI Checks**: `Get-WmiObject -Namespace ... -Class ...`
9. **Sysmon Checks**: `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath ...`
10. **Event Log Checks**: `Get-WinEvent -FilterHashtable @{LogName='...'; Id=...}`

---

## Sample Limit

The `sample_limit` field controls how many examples are included in the alert message. If a rule finds 100 issues but `sample_limit` is 8, only the first 8 will be shown in the alert message to keep it readable.

Typical sample limits:
- **1**: For binary checks (enabled/disabled)
- **5-8**: For lists that may have many entries
- **10**: For comprehensive lists
- **200-300**: For Sysmon event log queries (to scan recent history)

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
7. **Sample Limits**: Set reasonable sample limits (typically 1-10, higher for Sysmon queries)
8. **PowerShell Best Practices**: Use native PowerShell cmdlets when available

---

## Rule Statistics

- **Total Rules**: 44
- **High Severity (1)**: 18 rules
- **Medium Severity (2)**: 26 rules
- **Network Security**: 7 rules
- **Firewall & Antivirus**: 2 rules
- **User & Authentication**: 4 rules
- **Persistence Mechanisms**: 9 rules
- **File Permissions**: 2 rules
- **System Services**: 2 rules
- **Process Security**: 2 rules
- **File Shares**: 1 rule
- **Encryption & Security Features**: 3 rules
- **Remote Access**: 1 rule
- **Audit & Logging**: 2 rules
- **PowerShell Security**: 2 rules
- **System Updates**: 1 rule
- **Protocol Security**: 2 rules
- **Sysmon Detection**: 8 rules
- **Credential Access & Hardening**: 3 rules

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

6. **Sysmon Requirements**: Sysmon detection rules (IDs 35-42) require Microsoft Sysmon to be installed and configured on the Windows host. Some rules require specific Sysmon event IDs to be enabled (e.g., Event ID 10 for `sysmon_process_access_lsass`).

7. **Sysmon Event Log**: Sysmon rules query the `Microsoft-Windows-Sysmon/Operational` event log. Ensure Sysmon is properly configured and the event log is accessible.

---

*This document describes 44 Windows security rules covering network security, system configuration, user management, persistence mechanisms, Sysmon detection, credential access, and compliance checks.*
