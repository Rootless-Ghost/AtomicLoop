"""
AtomicLoop — Embedded Atomic Red Team test library.

Curated tests for 20 common MITRE ATT&CK techniques.
No internet or Atomic Red Team framework installation required.

Test fields:
    technique_id      — MITRE ATT&CK technique ID
    test_number       — 1-based index within the technique
    test_name         — short descriptive name
    description       — what this test simulates and why it's relevant
    executor_type     — powershell | cmd | bash | manual
    command           — command to execute (may contain #{variable} placeholders)
    cleanup_command   — optional cleanup after test (may be None)
    required_permissions — user | administrator
    platforms         — list: windows | linux | macos
    expected_event_ids   — Windows EventIDs this test should produce
    expected_log_sources — log channels to check: Security, Sysmon, System, etc.
    input_arguments   — {name: {description, type, default}}
"""

from __future__ import annotations

ATOMICS: dict[str, dict] = {

    # ── T1059.001 — PowerShell ────────────────────────────────────────────────
    "T1059.001": {
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/001",
        "description": (
            "Adversaries abuse PowerShell commands and scripts for execution. "
            "PowerShell is a powerful interactive command-line interface and scripting "
            "environment included in the Windows operating system."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "PowerShell Encoded Command Execution",
                "description": (
                    "Executes a PowerShell payload via the -EncodedCommand flag. "
                    "Encoding obfuscates the command from simple string-based detections. "
                    "Detections should focus on process creation with -EncodedCommand or -enc flags."
                ),
                "executor_type": "powershell",
                "command": (
                    "$cmd = 'Write-Host \"AtomicTest T1059.001-1: Encoded execution\"';"
                    "$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd);"
                    "$encoded = [Convert]::ToBase64String($bytes);"
                    "powershell.exe -NonInteractive -EncodedCommand $encoded"
                ),
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4104],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
            {
                "test_number": 2,
                "test_name": "PowerShell Download Cradle Simulation",
                "description": (
                    "Simulates a download cradle pattern by calling Invoke-WebRequest to a "
                    "non-routable address. Triggers network connection and script block logging. "
                    "The connection will fail, but the event artifacts are generated."
                ),
                "executor_type": "powershell",
                "command": (
                    "try { "
                    "Invoke-WebRequest -Uri '#{target_url}' -TimeoutSec 2 -ErrorAction Stop "
                    "} catch { "
                    "Write-Host 'AtomicTest T1059.001-2: IWR attempt completed (expected failure)' "
                    "}"
                ),
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 5156, 4104],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "target_url": {
                        "description": "URL to attempt download from (use loopback for safe simulation)",
                        "type": "url",
                        "default": "http://127.0.0.1:65533/atomictest",
                    },
                },
            },
            {
                "test_number": 3,
                "test_name": "PowerShell ExecutionPolicy Bypass",
                "description": (
                    "Launches PowerShell with -ExecutionPolicy Bypass, a common attacker "
                    "technique to circumvent script execution restrictions. "
                    "Detection: process creation with -ExecutionPolicy Bypass argument."
                ),
                "executor_type": "cmd",
                "command": 'powershell.exe -ExecutionPolicy Bypass -NonInteractive -Command "Write-Host \'AtomicTest T1059.001-3: ExecutionPolicy bypassed\'"',
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4104],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1059.003 — Windows Command Shell ────────────────────────────────────
    "T1059.003": {
        "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/003",
        "description": (
            "Adversaries abuse the Windows command shell (cmd.exe) to execute commands. "
            "The Windows command shell is the primary command prompt on Windows systems. "
            "The shell can be used to run executables, batch files, and other scripts."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Command Execution via cmd.exe",
                "description": (
                    "Executes reconnaissance commands via cmd.exe. "
                    "Captures whoami, hostname, and ipconfig output. "
                    "Detection: cmd.exe spawning with discovery-related child commands."
                ),
                "executor_type": "cmd",
                "command": "cmd.exe /c whoami && hostname && ipconfig /all",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
            {
                "test_number": 2,
                "test_name": "Batch Script Execution via cmd",
                "description": (
                    "Creates and executes a batch file, a common attacker pattern. "
                    "The script runs basic enumeration then deletes itself. "
                    "Detection: .bat file creation followed by cmd.exe execution."
                ),
                "executor_type": "cmd",
                "command": (
                    'echo @echo off > %TEMP%\\atomic_t1059003.bat && '
                    'echo echo AtomicTest T1059.003-2 >> %TEMP%\\atomic_t1059003.bat && '
                    'echo whoami >> %TEMP%\\atomic_t1059003.bat && '
                    'cmd.exe /c %TEMP%\\atomic_t1059003.bat'
                ),
                "cleanup_command": "del /f %TEMP%\\atomic_t1059003.bat 2>NUL",
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 11],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1055 — Process Injection ─────────────────────────────────────────────
    "T1055": {
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1055",
        "description": (
            "Adversaries inject code into processes to evade process-based defenses "
            "and possibly elevate privileges. Injecting code into a legitimate process "
            "may allow access to the process's memory, system resources, and elevated privileges."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Remote Thread Creation via PowerShell (Simulation)",
                "description": (
                    "Simulates process injection reconnaissance by using PowerShell to "
                    "enumerate target process handles — a precursor to injection. "
                    "Uses Get-Process to gather PIDs without performing actual injection. "
                    "Detection: PowerShell accessing process handles (Sysmon EID 10)."
                ),
                "executor_type": "powershell",
                "command": (
                    "$target = Get-Process -Name '#{target_process}' -ErrorAction SilentlyContinue | "
                    "Select-Object -First 1;"
                    "if ($target) {"
                    "Write-Host ('AtomicTest T1055-1: Target process found PID=' + $target.Id + ' Name=' + $target.Name);"
                    "} else {"
                    "Write-Host 'AtomicTest T1055-1: Target process not running (safe simulation complete)';"
                    "}"
                ),
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 10],
                "expected_log_sources": ["Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "target_process": {
                        "description": "Name of target process (without .exe)",
                        "type": "string",
                        "default": "notepad",
                    },
                },
            },
        ],
    },

    # ── T1003 — OS Credential Dumping ────────────────────────────────────────
    "T1003": {
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1003",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login and "
            "credential material. Credentials can then be used to perform lateral movement "
            "and access restricted information."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "LSASS Memory Dump via comsvcs.dll",
                "description": (
                    "Dumps LSASS memory using comsvcs.dll MiniDump export — a technique "
                    "commonly used by attackers to extract credentials. "
                    "Requires ADMINISTRATOR privileges. "
                    "Detection: rundll32.exe calling comsvcs.dll with MiniDump, or "
                    "OpenProcess on lsass.exe (Sysmon EID 10)."
                ),
                "executor_type": "powershell",
                "command": (
                    "$lsass = Get-Process lsass;"
                    "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "
                    "$($lsass.Id) #{dump_path} full"
                ),
                "cleanup_command": "Remove-Item -Path #{dump_path} -Force -ErrorAction SilentlyContinue",
                "required_permissions": "administrator",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 10],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "dump_path": {
                        "description": "Output path for the LSASS dump file",
                        "type": "path",
                        "default": "C:\\Windows\\Temp\\lsass_atomic.dmp",
                    },
                },
            },
        ],
    },

    # ── T1082 — System Information Discovery ─────────────────────────────────
    "T1082": {
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1082",
        "description": (
            "An adversary may attempt to get detailed information about the operating "
            "system and hardware, including version, patches, hotfixes, service packs, and "
            "architecture. This information may be used to shape follow-on behaviors."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "System Information Enumeration via systeminfo",
                "description": (
                    "Runs systeminfo.exe to collect OS version, hotfixes, hostname, "
                    "and domain information. A very common attacker enumeration step. "
                    "Detection: process creation for systeminfo.exe."
                ),
                "executor_type": "cmd",
                "command": "systeminfo",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
            {
                "test_number": 2,
                "test_name": "Environment Variable Enumeration",
                "description": (
                    "Dumps all environment variables via set command. "
                    "Reveals usernames, paths, domain names, and other config. "
                    "Detection: cmd.exe running 'set' or accessing environment variables."
                ),
                "executor_type": "cmd",
                "command": "set && ver && echo %USERNAME% %USERDOMAIN% %COMPUTERNAME%",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1083 — File and Directory Discovery ─────────────────────────────────
    "T1083": {
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1083",
        "description": (
            "Adversaries enumerate files and directories or search in specific locations "
            "for certain information within a file system. This activity is often performed "
            "during initial access or once inside a target environment."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "File Discovery via dir Command",
                "description": (
                    "Recursively lists files in the user profile directory looking for "
                    "interesting file types (.txt, .docx, .kdbx, .key). "
                    "Detection: cmd.exe running dir with /s /b flags, or mass file access events."
                ),
                "executor_type": "cmd",
                "command": "dir /s /b #{search_path} 2>NUL | findstr /i #{extensions}",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "search_path": {
                        "description": "Root path to search",
                        "type": "path",
                        "default": "%USERPROFILE%",
                    },
                    "extensions": {
                        "description": "File extensions to search for",
                        "type": "string",
                        "default": "\\.txt\\ \\|\\ \\.docx\\ \\|\\ \\.kdbx",
                    },
                },
            },
        ],
    },

    # ── T1057 — Process Discovery ─────────────────────────────────────────────
    "T1057": {
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1057",
        "description": (
            "Adversaries may attempt to get information about running processes on a system. "
            "Information obtained could be used to gain an understanding of common software "
            "running on systems within the network and identify security tooling."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Process Enumeration via tasklist",
                "description": (
                    "Lists all running processes with verbose output via tasklist.exe. "
                    "Attackers use this to identify security products, target processes for "
                    "injection, and map the environment. "
                    "Detection: process creation for tasklist.exe."
                ),
                "executor_type": "cmd",
                "command": "tasklist /v /fo list",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1069 — Permission Groups Discovery ──────────────────────────────────
    "T1069": {
        "technique_name": "Permission Groups Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1069",
        "description": (
            "Adversaries may attempt to find local system or domain-level groups and "
            "permissions settings. This information can help adversaries determine which "
            "user accounts and groups are available and what permissions they have."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Local Groups and Membership Enumeration",
                "description": (
                    "Enumerates local groups and Administrators group membership. "
                    "A critical attacker step to identify privileged accounts. "
                    "Detection: net.exe with localgroup argument."
                ),
                "executor_type": "cmd",
                "command": "net localgroup && net localgroup Administrators",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1021.001 — Remote Services: RDP ──────────────────────────────────────
    "T1021.001": {
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/001",
        "description": (
            "Adversaries use Valid Accounts to log into a computer using the Remote Desktop "
            "Protocol. They may also use RDP in conjunction with the Accessibility Features "
            "technique for Persistence."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Enable RDP via Registry Modification",
                "description": (
                    "Enables Remote Desktop Protocol by modifying the Terminal Services registry "
                    "key. This is a common attacker technique to enable persistent remote access. "
                    "Requires ADMINISTRATOR. "
                    "Detection: registry modification of fDenyTSConnections key (EID 4657/13)."
                ),
                "executor_type": "cmd",
                "command": (
                    "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" "
                    "/v fDenyTSConnections /t REG_DWORD /d 0 /f"
                ),
                "cleanup_command": (
                    "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" "
                    "/v fDenyTSConnections /t REG_DWORD /d 1 /f"
                ),
                "required_permissions": "administrator",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4657, 13],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1021.002 — Remote Services: SMB ─────────────────────────────────────
    "T1021.002": {
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/002",
        "description": (
            "Adversaries may use Valid Accounts to interact with a remote network share "
            "using Server Message Block. The adversary may then perform actions as the "
            "logged-on user."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "SMB Share Enumeration via net view",
                "description": (
                    "Enumerates accessible SMB shares on the local and network hosts. "
                    "Attackers use this to find file shares for lateral movement or data staging. "
                    "Detection: net.exe spawning with view/use arguments (EID 4688, 5140)."
                ),
                "executor_type": "cmd",
                "command": "net view \\\\#{target_host} 2>NUL & net share",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 5140],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "target_host": {
                        "description": "Target host to enumerate shares on",
                        "type": "string",
                        "default": "localhost",
                    },
                },
            },
        ],
    },

    # ── T1547.001 — Boot/Autostart: Registry Run Keys ─────────────────────────
    "T1547.001": {
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1547/001",
        "description": (
            "Adversaries may achieve persistence by adding a program to a startup folder "
            "or referencing it with a Registry run key. Programs referenced by run keys in "
            "the Registry are run when a user logs in or the system boots."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Persistence via HKCU Run Key",
                "description": (
                    "Adds an entry to the HKCU Run registry key to achieve user-level persistence. "
                    "This is one of the most common attacker persistence mechanisms. "
                    "Detection: registry modification of HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                    "(EID 4657/13)."
                ),
                "executor_type": "cmd",
                "command": (
                    "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
                    "/v #{reg_key_name} /t REG_SZ "
                    "/d \"#{payload_path}\" /f"
                ),
                "cleanup_command": (
                    "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
                    "/v #{reg_key_name} /f 2>NUL"
                ),
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4657, 13],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "reg_key_name": {
                        "description": "Registry value name for the Run key entry",
                        "type": "string",
                        "default": "AtomicTest_T1547001",
                    },
                    "payload_path": {
                        "description": "Path to the payload executable",
                        "type": "path",
                        "default": "C:\\Windows\\System32\\calc.exe",
                    },
                },
            },
        ],
    },

    # ── T1053.005 — Scheduled Task ────────────────────────────────────────────
    "T1053.005": {
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1053/005",
        "description": (
            "Adversaries may abuse Windows Task Scheduler to perform task scheduling for "
            "initial or recurring execution of malicious code. Attackers can use the schtasks "
            "utility to schedule a program to execute when a user logs in or the system starts."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Scheduled Task Creation via schtasks",
                "description": (
                    "Creates a scheduled task that runs a payload at system logon. "
                    "A very common attacker persistence technique. "
                    "Detection: schtasks.exe /create, EID 4698 (task created)."
                ),
                "executor_type": "cmd",
                "command": (
                    "schtasks /Create /SC ONLOGON /TN #{task_name} "
                    "/TR \"#{payload_path}\" /RU SYSTEM /F"
                ),
                "cleanup_command": "schtasks /Delete /TN #{task_name} /F 2>NUL",
                "required_permissions": "administrator",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4698],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "task_name": {
                        "description": "Scheduled task name",
                        "type": "string",
                        "default": "AtomicTest_T1053005",
                    },
                    "payload_path": {
                        "description": "Path to the payload executable",
                        "type": "path",
                        "default": "C:\\Windows\\System32\\calc.exe",
                    },
                },
            },
        ],
    },

    # ── T1070.001 — Clear Windows Event Logs ─────────────────────────────────
    "T1070.001": {
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1070/001",
        "description": (
            "Adversaries may clear Windows Event Logs to hide their activities. "
            "The event logs capture information about system activity, and clearing them "
            "can remove evidence of malicious activity."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Clear Windows Event Log via wevtutil",
                "description": (
                    "Clears a specified Windows event log channel using wevtutil.exe. "
                    "Attackers clear logs to cover their tracks after an intrusion. "
                    "Ironically, EID 1102 (Security log cleared) or 104 (System log cleared) "
                    "fires when this occurs. Requires ADMINISTRATOR. "
                    "Detection: wevtutil.exe cl argument, EID 1102."
                ),
                "executor_type": "cmd",
                "command": "wevtutil cl #{log_name}",
                "cleanup_command": None,
                "required_permissions": "administrator",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 1102, 104],
                "expected_log_sources": ["Security", "System"],
                "input_arguments": {
                    "log_name": {
                        "description": "Event log channel to clear",
                        "type": "string",
                        "default": "Microsoft-Windows-PowerShell/Operational",
                    },
                },
            },
        ],
    },

    # ── T1112 — Modify Registry ───────────────────────────────────────────────
    "T1112": {
        "technique_name": "Modify Registry",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1112",
        "description": (
            "Adversaries may interact with the Windows Registry to hide configuration "
            "information within Registry keys, remove information as part of cleaning up, "
            "or as part of other techniques to aid in persistence and execution."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Registry Modification via reg.exe",
                "description": (
                    "Creates a registry key/value under HKCU to store data or configuration. "
                    "Attackers use the registry to store payloads, C2 config, and persist data. "
                    "Detection: reg.exe with add argument, or Sysmon EID 12/13 registry events."
                ),
                "executor_type": "cmd",
                "command": (
                    "reg add \"HKCU\\Software\\AtomicTest\" /v #{value_name} "
                    "/t REG_SZ /d \"#{value_data}\" /f"
                ),
                "cleanup_command": "reg delete \"HKCU\\Software\\AtomicTest\" /f 2>NUL",
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4657, 12, 13],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "value_name": {
                        "description": "Registry value name",
                        "type": "string",
                        "default": "AtomicTest_T1112",
                    },
                    "value_data": {
                        "description": "Data to store in the registry value",
                        "type": "string",
                        "default": "AtomicLoop detection validation",
                    },
                },
            },
        ],
    },

    # ── T1027 — Obfuscated Files or Information ───────────────────────────────
    "T1027": {
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1027",
        "description": (
            "Adversaries may attempt to make an executable or file difficult to discover "
            "or analyze by encrypting, encoding, or otherwise obfuscating its contents. "
            "PowerShell -EncodedCommand is one of the most common forms."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Base64 Encoded PowerShell Payload",
                "description": (
                    "Encodes a PowerShell command in Base64 and executes it, simulating "
                    "attacker obfuscation. The encoded payload is clearly detectable via "
                    "PowerShell Script Block Logging (EID 4104). "
                    "Detection: -EncodedCommand flag in process args, EID 4104 script blocks."
                ),
                "executor_type": "powershell",
                "command": (
                    "$payload = '#{plaintext_command}';"
                    "$bytes = [System.Text.Encoding]::Unicode.GetBytes($payload);"
                    "$b64 = [Convert]::ToBase64String($bytes);"
                    "Write-Host ('AtomicTest T1027-1 encoded: ' + $b64.Substring(0,20) + '...');"
                    "powershell.exe -NonInteractive -EncodedCommand $b64"
                ),
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 4104],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "plaintext_command": {
                        "description": "Command to encode and execute",
                        "type": "string",
                        "default": "Write-Host 'AtomicTest T1027 obfuscation test'",
                    },
                },
            },
        ],
    },

    # ── T1562.001 — Impair Defenses: Disable or Modify Tools ──────────────────
    "T1562.001": {
        "technique_name": "Impair Defenses: Disable or Modify Security Tools",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1562/001",
        "description": (
            "Adversaries may modify and/or disable security tools to avoid possible "
            "detection of their malware/tools and activities. This may take the form of "
            "disabling security software or script blocking."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Disable Windows Defender Real-Time Protection",
                "description": (
                    "Disables Windows Defender real-time monitoring via PowerShell cmdlet. "
                    "A very common post-exploitation step to reduce detection. "
                    "Requires ADMINISTRATOR. "
                    "Detection: Set-MpPreference -DisableRealtimeMonitoring True, EID 5001 "
                    "(Windows Defender disabled)."
                ),
                "executor_type": "powershell",
                "command": "Set-MpPreference -DisableRealtimeMonitoring $true",
                "cleanup_command": "Set-MpPreference -DisableRealtimeMonitoring $false",
                "required_permissions": "administrator",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 5001, 5010],
                "expected_log_sources": ["Security", "Microsoft-Windows-Windows Defender/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1566.001 — Phishing: Spearphishing Attachment ────────────────────────
    "T1566.001": {
        "technique_name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/001",
        "description": (
            "Adversaries may send spearphishing emails with a malicious attachment in an "
            "attempt to gain access to victim systems. Spearphishing attachments are different "
            "from other forms of spearphishing in that they employ malware attached to an email."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Malicious HTA Execution via mshta.exe",
                "description": (
                    "Simulates a phishing attachment that drops and executes an HTA file via "
                    "mshta.exe — a common malicious attachment execution technique. "
                    "The HTA contains benign JavaScript that opens a message box. "
                    "Detection: mshta.exe spawning from email client, EID 4688 for mshta."
                ),
                "executor_type": "cmd",
                "command": (
                    'echo ^<html^>^<head^>^<HTA:APPLICATION^>^</head^>^<body^>'
                    '^<script language="JScript"^>alert("AtomicTest T1566.001-1");close();'
                    '^</script^>^</body^>^</html^> > %TEMP%\\atomic_t1566.hta && '
                    "mshta.exe %TEMP%\\atomic_t1566.hta"
                ),
                "cleanup_command": "del /f %TEMP%\\atomic_t1566.hta 2>NUL",
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688, 1, 11],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1078 — Valid Accounts ────────────────────────────────────────────────
    "T1078": {
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1078",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a means "
            "of gaining Initial Access, Persistence, Privilege Escalation, or Defense "
            "Evasion. Compromised credentials may be used to bypass access controls."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Local Account Enumeration via net user",
                "description": (
                    "Enumerates all local user accounts using net.exe. "
                    "Attackers enumerate accounts to identify valid targets for credential "
                    "stuffing or privilege escalation. "
                    "Detection: net.exe user argument, process creation EID 4688."
                ),
                "executor_type": "cmd",
                "command": "net user && whoami /all",
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4688],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {},
            },
        ],
    },

    # ── T1110.001 — Brute Force: Password Guessing ────────────────────────────
    "T1110.001": {
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001",
        "description": (
            "Adversaries with no prior knowledge of legitimate credentials within the "
            "system may guess passwords to attempt to gain access to accounts. "
            "Without knowledge of the password, an adversary may opt to systematically "
            "guess the password using a repetitive or iterative mechanism."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "Local Account Password Guessing via net use",
                "description": (
                    "Simulates a password guessing attack by attempting three authentication "
                    "attempts against a local share with a non-existent user. "
                    "Generates EID 4625 (failed logon) events for each attempt. "
                    "Detection: multiple EID 4625 events with LogonType 3 from the same source."
                ),
                "executor_type": "cmd",
                "command": (
                    "net use \\\\localhost\\IPC$ /user:#{target_user} #{password1} 2>NUL & "
                    "net use \\\\localhost\\IPC$ /user:#{target_user} #{password2} 2>NUL & "
                    "net use \\\\localhost\\IPC$ /user:#{target_user} #{password3} 2>NUL"
                ),
                "cleanup_command": "net use \\\\localhost\\IPC$ /delete 2>NUL",
                "required_permissions": "user",
                "platforms": ["windows"],
                "expected_event_ids": [4625, 4776],
                "expected_log_sources": ["Security"],
                "input_arguments": {
                    "target_user": {
                        "description": "Username to attempt guessing (should be non-existent)",
                        "type": "string",
                        "default": "atomictest_nouser",
                    },
                    "password1": {
                        "description": "First password guess",
                        "type": "string",
                        "default": "Password1!",
                    },
                    "password2": {
                        "description": "Second password guess",
                        "type": "string",
                        "default": "Summer2024!",
                    },
                    "password3": {
                        "description": "Third password guess",
                        "type": "string",
                        "default": "Winter2024!",
                    },
                },
            },
        ],
    },

    # ── T1190 — Exploit Public-Facing Application ─────────────────────────────
    "T1190": {
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1190",
        "description": (
            "Adversaries may attempt to exploit a weakness in an Internet-facing host or "
            "system to initially access a network. The weakness in the system can be a "
            "software bug, a temporary glitch, or a misconfiguration."
        ),
        "tests": [
            {
                "test_number": 1,
                "test_name": "HTTP Parameter Fuzzing via curl (Simulated)",
                "description": (
                    "Simulates web application exploitation reconnaissance by sending "
                    "malformed HTTP requests to a local target. Uses benign payloads to "
                    "test detection of suspicious URI patterns. "
                    "Detection: web server logs showing SQLi/XSS patterns, IDS signatures."
                ),
                "executor_type": "powershell",
                "command": (
                    "$uri = '#{target_url}';"
                    "$payloads = @(\"?id=1' OR 1=1--\", \"?q=<script>alert(1)</script>\", \"?path=../../../etc/passwd\");"
                    "foreach ($p in $payloads) {"
                    "try {"
                    "Invoke-WebRequest -Uri ($uri + $p) -TimeoutSec 2 -ErrorAction Stop;"
                    "} catch {"
                    "Write-Host ('AtomicTest T1190-1 sent payload: ' + $p);"
                    "}"
                    "}"
                ),
                "cleanup_command": None,
                "required_permissions": "user",
                "platforms": ["windows", "linux"],
                "expected_event_ids": [4688, 5156],
                "expected_log_sources": ["Security", "Microsoft-Windows-Sysmon/Operational"],
                "input_arguments": {
                    "target_url": {
                        "description": "Base URL of the target application (use localhost for safe testing)",
                        "type": "url",
                        "default": "http://127.0.0.1:8080",
                    },
                },
            },
        ],
    },
}


# ── Public API ────────────────────────────────────────────────────────────────

def get_all_techniques() -> list[dict]:
    """Return summary list of all embedded techniques with test counts."""
    result = []
    for tid, data in ATOMICS.items():
        result.append({
            "technique_id":   tid,
            "technique_name": data["technique_name"],
            "tactic":         data["tactic"],
            "mitre_url":      data.get("mitre_url", ""),
            "description":    data.get("description", ""),
            "test_count":     len(data["tests"]),
        })
    result.sort(key=lambda x: x["technique_id"])
    return result


def get_technique(technique_id: str) -> dict | None:
    """Return full data for a technique including all tests."""
    tid = technique_id.upper()
    data = ATOMICS.get(tid)
    if data is None:
        return None
    return {
        "technique_id":   tid,
        "technique_name": data["technique_name"],
        "tactic":         data["tactic"],
        "mitre_url":      data.get("mitre_url", ""),
        "description":    data.get("description", ""),
        "tests":          data["tests"],
        "test_count":     len(data["tests"]),
    }


def get_test(technique_id: str, test_number: int) -> dict | None:
    """Return a single test definition."""
    tech = get_technique(technique_id)
    if tech is None:
        return None
    for test in tech["tests"]:
        if test["test_number"] == test_number:
            return {**test, "technique_id": technique_id,
                    "technique_name": tech["technique_name"],
                    "tactic": tech["tactic"]}
    return None


def list_techniques_by_tactic() -> dict[str, list[str]]:
    """Group technique IDs by tactic name."""
    by_tactic: dict[str, list[str]] = {}
    for tid, data in ATOMICS.items():
        tactic = data.get("tactic", "Other")
        by_tactic.setdefault(tactic, []).append(tid)
    for tactic in by_tactic:
        by_tactic[tactic].sort()
    return by_tactic
