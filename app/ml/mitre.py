"""
MITRE ATT&CK Enterprise — static registry (100 techniques) and deterministic mapper.
No network I/O. Tactic IDs follow the ForensIQ distribution table (TA0001-TA0014).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("forensiq.mitre")

TECHNIQUE_ROWS: list[tuple[str, str, str, str, str, list[str], list[str]]] = [
    # Reconnaissance (5) — TA0001
    ("T1595", "Active Scanning", "Reconnaissance", "TA0001", "Adversaries scan victim infrastructure for information.", ["network-traffic"], ["scan", "port_scan", "nmap", "masscan", "vuln_scan", "host_discovery"]),
    ("T1592", "Gather Victim Host Information", "Reconnaissance", "TA0001", "Gather details about victim hosts before targeting.", ["endpoint"], ["hostname", "os_version", "patch", "host_info", "gather_host"]),
    ("T1589", "Gather Victim Identity Information", "Reconnaissance", "TA0001", "Collect identities for targeting.", ["person", "identity"], ["email_address", "employee", "username_list", "identity", "osint"]),
    ("T1590", "Gather Victim Network Information", "Reconnaissance", "TA0001", "Map victim networks and services.", ["network"], ["subnet", "dns_lookup", "whois", "dns_enum", "topology"]),
    ("T1598", "Phishing for Information", "Reconnaissance", "TA0001", "Use phishing to elicit sensitive information.", ["email"], ["phish_info", "credential_harvest", "pretext", "survey"]),
    # Resource Development (3) — TA0002
    ("T1583", "Acquire Infrastructure", "Resource Development", "TA0002", "Buy or compromise infrastructure for operations.", ["infrastructure"], ["domain_buy", "vps", "bulletproof", "infrastructure"]),
    ("T1588", "Obtain Capabilities", "Resource Development", "TA0002", "Acquire malware, exploits, or certs.", ["malware"], ["malware_kit", "buy_exploit", "crypter", "capabilities"]),
    ("T1608", "Stage Capabilities", "Resource Development", "TA0002", "Upload or stage tools on infrastructure.", ["infrastructure"], ["stage", "upload_payload", "dropper_host", "prep"]),
    # Initial Access (7) — TA0003
    ("T1566", "Phishing", "Initial Access", "TA0003", "Deliver malicious payloads via phishing.", ["email"], ["phish", "email", "attachment", "link", "spear", "PHISHING_CLICK"]),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0003", "Exploit internet-facing apps for initial access.", ["application"], ["exploit", "sqli", "rce", "web_shell", "cve"]),
    ("T1133", "External Remote Services", "Initial Access", "TA0003", "Leverage VPN/RDP/email services for access.", ["network"], ["vpn_login", "rdp_gateway", "external_remote"]),
    ("T1078", "Valid Accounts", "Initial Access", "TA0003", "Use stolen or valid credentials.", ["account"], ["valid_account", "stolen_credentials", "legit_login", "CLOUD_LOGIN"]),
    ("T1091", "Replication Through Removable Media", "Initial Access", "TA0003", "Propagate via USB/removable media.", ["removable-media"], ["usb", "autorun", "removable_media"]),
    ("T1189", "Drive-by Compromise", "Initial Access", "TA0003", "Compromise via malicious web content.", ["web"], ["drive-by", "watering_hole", "malvertising"]),
    ("T1195", "Supply Chain Compromise", "Initial Access", "TA0003", "Compromise upstream vendor for access.", ["supply-chain"], ["vendor", "supply_chain", "signed_binary"]),
    # Execution (8) — TA0004
    ("T1059", "Command and Scripting Interpreter", "Execution", "TA0004", "Execute commands via interpreters.", ["process"], ["powershell", "bash", "python", "cmd", "script", "PROCESS_CREATE"]),
    ("T1053", "Scheduled Task/Job", "Execution", "TA0004", "Run tasks on schedules for execution.", ["schedule"], ["cron", "at", "task_scheduler", "SCHEDULED_TASK", "schtasks"]),
    ("T1047", "Windows Management Instrumentation", "Execution", "TA0004", "Execute via WMI.", ["wmi"], ["wmi", "wmiprvse", "invoke-wmi"]),
    ("T1204", "User Execution", "Execution", "TA0004", "Rely on user running malicious object.", ["process"], ["double_click", "user_open", "macro_enable"]),
    ("T1106", "Native API", "Execution", "TA0004", "Call OS APIs for execution primitives.", ["api"], ["ntdll", "syscall", "native_api"]),
    ("T1129", "Shared Modules", "Execution", "TA0004", "Load shared modules for code execution.", ["module"], ["dll_load", "shared_module", "rundll32"]),
    ("T1072", "Software Deployment Tools", "Execution", "TA0004", "Abuse enterprise deployment tools.", ["software"], ["sccm", "puppet", "deploy_tool"]),
    ("T1569", "System Services", "Execution", "TA0004", "Abuse system services to run code.", ["service"], ["service_start", "launchctl", "systemd_run"]),
    # Persistence (9) — TA0005
    ("T1547", "Boot or Logon Autostart Execution", "Persistence", "TA0005", "Establish autostart on boot or logon.", ["registry", "file"], ["run_key", "startup_folder", "autostart", "logon_script"]),
    ("T1543", "Create or Modify System Process", "Persistence", "TA0005", "Install/alter services or daemons.", ["service"], ["systemd", "service_install", "create_service", "FILE_WRITE", "/etc/systemd"]),
    ("T1546", "Event Triggered Execution", "Persistence", "TA0005", "Execute on ETW/trigger conditions.", ["event"], ["wmi_event", "screensaver", "netsh_helper"]),
    ("T1574", "Hijack Execution Flow", "Persistence", "TA0005", "Hijack execution through search order or path.", ["path"], ["dll_search", "path_hijack", "com_hijack"]),
    ("T1525", "Implant Internal Image", "Persistence", "TA0005", "Implant malicious container or VM image.", ["container"], ["image_tamper", "container_image"]),
    ("T1137", "Office Application Startup", "Persistence", "TA0005", "Use Office startup locations.", ["office"], ["word_startup", "excel_addin", "office_template"]),
    ("T1542", "Pre-OS Boot", "Persistence", "TA0005", "Modify boot process before OS loads.", ["firmware"], ["bootkit", "uefi", "mbr"]),
    ("T1053.005", "Scheduled Task", "Persistence", "TA0005", "Scheduled task for persistence.", ["schedule"], ["scheduled_task", "/etc/cron", "cron.d"]),
    ("T1505", "Server Software Component", "Persistence", "TA0005", "Modify server software for persistence.", ["application"], ["iis_module", "apache_module", "web_shell_persist"]),
    # Privilege Escalation (8) — TA0006
    ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "TA0006", "Bypass UAC/sudo mechanisms.", ["authorization"], ["sudo", "uac_bypass", "SUDO_EXEC", "runas"]),
    ("T1134", "Access Token Manipulation", "Privilege Escalation", "TA0006", "Manipulate tokens for elevated context.", ["token"], ["duplicate_token", "impersonation", "TOKEN_IMPERSONATE"]),
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0006", "Exploit OS/app bugs to escalate.", ["vulnerability"], ["local_exploit", "priv_esc_exploit"]),
    ("T1055", "Process Injection", "Privilege Escalation", "TA0006", "Inject code into processes.", ["process"], ["inject", "dll_injection", "PROCESS_INJECT", "PROCESS_HOLLOW"]),
    ("T1078.003", "Local Accounts", "Privilege Escalation", "TA0006", "Abuse local account for escalation.", ["account"], ["local_admin", "guest_enable"]),
    ("T1611", "Escape to Host", "Privilege Escalation", "TA0006", "Break out of container to host.", ["container"], ["docker_escape", "container_breakout"]),
    ("T1484", "Domain Policy Modification", "Privilege Escalation", "TA0006", "Change domain policy for elevated access.", ["active-directory"], ["gpo_edit", "domain_policy"]),
    ("T1098", "Account Manipulation", "Privilege Escalation", "TA0006", "Modify accounts for persistence/escalation.", ["account"], ["add_to_admin", "sid_history", "account_mod"]),
    # Defense Evasion (12) — TA0007
    ("T1070", "Indicator Removal", "Defense Evasion", "TA0007", "Clear logs/evidence to hide activity.", ["logs"], ["CLEAR_LOGS", "clear_logs", "eventlog_clear", "rm_-rf_/var/log"]),
    ("T1562", "Impair Defenses", "Defense Evasion", "TA0007", "Disable security tools.", ["configuration"], ["DISABLE_AUDIT", "defender_off", "firewall_disable"]),
    ("T1036", "Masquerading", "Defense Evasion", "TA0007", "Disguise malicious artifacts.", ["file", "process"], ["rename_binary", "trusted_path", "masquerade"]),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion", "TA0007", "Obfuscate payloads to evade detection.", ["file"], ["xor_encode", "packer", "encrypted_payload"]),
    ("T1218", "System Binary Proxy Execution", "Defense Evasion", "TA0007", "Abuse signed binaries for execution.", ["binary"], ["regsvr32", "mshta", "lolbin"]),
    ("T1055.012", "Process Hollowing", "Defense Evasion", "TA0007", "Hollow a process to execute code.", ["process"], ["PROCESS_HOLLOW", "hollowing", "suspended_process"]),
    ("T1112", "Modify Registry", "Defense Evasion", "TA0007", "Alter registry for evasion.", ["registry"], ["REGISTRY_WRITE", "reg_add", "persistence_reg"]),
    ("T1564", "Hide Artifacts", "Defense Evasion", "TA0007", "Conceal presence on system.", ["file"], ["hidden_file", "ads", "hidden_volume"]),
    ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion", "TA0007", "Detect VM/sandbox to evade.", ["environment"], ["vm_check", "sandbox_detect"]),
    ("T1620", "Reflective Code Loading", "Defense Evasion", "TA0007", "Load code reflectively without file.", ["memory"], ["reflective_dll", "manual_map"]),
    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "TA0007", "Decode prior to execution.", ["file"], ["base64_decode", "decrypt_stage"]),
    ("T1202", "Indirect Command Execution", "Defense Evasion", "TA0007", "Execute via indirect chaining.", ["command"], ["forfiles", "indirect_exec"]),
    # Credential Access (9) — TA0008
    ("T1110", "Brute Force", "Credential Access", "TA0008", "Guess credentials by repeated attempts.", ["authentication"], ["SSH_AUTH_FAIL", "AUTH_FAIL", "BRUTE_FORCE", "login_fail"]),
    ("T1003", "OS Credential Dumping", "Credential Access", "TA0008", "Dump credentials from OS.", ["credential"], ["LSASS_ACCESS", "mimikatz", "sam_dump", "lsass"]),
    ("T1056", "Input Capture", "Credential Access", "TA0008", "Capture user input for secrets.", ["input"], ["keylogger", "clipboard_hook", "KEYLOG_START"]),
    ("T1539", "Steal Web Session Cookie", "Credential Access", "TA0008", "Harvest web sessions.", ["browser"], ["cookie_theft", "session_token"]),
    ("T1552", "Unsecured Credentials", "Credential Access", "TA0008", "Find credentials in insecure storage.", ["file"], ["plaintext_password", ".env", "config_password"]),
    ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access", "TA0008", "Abuse Kerberos tickets.", ["kerberos"], ["KERBEROS_REQUEST", "gold_ticket", "pass_the_ticket"]),
    ("T1111", "Multi-Factor Authentication Interception", "Credential Access", "TA0008", "Intercept MFA approvals.", ["mfa"], ["mfa_phish", "push_bomb"]),
    ("T1649", "Steal or Forge Authentication Certificates", "Credential Access", "TA0008", "Abuse PKI auth material.", ["certificate"], ["adcs", "pfx_theft"]),
    ("T1187", "Forced Authentication", "Credential Access", "TA0008", "Force auth to capture hash.", ["network"], ["responder", "llmnr_poison", "wpad"]),
    # Discovery (8) — TA0009
    ("T1082", "System Information Discovery", "Discovery", "TA0009", "Collect OS/hardware info.", ["endpoint"], ["systeminfo", "uname", "host_info"]),
    ("T1083", "File and Directory Discovery", "Discovery", "TA0009", "Enumerate files and paths.", ["file"], ["dir_list", "find_cmd", "file_discovery"]),
    ("T1018", "Remote System Discovery", "Discovery", "TA0009", "Find remote systems on network.", ["network"], ["ping_sweep", "net_view", "remote_discovery"]),
    ("T1046", "Network Service Discovery", "Discovery", "TA0009", "Scan for network services.", ["network"], ["NET_SCAN", "nmap_service", "port_scan", "discovery"]),
    ("T1057", "Process Discovery", "Discovery", "TA0009", "Enumerate running processes.", ["process"], ["tasklist", "ps_aux", "process_list"]),
    ("T1087", "Account Discovery", "Discovery", "TA0009", "Enumerate accounts and groups.", ["account"], ["LDAP_QUERY", "net_user", "enum_users"]),
    ("T1135", "Network Share Discovery", "Discovery", "TA0009", "Find network shares.", ["network"], ["net_share", "smb_enum_share"]),
    ("T1124", "System Time Discovery", "Discovery", "TA0009", "Query system time/timezone.", ["time"], ["w32tm", "timedatectl"]),
    # Lateral Movement (7) — TA0010
    ("T1021", "Remote Services", "Lateral Movement", "TA0010", "Use remote services for movement.", ["network"], ["SMB_CONNECT", "RDP_CONNECT", "ssh_remote", "winrm"]),
    ("T1210", "Exploitation of Remote Services", "Lateral Movement", "TA0010", "Exploit remote services to move.", ["network"], ["exploit_rdp", "remote_exploit"]),
    ("T1534", "Internal Spearphishing", "Lateral Movement", "TA0010", "Phish internal users for lateral access.", ["email"], ["internal_phish", "spear_internal"]),
    ("T1570", "Lateral Tool Transfer", "Lateral Movement", "TA0010", "Copy tools between hosts.", ["file"], ["SMB_WRITE", "copy_admin$", "psexec_copy"]),
    ("T1080", "Taint Shared Content", "Lateral Movement", "TA0010", "Poison shared resources.", ["file"], ["shared_link", "tainted_doc"]),
    ("T1563", "Remote Service Session Hijacking", "Lateral Movement", "TA0010", "Hijack existing remote session.", ["session"], ["rdp_hijack", "session_steal"]),
    ("T1550", "Use Alternate Authentication Material", "Lateral Movement", "TA0010", "Use hashes/tickets instead of password.", ["credential"], ["pass_the_hash", "PTH", "golden_ticket"]),
    # Collection (6) — TA0011
    ("T1560", "Archive Collected Data", "Collection", "TA0011", "Archive data before exfil.", ["archive"], ["ARCHIVE_CREATE", "zip", "tar", "compress_staged"]),
    ("T1115", "Clipboard Data", "Collection", "TA0011", "Capture clipboard contents.", ["clipboard"], ["CLIPBOARD_ACCESS", "clipboard", "ClipData"]),
    ("T1213", "Data from Information Repositories", "Collection", "TA0011", "Collect from Confluence/Wiki/Git.", ["application"], ["wiki_dump", "confluence", "sharepoint"]),
    ("T1005", "Data from Local System", "Collection", "TA0011", "Collect files from local system.", ["file"], ["file_collect", "doc_grab"]),
    ("T1025", "Data from Removable Media", "Collection", "TA0011", "Access removable media for data.", ["removable-media"], ["usb_copy", "sd_card"]),
    ("T1113", "Screen Capture", "Collection", "TA0011", "Capture screenshots.", ["screen"], ["SCREEN_CAPTURE", "screenshot", "screencap"]),
    # Command and Control (7) — TA0012
    ("T1071", "Application Layer Protocol", "Command and Control", "TA0012", "Use web/DNS/IRC for C2.", ["network"], ["HTTP_GET", "HTTP_POST", "API_CALL", "TELEMETRY_SEND", "TCP_CONNECT", "beacon", "c2"]),
    ("T1132", "Data Encoding", "Command and Control", "TA0012", "Encode C2 traffic.", ["network"], ["base64_c2", "hex_encode"]),
    ("T1001", "Data Obfuscation", "Command and Control", "TA0012", "Obfuscate C2 payloads.", ["network"], ["junk_data", "protocol_padding"]),
    ("T1568", "Dynamic Resolution", "Command and Control", "TA0012", "Resolve C2 via DGA/fast-flux.", ["dns"], ["DNS_QUERY", "dga", "fast_flux"]),
    ("T1573", "Encrypted Channel", "Command and Control", "TA0012", "Encrypt C2 channel.", ["network"], ["https_c2", "tls_beacon"]),
    ("T1008", "Fallback Channels", "Command and Control", "TA0012", "Alternate C2 when primary fails.", ["network"], ["secondary_c2", "backup_channel"]),
    ("T1572", "Protocol Tunneling", "Command and Control", "TA0012", "Tunnel protocols (SSH/HTTP).", ["network"], ["ssh_tunnel", "dns_tunnel"]),
    # Exfiltration (6) — TA0013
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "TA0013", "Exfil using established C2.", ["network"], ["exfil_c2", "bulk_upload_c2", "HTTP_POST"]),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "TA0013", "Exfil via non-primary channel.", ["network"], ["ftp_exfil", "icmp_exfil"]),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration", "TA0013", "Exfil to cloud/web storage.", ["cloud"], ["mega_upload", "dropbox_exfil", "pastebin"]),
    ("T1029", "Scheduled Transfer", "Exfiltration", "TA0013", "Exfil on a schedule.", ["schedule"], ["scheduled_exfil", "cron_upload"]),
    ("T1030", "Data Transfer Size Limits", "Exfiltration", "TA0013", "Limit chunk sizes to evade DLP.", ["network"], ["chunked_exfil", "size_limit"]),
    ("T1020", "Automated Exfiltration", "Exfiltration", "TA0013", "Automated collection and transfer.", ["process"], ["auto_sync_leak", "continuous_exfil"]),
    # Impact (5) — TA0014
    ("T1486", "Data Encrypted for Impact", "Impact", "TA0014", "Encrypt data for ransom.", ["data"], ["ransomware", "encrypt_files", "ENCRYPT_FILE"]),
    ("T1485", "Data Destruction", "Impact", "TA0014", "Destroy data or wipe systems.", ["data"], ["WIPE_DISK", "shred", "FORMAT_DRIVE"]),
    ("T1490", "Inhibit System Recovery", "Impact", "TA0014", "Remove recovery options.", ["system"], ["vss_delete", "wbadmin_delete", "recovery_disable"]),
    ("T1498", "Network Denial of Service", "Impact", "TA0014", "DoS against network resources.", ["network"], ["dos", "flood", "syn_flood"]),
    ("T1491", "Defacement", "Impact", "TA0014", "Alter public-facing content.", ["web"], ["deface", "website_vandalism"]),
]

TECHNIQUES: dict[str, dict[str, Any]] = {}
for tid, name, tactic, tact_id, desc, ds, kws in TECHNIQUE_ROWS:
    TECHNIQUES[tid] = {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "tactic_id": tact_id,
        "description": desc,
        "data_sources": ds,
        "keywords": kws,
    }


def get_technique(technique_id: str) -> dict[str, Any] | None:
    """Lookup technique by ID; returns None if unknown (never raises)."""
    if not technique_id:
        return None
    return TECHNIQUES.get(technique_id)


RULE_FALLBACK: dict[str, str] = {
    "R001": "T1078",
    "R100": "T1070",
    "R101": "T1486",
    "R102": "T1003",
    "R007": "T1213",
    "R003": "T1548",
    "R002": "T1567",
    "R201": "T1543",
    "R202": "T1543",
    "R500": "T1110",
    "R502": "T1078",
    "R608": "T1071",
    "R610": "T1078",
    "R612": "T1071",
    "R005": "T1041",
    "R004": "T1021",
    "R301": "T1046",
    "R006": "T1071",
    "R401": "T1071",
}


class MitreMapper:
    """Three-stage deterministic mapping: action → context → fusion fallback."""

    ACTION_MAP: dict[str, str] = {
        "CLEAR_LOGS": "T1070",
        "LSASS_ACCESS": "T1003",
        "SMB_CONNECT": "T1021",
        "RDP_CONNECT": "T1021",
        "SSH_AUTH_FAIL": "T1110",
        "AUTH_FAIL": "T1110",
        "SUDO_EXEC": "T1548",
        "PROCESS_INJECT": "T1055",
        "CLOUD_LOGIN": "T1078",
        "TCP_CONNECT": "T1071",
        "HTTP_POST": "T1041",
        "FILE_WRITE": "T1543",
        "PROCESS_CREATE": "T1059",
        "TELEMETRY_SEND": "T1071",
        "API_CALL": "T1071",
        "HTTP_GET": "T1071",
        "SMB_WRITE": "T1570",
        "KERBEROS_REQUEST": "T1558",
        "REGISTRY_WRITE": "T1112",
        "SCHEDULED_TASK": "T1053",
        "SCHEDULE_TASK": "T1053",
        "NET_SCAN": "T1046",
        "LDAP_QUERY": "T1087",
        "DNS_QUERY": "T1568",
        "SCREEN_CAPTURE": "T1113",
        "CLIPBOARD_ACCESS": "T1115",
        "ARCHIVE_CREATE": "T1560",
        "PROCESS_HOLLOW": "T1055",
        "TOKEN_IMPERSONATE": "T1134",
        "BRUTE_FORCE": "T1110",
        "PHISHING_CLICK": "T1566",
    }

    def _triple(self, technique_id: str) -> tuple[str, str, str]:
        info = TECHNIQUES.get(technique_id)
        if info:
            return technique_id, info["name"], info["tactic"]
        return "T1071", TECHNIQUES["T1071"]["name"], TECHNIQUES["T1071"]["tactic"]

    def map_event(
        self,
        event: dict[str, Any],
        fusion_result: dict[str, Any],
        symbolic_risk_flags: dict[str, Any],
    ) -> tuple[str, str, str]:
        try:
            return self._map_event_inner(event, fusion_result, symbolic_risk_flags)
        except Exception as exc:
            logger.warning("MitreMapper fallback after error: %s", exc)
            return (
                "T1071",
                TECHNIQUES["T1071"]["name"],
                TECHNIQUES["T1071"]["tactic"],
            )

    def _map_event_inner(
        self,
        event: dict[str, Any],
        fusion_result: dict[str, Any],
        symbolic_risk_flags: dict[str, Any],
    ) -> tuple[str, str, str]:
        action_raw = (event.get("action") or "").strip()
        action_u = action_raw.upper()
        if action_u in self.ACTION_MAP:
            return self._triple(self.ACTION_MAP[action_u])

        meta = event.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        outcome = (event.get("outcome") or "").lower()
        trust = (event.get("trust_tier") or "").lower()
        dest_ip = event.get("dest_ip") or ""
        action_l = action_raw.lower()

        try:
            bs = int(float(meta.get("bytes_sent", 0) or 0))
        except (TypeError, ValueError):
            bs = 0

        after_hours = bool(meta.get("after_hours"))
        restricted = bool(meta.get("restricted_asset"))

        if after_hours and restricted and outcome == "failure":
            return self._triple("T1110")

        if self._is_external_dest(dest_ip) and bs > 100_000:
            return self._triple("T1041")

        if restricted and trust in ("kernel", "iam") and outcome == "success":
            return self._triple("T1078")

        if after_hours and trust == "iot":
            return self._triple("T1071")

        if "scan" in action_l or "discovery" in action_l or "discover" in action_l:
            return self._triple("T1046")

        if "upload" in action_l or "transfer" in action_l:
            return self._triple("T1041")

        if "inject" in action_l:
            return self._triple("T1055")

        if "cron" in action_l or "schedule" in action_l or "task" in action_l:
            return self._triple("T1053")

        if bs > 500_000:
            return self._triple("T1567")

        if trust == "iot" and bs > 50_000:
            return self._triple("T1071")

        if outcome == "failure" and any(k in action_l for k in ("auth", "login", "ssh")):
            return self._triple("T1110")

        # Optional symbolic flags (Stage 2 supplement)
        if symbolic_risk_flags.get("high_credential_risk"):
            return self._triple("T1110")

        # Stage 3 — fusion rule primary mitre_technique ids
        for rid in fusion_result.get("matched_rule_mitre_ids") or []:
            if rid and rid in TECHNIQUES:
                return self._triple(rid)

        for rid in fusion_result.get("matched_rules") or []:
            fb = RULE_FALLBACK.get(rid)
            if fb:
                return self._triple(fb)

        for trace in fusion_result.get("rule_trace") or []:
            if not isinstance(trace, str):
                continue
            m = re.search(r"MATCH\s+(R\d+[A-Za-z0-9]*)\s*:", trace)
            if m:
                fb = RULE_FALLBACK.get(m.group(1))
                if fb:
                    return self._triple(fb)

        return self._triple("T1071")

    @staticmethod
    def _is_external_dest(dest_ip: str) -> bool:
        if not dest_ip or not isinstance(dest_ip, str):
            return False
        dip = dest_ip.strip().lower()
        if dip.startswith("10."):
            return False
        if dip.startswith("192.168."):
            return False
        if dip.startswith("172."):
            parts = dip.split(".")
            if len(parts) >= 2 and parts[1].isdigit():
                second = int(parts[1])
                if 16 <= second <= 31:
                    return False
        return True


