
import json


with open("events.json", "r") as file:
    events = json.load(file)


rules = {
    "repeated_failed_logins": (
        "T1110", "Brute Force",
        "Repeated login failures may indicate password guessing.",
        "Check timestamps, targeted accounts, source IP, and successful logins."
    ),
    "suspicious_shell_execution": (
        "T1059.004", "Unix Shell",
        "Unusual shell execution may require investigation.",
        "Review the command, user, parent process, and execution context."
    ),
    "suspicious_powershell": (
        "T1059.001", "PowerShell",
        "Unusual PowerShell activity may indicate suspicious execution.",
        "Review command-line details and the process that launched it."
    ),
    "scheduled_task_created": (
        "T1053", "Scheduled Task/Job",
        "Unexpected task creation may be used to execute code later.",
        "Inspect the task, creator account, configured command, and timing."
    ),
    "new_startup_entry": (
        "T1547", "Boot or Logon Autostart Execution",
        "An unfamiliar startup entry may run a program automatically.",
        "Inspect the entry, target file, creator, and file reputation."
    ),
    "suspicious_process_injection": (
        "T1055", "Process Injection",
        "An endpoint alert reported behavior consistent with process injection.",
        "Review endpoint telemetry and investigate the affected process."
    ),
    "unexpected_admin_account": (
        "T1098", "Account Manipulation",
        "An unexpected privileged-group change may alter account access.",
        "Verify the account, group change, creator, and authorization."
    ),
    "security_tool_disabled": (
        "T1562.001", "Impair Defenses: Disable or Modify Tools",
        "Unexpectedly disabling security protection may reduce visibility.",
        "Check who disabled it, when, and whether maintenance was approved."
    ),
    "suspicious_dns_queries": (
        "T1071.004", "Application Layer Protocol: DNS",
        "Unusual DNS requests may warrant command-and-control investigation.",
        "Review queried domains, DNS answers, frequency, and destination traffic."
    ),
    "unusual_outbound_transfer": (
        None, "Manual review required",
        "A large outbound transfer alone does not prove data theft.",
        "Check destination, data type, volume, and business justification."
    ),
    "suspicious_archive_creation": (
        "T1560", "Archive Collected Data",
        "Unexpected archiving of files may relate to data staging.",
        "Inspect the archive, its contents, creator, and subsequent activity."
    ),
    "new_service_installed": (
        "T1543", "Create or Modify System Process",
        "An unfamiliar service may be used to run a program persistently.",
        "Inspect service configuration, executable, creator, and timing."
    ),
    "suspicious_remote_login": (
        "T1021", "Remote Services",
        "An unusual remote login may warrant investigation.",
        "Verify the user, source IP, authentication method, and expected schedule."
    ),
    "phishing_email_reported": (
        "T1566", "Phishing",
        "A suspicious email may be an attempt to gain access through deception.",
        "Examine sender details, links, attachments, and recipient exposure."
    ),
    "suspicious_file_download": (
        "T1105", "Ingress Tool Transfer",
        "An unexpected executable download may involve tool transfer.",
        "Check the URL, file hash, download process, and file reputation."
    ),
    "file_integrity_change": (
        None, "Manual review required",
        "A file change alone does not identify an attacker technique.",
        "Compare file hashes and review the change, user, and file history."
    ),
    "multiple_account_failures": (
        "T1110.003", "Password Spraying (candidate)",
        "Failures across many accounts may warrant investigation for spraying.",
        "Compare targeted accounts, timing, source IP, and password patterns."
    ),
    "unusual_privilege_use": (
        None, "Manual review required",
        "An unusual privileged operation alone does not prove an attack.",
        "Review process details, permissions, outcome, and related alerts."
    ),
    "possible_log_clearing": (
        "T1070", "Indicator Removal",
        "Unexpected log clearing may indicate an attempt to remove evidence.",
        "Check audit records, authorized maintenance, and logging gaps."
    ),
    "suspicious_remote_service": (
        "T1021", "Remote Services",
        "Unexpected connections between workstations may require investigation.",
        "Identify the service, source and destination hosts, and authentication."
    ),

    "suspicious_account_discovery": (
        "T1087", "Account Discovery",
        "Unexpected account enumeration may indicate reconnaissance.",
        "Review the process, account, command, and scope of enumeration."
    ),
    "suspicious_system_info_discovery": (
        "T1082", "System Information Discovery",
        "Unexpected collection of system details may warrant review.",
        "Review commands, process ancestry, user, and related events."
    ),
    "suspicious_process_discovery": (
        "T1057", "Process Discovery",
        "Unexpected process enumeration may warrant investigation.",
        "Inspect the process, command, user, and surrounding activity."
    ),
    "suspicious_file_discovery": (
        "T1083", "File and Directory Discovery",
        "Unusual file-system enumeration may indicate reconnaissance.",
        "Review accessed paths, process, account, and access patterns."
    ),
    "suspicious_network_service_scan": (
        "T1046", "Network Service Discovery",
        "Unexpected scanning may indicate service discovery.",
        "Identify the source, destinations, ports, and authorization."
    ),
    "suspicious_remote_host_discovery": (
        "T1018", "Remote System Discovery",
        "Unexpected discovery of remote hosts may warrant investigation.",
        "Review host lists, commands, source system, and timing."
    ),
    "suspicious_network_share_access": (
        "T1135", "Network Share Discovery",
        "Unexpected network-share enumeration may be reconnaissance.",
        "Check accessed shares, account, process, and business purpose."
    ),
    "suspicious_password_store_access": (
        "T1555", "Credentials from Password Stores",
        "Unexpected password-store access may expose credentials.",
        "Review the application, account, access result, and endpoint alerts."
    ),
    "suspicious_input_capture": (
        "T1056", "Input Capture",
        "Behavior suggesting input capture requires investigation.",
        "Review endpoint alerts, process behavior, and file provenance."
    ),
    "suspicious_screen_capture": (
        "T1113", "Screen Capture",
        "Unexpected screen capture may warrant investigation.",
        "Identify the application, user, process, and resulting files."
    ),
    "sensitive_file_collection": (
        "T1005", "Data from Local System",
        "Unexpected local-file collection may indicate data gathering.",
        "Review file access, sensitivity, account, and destination."
    ),
    "suspicious_web_exfiltration": (
        "T1567", "Exfiltration Over Web Service",
        "Suspicious transfer to a web service may warrant investigation.",
        "Review destination, upload volume, files, and authorization."
    ),
    "public_facing_app_exploit": (
        "T1190", "Exploit Public-Facing Application",
        "An application alert may indicate attempted exploitation.",
        "Review web logs, requests, application errors, and patch status."
    ),
    "phishing_attachment": (
        "T1566.001", "Spearphishing Attachment",
        "A suspicious email attachment may be a delivery method.",
        "Inspect email headers, attachment hash, recipient, and execution."
    ),
    "unusual_valid_account_use": (
        "T1078", "Valid Accounts",
        "Unexpected use of a legitimate account may warrant review.",
        "Verify identity, login context, device, and session activity."
    ),
    "external_remote_service_access": (
        "T1133", "External Remote Services",
        "Unexpected external remote access may require investigation.",
        "Verify service exposure, authentication, account, and source."
    ),
    "suspicious_ssh_activity": (
        "T1021.004", "Remote Services: SSH",
        "Unexpected SSH activity may indicate suspicious remote access.",
        "Review SSH logs, account, source, and session activity."
    ),
    "authentication_process_modified": (
        "T1556", "Modify Authentication Process",
        "Unexpected authentication changes may affect access controls.",
        "Inspect changed files, account activity, approvals, and audit logs."
    ),
    "obfuscated_file_detected": (
        "T1027", "Obfuscated Files or Information",
        "Obfuscation indicators may warrant malware investigation.",
        "Analyze file metadata, hash, source, and endpoint detections."
    ),
    "privilege_escalation_attempt": (
        "T1548", "Abuse Elevation Control Mechanism",
        "An alert suggests possible abuse of an elevation mechanism.",
        "Review the command, permissions, outcome, and related telemetry."
    )
}


report = []

for event in events:
    event_type = event.get("event_type", "")
    result = rules.get(event_type)

    if result:
        technique_id, technique_name, reason, next_step = result
    else:
        technique_id = None
        technique_name = "Unknown event type"
        reason = "No mapping rule matches this event."
        next_step = "Review the event and consider adding a mapping rule."

    report.append({
        "event_id": event.get("event_id", "Unknown"),
        "event_type": event_type,
        "description": event.get("description", ""),
        "source_ip": event.get("source_ip", "Not provided"),
        "attempts": event.get("attempts", "Not provided"),
        "technique_id": technique_id,
        "technique_name": technique_name,
        "reason": reason,
        "next_step": next_step
    })


print("=" * 55)
print("       MITRE ATT&CK INVESTIGATION REPORT")
print("=" * 55)
print("Mapping rules available:", len(rules))
print("Total events analyzed:", len(report))

for item in report:
    print("\n" + "-" * 55)
    print("Event ID       :", item["event_id"])
    print("Event Type     :", item["event_type"])
    print("Description    :", item["description"])
    print("Source IP      :", item["source_ip"])
    print("Attempts       :", item["attempts"])
    print("ATT&CK ID      :", item["technique_id"] or "No automatic mapping")
    print("Technique      :", item["technique_name"])
    print("Reason         :", item["reason"])
    print("Recommended Step:", item["next_step"])


with open("report.json", "w") as file:
    json.dump(report, file, indent=4)

print("\n" + "=" * 55)
print("Investigation complete.")
print("Events included in report:", len(report))
print("Detailed report saved to report.json")
print("=" * 55)
