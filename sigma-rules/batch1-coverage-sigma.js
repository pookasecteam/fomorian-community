// =============================================================================
// Batch 1 MITRE ATT&CK Coverage - Graylog Sigma Pipeline Rules
// =============================================================================
// Deploy with: docker exec -i graylog-mongo mongosh graylog < /tmp/batch1-sigma-rules.js
//
// Coverage: 47 techniques (36+ unique rules)
//   - DISCOVERY: 16 techniques (T1010, T1016.001, T1016.002, T1069.003, T1497.002,
//                T1497.003, T1518.002, T1538, T1580, T1613, T1614.001, T1619,
//                T1622, T1652, T1673, T1680)
//   - LATERAL MOVEMENT: 9 techniques (T1021.005, T1021.007, T1021.008, T1072,
//                T1080, T1091, T1210, T1550.004, T1563.001)
//   - INITIAL ACCESS: 11 techniques (T1078.001, T1078.002, T1078.003, T1091,
//                T1195.001, T1195.003, T1200, T1566.003, T1566.004, T1659, T1669)
//
// Field Mapping:
//   - Windows Sysmon: filebeat_data_win_eventdata_*
//   - Linux Sysmon: filebeat_data_eventdata_* (no 'win' segment)
//   - Cloud/O365: filebeat_data_office365_* or CLI tool detection
//
// Author: PookaSec Detection Engineering
// Date: 2026-02-08
// =============================================================================

// =============================================================================
// DISCOVERY RULES (16 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: Application Window Discovery (T1010)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Application Window Discovery (T1010)",
    "description": "Detects adversaries enumerating open application windows. Real adversaries: Volt Typhoon, Lazarus, QakBot, ROKRAT, njRAT.",
    "source": `rule "Sigma: Application Window Discovery (T1010)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "MainWindowTitle") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Process") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Where-Object")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetForegroundWindow") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "EnumWindows") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "user32.dll") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetWindow")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "windowenum") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "FindWindow") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Process") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "MainWindow"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "explorer.exe") AND
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "taskmgr")
    )
then
    set_field("sigma_rule_title", "Application Window Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1010");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Application Window Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Internet Connection Discovery (T1016.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Internet Connection Discovery (T1016.001)",
    "description": "Detects adversaries checking internet connectivity. Real commands: ping 8.8.8.8, Test-NetConnection, curl ifconfig.me/icanhazip.com.",
    "source": `rule "Sigma: Internet Connection Discovery (T1016.001)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "ping.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "8.8.8.8") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "1.1.1.1") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "google.com"))) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Test-NetConnection") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ifconfig.me") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "icanhazip.com") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ipinfo.io") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "checkip.amazonaws.com") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "api.ipify.org") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "whatismyip")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "SCCM") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "monitoring")
    )
then
    set_field("sigma_rule_title", "Internet Connection Discovery");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1016.001");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Internet Connection Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Wi-Fi Discovery (T1016.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Wi-Fi Discovery (T1016.002)",
    "description": "Detects adversaries enumerating Wi-Fi networks and stored credentials. Commands: netsh wlan show profiles/networks.",
    "source": `rule "Sigma: Wi-Fi Discovery (T1016.002)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "netsh.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wlan") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "show") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "export"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wlan") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "key=clear")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Wifi.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "WlanGetProfileList")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "services.exe")
    )
then
    set_field("sigma_rule_title", "Wi-Fi Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1016.002");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Wi-Fi Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Groups Discovery (T1069.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Groups Discovery (T1069.003)",
    "description": "Detects adversaries enumerating cloud groups via CLI tools. Commands: az ad group list, Get-AzADGroup, aws iam list-groups.",
    "source": `rule "Sigma: Cloud Groups Discovery (T1069.003)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "az.cmd") OR
         contains(to_string($message.filebeat_data_win_eventdata_image), "az.ps1") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az ")) AND
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ad group") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "role assignment")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzADGroup") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzureADGroup") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-MgGroup") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "iam") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "list-groups")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "iam") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "groups"))
    )
then
    set_field("sigma_rule_title", "Cloud Groups Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1069.003");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Cloud Groups");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: User Activity Based Checks - Sandbox Evasion (T1497.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: User Activity Based Checks (T1497.002)",
    "description": "Detects sandbox evasion via user activity checks. Real malware: Darkhotel, FIN7, Okrum (mouse clicks), TONESHELL (GetForegroundWindow).",
    "source": `rule "Sigma: User Activity Based Checks (T1497.002)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetCursorPos") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetLastInputInfo") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetForegroundWindow") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetAsyncKeyState") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Cursor") AND
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Position") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "MousePosition") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Desktop") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Count") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-ChildItem")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "RecentDocs") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Recent") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Count"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "devenv.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "code.exe")
    )
then
    set_field("sigma_rule_title", "User Activity Based Checks");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1497.002");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Virtualization/Sandbox Evasion: User Activity Based Checks");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Time Based Checks - Sandbox Evasion (T1497.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Time Based Checks (T1497.003)",
    "description": "Detects sandbox evasion via time-based delays. Real malware: SUNBURST, TrickBot, HermeticWiper, WhisperGate.",
    "source": `rule "Sigma: Time Based Checks (T1497.003)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "ping.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-n 60") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-n 120") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-n 300") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "127.0.0.1 -n"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "timeout.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/t 60") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/t 120") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/t 300"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Start-Sleep") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-Seconds 60") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-Seconds 120") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-Seconds 300") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-s 60") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-s 120"))) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "GetTickCount") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "QueryPerformanceCounter")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "setup.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe")
    )
then
    set_field("sigma_rule_title", "Time Based Sandbox Evasion");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1497.003");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Time Based Evasion");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Backup Software Discovery (T1518.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Backup Software Discovery (T1518.002)",
    "description": "Detects adversaries enumerating backup software (pre-ransomware recon). Real adversaries: BlackCat, LockBit, REvil, all major ransomware groups.",
    "source": `rule "Sigma: Backup Software Discovery (T1518.002)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "wmic.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "product") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "backup") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "veeam") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "acronis") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "shadow") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "carbonite"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Win32_Product") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "backup") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "veeam"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WmiObject") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "backup")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sc query") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "veeam") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "backup"))) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "VeeamAgent") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "BackupExec")
    )
then
    set_field("sigma_rule_title", "Backup Software Discovery");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1518.002");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Backup Software Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Service Dashboard (T1538)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Service Dashboard Access (T1538)",
    "description": "Detects cloud portal access via browser or CLI login commands. Covers Azure Portal, AWS Console, GCP Console.",
    "source": `rule "Sigma: Cloud Service Dashboard Access (T1538)"
when
    (
        has_field("filebeat_data_win_eventdata_commandLine") AND
        to_string($message.filebeat_data_win_system_eventID) == "1" AND
        (
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az login") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws configure") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud auth login") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Connect-AzAccount") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Connect-AzureAD") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Connect-MgGraph") OR
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
             contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sts") AND
             contains(to_string($message.filebeat_data_win_eventdata_commandLine), "get-caller-identity"))
        )
    ) OR (
        has_field("filebeat_data_office365_Operation") AND
        (
            to_string($message.filebeat_data_office365_Operation) == "UserLoggedIn" AND
            (
                contains(to_string($message.filebeat_data_office365_Target_0_ID), "Azure Portal") OR
                contains(to_string($message.filebeat_data_office365_Target_0_ID), "AWS") OR
                contains(to_string($message.filebeat_data_office365_Target_0_ID), "Google Cloud")
            )
        )
    )
then
    set_field("sigma_rule_title", "Cloud Service Dashboard Access");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1538");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Cloud Service Dashboard");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Infrastructure Discovery (T1580)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Infrastructure Discovery (T1580)",
    "description": "Detects cloud infrastructure enumeration via CLI. Commands: aws ec2 describe-instances, az vm list, az resource list.",
    "source": `rule "Sigma: Cloud Infrastructure Discovery (T1580)"
when
    (
        has_field("filebeat_data_win_eventdata_commandLine") AND
        to_string($message.filebeat_data_win_system_eventID) == "1" AND
        (
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ec2 describe") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3 ls") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3api list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "iam list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "rds describe") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lambda list"))) OR
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vm list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "resource list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "storage account list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "network list"))) OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzVM") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzResource") OR
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
             contains(to_string($message.filebeat_data_win_eventdata_commandLine), "compute instances list"))
        )
    ) OR (
        has_field("filebeat_data_aws_eventName") AND
        (
            to_string($message.filebeat_data_aws_eventName) == "DescribeInstances" OR
            to_string($message.filebeat_data_aws_eventName) == "ListBuckets" OR
            to_string($message.filebeat_data_aws_eventName) == "DescribeSecurityGroups" OR
            to_string($message.filebeat_data_aws_eventName) == "DescribeSubnets" OR
            to_string($message.filebeat_data_aws_eventName) == "DescribeVpcs" OR
            to_string($message.filebeat_data_aws_eventName) == "ListFunctions20150331" OR
            to_string($message.filebeat_data_aws_eventName) == "DescribeDBInstances" OR
            to_string($message.filebeat_data_aws_eventName) == "ListUsers"
        )
    ) OR (
        has_field("filebeat_data_office365_Operation") AND
        (
            contains(to_string($message.filebeat_data_office365_Operation), "List") OR
            contains(to_string($message.filebeat_data_office365_Operation), "Get") OR
            contains(to_string($message.filebeat_data_office365_Operation), "Describe")
        ) AND (
            contains(to_string($message.filebeat_data_office365_Workload), "Azure") OR
            contains(to_string($message.filebeat_data_office365_Workload), "AzureActiveDirectory")
        )
    )
then
    set_field("sigma_rule_title", "Cloud Infrastructure Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1580");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Cloud Infrastructure Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Container and Resource Discovery (T1613) - Linux
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Container and Resource Discovery (T1613)",
    "description": "Detects container enumeration via docker/kubectl/crictl. Commands: docker ps, kubectl get pods/secrets.",
    "source": `rule "Sigma: Container and Resource Discovery (T1613)"
when
    (
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "docker ps") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "docker images") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "docker inspect") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl get pods") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl get secrets") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl get nodes") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl get all") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "crictl ps") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "crictl images") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "podman ps") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "nerdctl ps")))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker ps") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "kubectl get pods") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "kubectl get secrets")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "containerd") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "dockerd")
    )
then
    set_field("sigma_rule_title", "Container and Resource Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1613");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Container and Resource Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: System Language Discovery (T1614.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: System Language Discovery (T1614.001)",
    "description": "Detects language/locale enumeration (ransomware CIS country checks). Real adversaries: REvil, Maze, DarkSide.",
    "source": `rule "Sigma: System Language Discovery (T1614.001)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "chcp.com") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg query") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Nls\\\\Language") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Nls\\Language") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Control Panel\\\\International") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Control Panel\\International"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "dism.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Intl")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "wmic.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "os") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Locale")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WinSystemLocale") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Culture") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WinUserLanguageList") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "[System.Globalization.CultureInfo]")
    )
then
    set_field("sigma_rule_title", "System Language Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1614.001");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "System Language Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Storage Object Discovery (T1619)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Storage Object Discovery (T1619)",
    "description": "Detects cloud storage enumeration via CLI. Commands: aws s3 ls, az storage blob list, gsutil ls.",
    "source": `rule "Sigma: Cloud Storage Object Discovery (T1619)"
when
    (
        has_field("filebeat_data_win_eventdata_commandLine") AND
        to_string($message.filebeat_data_win_system_eventID) == "1" AND
        (
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3 ls") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3api list-objects") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3api list-buckets"))) OR
            (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
             contains(to_string($message.filebeat_data_win_eventdata_commandLine), "storage") AND
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "blob list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "container list") OR
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "file list"))) OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gsutil ls") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzStorageBlob") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AzStorageContainer")
        )
    ) OR (
        has_field("filebeat_data_office365_Operation") AND
        (
            contains(to_string($message.filebeat_data_office365_Operation), "FileAccessed") OR
            contains(to_string($message.filebeat_data_office365_Operation), "FolderAccessed") OR
            contains(to_string($message.filebeat_data_office365_Operation), "SearchQueryPerformed") OR
            contains(to_string($message.filebeat_data_office365_Operation), "FilePreviewed")
        ) AND (
            contains(to_string($message.filebeat_data_office365_Workload), "SharePoint") OR
            contains(to_string($message.filebeat_data_office365_Workload), "OneDrive")
        )
    )
then
    set_field("sigma_rule_title", "Cloud Storage Object Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1619");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Cloud Storage Object Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Debugger Evasion (T1622) - Windows
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Debugger Evasion - Windows (T1622)",
    "description": "Detects debugger evasion techniques. Real malware: AsyncRAT, Black Basta, DarkGate, LockBit, Lumma Stealer, Pikabot.",
    "source": `rule "Sigma: Debugger Evasion - Windows (T1622)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "IsDebuggerPresent") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CheckRemoteDebuggerPresent") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtQueryInformationProcess") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Debugger") AND
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "IsAttached") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ProcessName") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "dbg") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ida") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "olly") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "x64dbg") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "windbg"))) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "OutputDebugString") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "QueryPerformanceCounter") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "al-khaser") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pafish") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "antidebug")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "devenv.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "WinDbg")
    )
then
    set_field("sigma_rule_title", "Debugger Evasion");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1622");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Debugger Evasion");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Debugger Evasion (T1622) - Linux
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Debugger Evasion - Linux (T1622)",
    "description": "Detects Linux debugger evasion via ptrace or /proc checks.",
    "source": `rule "Sigma: Debugger Evasion - Linux (T1622)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_commandLine), "ptrace") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "cat") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/self/status") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "TracerPid")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "grep") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "TracerPid")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "PTRACE_TRACEME")
    )
then
    set_field("sigma_rule_title", "Debugger Evasion - Linux");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1622");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Debugger Evasion");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Device Driver Discovery (T1652) - Windows
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Device Driver Discovery - Windows (T1652)",
    "description": "Detects driver enumeration. Real adversaries: HOPLIGHT, INC Ransomware, Medusa.",
    "source": `rule "Sigma: Device Driver Discovery - Windows (T1652)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "driverquery.exe") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WmiObject") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Win32_SystemDriver")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gwmi") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SystemDriver")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WindowsDriver") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sc query") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "type= driver"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "setup.exe")
    )
then
    set_field("sigma_rule_title", "Device Driver Discovery - Windows");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1652");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Device Driver Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Device Driver Discovery (T1652) - Linux
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Device Driver Discovery - Linux (T1652)",
    "description": "Detects Linux kernel module enumeration via lsmod/modinfo.",
    "source": `rule "Sigma: Device Driver Discovery - Linux (T1652)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_image), "/lsmod") OR
        contains(to_string($message.filebeat_data_eventdata_image), "/modinfo") OR
        contains(to_string($message.filebeat_data_eventdata_image), "/modprobe") AND
        contains(to_string($message.filebeat_data_eventdata_commandLine), "-l") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "cat") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/modules"))
    )
then
    set_field("sigma_rule_title", "Device Driver Discovery - Linux");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1652");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Device Driver Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Virtual Machine Discovery (T1673)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Virtual Machine Discovery (T1673)",
    "description": "Detects VM enumeration commands. Real adversaries: Cheerscrypt, UNC3886, VIRTUALPITA.",
    "source": `rule "Sigma: Virtual Machine Discovery (T1673)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "esxcli vm process list") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vim-cmd vmsvc") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "getallvms") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-VM") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vmrun list") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "VBoxManage list vms") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "VBoxManage list runningvms")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "virsh list") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcli vm process") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "vim-cmd vmsvc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "qm list") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "prlctl list")))
    )
then
    set_field("sigma_rule_title", "Virtual Machine Discovery");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1673");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Virtual Machine Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Local Storage Discovery (T1680)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Local Storage Discovery (T1680)",
    "description": "Detects storage/disk enumeration. Real adversaries: 150+ malware families.",
    "source": `rule "Sigma: Local Storage Discovery (T1680)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_image), "wmic.exe") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "logicaldisk")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_image), "fsutil.exe") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "fsinfo")) OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "mountvol.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-PSDrive") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Volume") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-Disk") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-WmiObject") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Win32_LogicalDisk"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "lsblk") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "fdisk -l") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "df -h") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "blkid") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "findmnt")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "explorer.exe")
    )
then
    set_field("sigma_rule_title", "Local Storage Discovery");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1680");
    set_field("sigma_mitre_tactic", "Discovery");
    set_field("sigma_mitre_technique", "Local Storage Discovery");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// =============================================================================
// LATERAL MOVEMENT RULES (9 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: VNC Remote Access (T1021.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: VNC Remote Access (T1021.005)",
    "description": "Detects VNC client execution or network connections on VNC ports (5900-5910).",
    "source": `rule "Sigma: VNC Remote Access (T1021.005)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    (
        (to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "vncviewer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "tvnviewer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "uvnc") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "tightvnc") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "realvnc") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "vnc.exe")))
        OR
        (to_string($message.filebeat_data_win_system_eventID) == "3" AND
         (contains(to_string($message.filebeat_data_win_eventdata_destinationPort), "5900") OR
          contains(to_string($message.filebeat_data_win_eventdata_destinationPort), "5901") OR
          contains(to_string($message.filebeat_data_win_eventdata_destinationPort), "5902")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "services.exe")
    )
then
    set_field("sigma_rule_title", "VNC Remote Access");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1021.005");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "VNC");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Services Lateral Movement (T1021.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Services Lateral Movement (T1021.007)",
    "description": "Detects lateral movement via cloud VM run commands. Commands: az vm run-command, aws ssm send-command.",
    "source": `rule "Sigma: Cloud Services Lateral Movement (T1021.007)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vm") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "run-command")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-AzVMRunCommand") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ssm") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "send-command")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "compute") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ssh"))
    )
then
    set_field("sigma_rule_title", "Cloud Services Lateral Movement");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1021.007");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Cloud Services");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Direct Cloud VM Connections (T1021.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Direct Cloud VM Connections (T1021.008)",
    "description": "Detects direct cloud VM access via SSM/serial console. Commands: aws ssm start-session, az serial-console connect.",
    "source": `rule "Sigma: Direct Cloud VM Connections (T1021.008)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ssm") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "start-session")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "serial-console") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "connect")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "compute") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "connect-to-serial-port"))
    )
then
    set_field("sigma_rule_title", "Direct Cloud VM Connections");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1021.008");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Direct Cloud VM Connections");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Software Deployment Tools (T1072)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Software Deployment Tools Abuse (T1072)",
    "description": "Detects misuse of deployment tools for lateral movement. Real tools: PDQ Deploy, Radmin, SCCM/SharpSCCM.",
    "source": `rule "Sigma: Software Deployment Tools Abuse (T1072)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "PDQDeploy") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "PDQDeployRunner") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Radmin") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SharpSCCM") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sccmexec") OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "psexec") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-d")) OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "BigFix") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "dameware")
    )
then
    set_field("sigma_rule_title", "Software Deployment Tools Abuse");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1072");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Software Deployment Tools");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Taint Shared Content (T1080)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Taint Shared Content (T1080)",
    "description": "Detects malicious file creation on network shares. Real adversaries: BRONZE BUTLER, Cinnamon Tempest, Gamaredon, RedCurl.",
    "source": `rule "Sigma: Taint Shared Content (T1080)"
when
    has_field("filebeat_data_win_eventdata_targetFilename") AND
    to_string($message.filebeat_data_win_system_eventID) == "11" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".lnk") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".scf") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".url") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".library-ms") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".searchConnector-ms") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".hta") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".js") OR
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".vbs")
    )
then
    set_field("sigma_rule_title", "Taint Shared Content");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1080");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Taint Shared Content");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Replication Through Removable Media (T1091)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Replication Through Removable Media (T1091)",
    "description": "Detects execution from removable media or autorun.inf creation. Real malware: Stuxnet, Agent.BTZ, USBStealer.",
    "source": `rule "Sigma: Replication Through Removable Media (T1091)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "D:\\\\") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "E:\\\\") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "F:\\\\") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "G:\\\\") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "H:\\\\")))
        OR
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "autorun.inf") OR
          (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ":\\\\") AND
           (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".exe") OR
            contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".dll") OR
            contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".lnk")))))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "Windows") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Program Files")
    )
then
    set_field("sigma_rule_title", "Replication Through Removable Media");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1091");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Replication Through Removable Media");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Exploitation of Remote Services (T1210)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Exploitation of Remote Services (T1210)",
    "description": "Detects exploit activity via unusual child processes of system services. Real exploits: EternalBlue, ZeroLogon, BlueKeep, PrintNightmare.",
    "source": `rule "Sigma: Exploitation of Remote Services (T1210)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "lsass.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "rundll32.exe"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "spoolsv.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "svchost.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-enc")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "services.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/c"))
    )
then
    set_field("sigma_rule_title", "Exploitation of Remote Services");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1210");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Exploitation of Remote Services");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Web Session Cookie Theft (T1550.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Web Session Cookie Theft (T1550.004)",
    "description": "Detects access to browser cookie databases for session hijacking.",
    "source": `rule "Sigma: Web Session Cookie Theft (T1550.004)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Cookies") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cookies.sqlite") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Network\\Cookies") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Chrome\\User Data") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Cookies") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cookie-extractor") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SharpChrome") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SharpCookieMonster")))
        OR
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "Cookies") AND
         NOT contains(to_string($message.filebeat_data_win_eventdata_image), "chrome.exe") AND
         NOT contains(to_string($message.filebeat_data_win_eventdata_image), "msedge.exe") AND
         NOT contains(to_string($message.filebeat_data_win_eventdata_image), "firefox.exe"))
    )
then
    set_field("sigma_rule_title", "Web Session Cookie Theft");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1550.004");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Web Session Cookie");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: SSH Hijacking (T1563.001) - Linux
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: SSH Hijacking (T1563.001)",
    "description": "Detects SSH agent socket access or manipulation. Real malware: MEDUSA.",
    "source": `rule "Sigma: SSH Hijacking (T1563.001)"
when
    (has_field("filebeat_data_eventdata_commandLine") OR has_field("filebeat_data_eventdata_parentCommandLine")) AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "SSH_AUTH_SOCK") OR
         contains(to_string($message.filebeat_data_eventdata_parentCommandLine), "SSH_AUTH_SOCK")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "/tmp/ssh-") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "agent")) OR
        (contains(to_string($message.filebeat_data_eventdata_parentCommandLine), "/tmp/ssh-") AND
         contains(to_string($message.filebeat_data_eventdata_parentCommandLine), "agent")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "ssh-add") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-l")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "ControlMaster") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "find") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "ssh-") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "agent"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "sshd")
    )
then
    set_field("sigma_rule_title", "SSH Agent Socket Hijacking");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1563.001");
    set_field("sigma_mitre_tactic", "Lateral Movement");
    set_field("sigma_mitre_technique", "Remote Service Session Hijacking: SSH Hijacking");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// =============================================================================
// INITIAL ACCESS RULES (11 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: Default Accounts (T1078.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Default Accounts Login (T1078.001)",
    "description": "Detects login with known default usernames that should not be used in production.",
    "source": `rule "Sigma: Default Accounts Login (T1078.001)"
when
    has_field("filebeat_data_win_eventdata_targetUserName") AND
    (to_string($message.filebeat_data_win_system_eventID) == "4624" OR
     to_string($message.filebeat_data_win_system_eventID) == "4625") AND
    (
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "admin" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "administrator" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "sa" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "postgres" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "root" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "guest" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "test" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "user" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "backup" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "oracle" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "mysql"
    )
then
    set_field("sigma_rule_title", "Default Accounts Login");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1078.001");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Default Accounts");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Domain Accounts Suspicious Login (T1078.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Domain Accounts Suspicious Login (T1078.002)",
    "description": "Detects domain logon type 3 (network) or 10 (RDP) which may indicate lateral movement or unauthorized access.",
    "source": `rule "Sigma: Domain Accounts Suspicious Login (T1078.002)"
when
    has_field("filebeat_data_win_eventdata_targetUserName") AND
    to_string($message.filebeat_data_win_system_eventID) == "4624" AND
    (to_string($message.filebeat_data_win_eventdata_logonType) == "3" OR
     to_string($message.filebeat_data_win_eventdata_logonType) == "10") AND
    has_field("filebeat_data_win_eventdata_targetDomainName") AND
    NOT (
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "SYSTEM" OR
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "ANONYMOUS LOGON" OR
        contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "$")
    )
then
    set_field("sigma_rule_title", "Domain Accounts Network Logon");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1078.002");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Domain Accounts");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Local Accounts Brute Force (T1078.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Local Accounts Failed Login (T1078.003)",
    "description": "Detects failed logon attempts which may indicate brute force activity.",
    "source": `rule "Sigma: Local Accounts Failed Login (T1078.003)"
when
    has_field("filebeat_data_win_eventdata_targetUserName") AND
    to_string($message.filebeat_data_win_system_eventID) == "4625" AND
    NOT (
        to_string($message.filebeat_data_win_eventdata_targetUserName) == "SYSTEM" OR
        contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "$")
    )
then
    set_field("sigma_rule_title", "Local Accounts Failed Login");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1078.003");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Local Accounts");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Supply Chain - Malicious Package Execution (T1195.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Supply Chain - Malicious Package Execution (T1195.001)",
    "description": "Detects execution from package manager cache directories which may indicate supply chain compromise.",
    "source": `rule "Sigma: Supply Chain - Malicious Package Execution (T1195.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "npm") AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "preinstall") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "postinstall"))) OR
         (contains(to_string($message.filebeat_data_win_eventdata_image), "node_modules") AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cmd") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "powershell"))) OR
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pip") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "install")) OR
         contains(to_string($message.filebeat_data_win_eventdata_image), "AppData\\\\Local\\\\pip"))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "pip") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "install")) OR
          contains(to_string($message.filebeat_data_eventdata_image), ".local/lib/python") OR
          (contains(to_string($message.filebeat_data_eventdata_image), "node_modules") AND
           NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "npm"))))
    )
then
    set_field("sigma_rule_title", "Supply Chain - Malicious Package Execution");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1195.001");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Compromise Software Dependencies and Development Tools");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Hardware Supply Chain - Driver Load (T1195.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Hardware Supply Chain - Suspicious Driver Load (T1195.003)",
    "description": "Detects suspicious driver loading which may indicate hardware supply chain compromise.",
    "source": `rule "Sigma: Hardware Supply Chain - Suspicious Driver Load (T1195.003)"
when
    has_field("filebeat_data_win_eventdata_imageLoaded") AND
    to_string($message.filebeat_data_win_system_eventID) == "6" AND
    (
        (NOT contains(to_string($message.filebeat_data_win_eventdata_signed), "true") AND
         NOT contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "Windows")) OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "Temp") OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "Downloads") OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "AppData")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_signature), "Microsoft") OR
        contains(to_string($message.filebeat_data_win_eventdata_signature), "Windows")
    )
then
    set_field("sigma_rule_title", "Hardware Supply Chain - Suspicious Driver Load");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1195.003");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Compromise Hardware Supply Chain");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Hardware Additions - HID Device (T1200)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Hardware Additions - HID Device (T1200)",
    "description": "Detects new USB HID device installation (Rubber Ducky, BadUSB). Uses Sysmon Event 6 driver load.",
    "source": `rule "Sigma: Hardware Additions - HID Device (T1200)"
when
    has_field("filebeat_data_win_eventdata_imageLoaded") AND
    to_string($message.filebeat_data_win_system_eventID) == "6" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "hidusb") OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "kbdhid") OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "mouhid") OR
        contains(to_string($message.filebeat_data_win_eventdata_imageLoaded), "usb8023")
    )
then
    set_field("sigma_rule_title", "Hardware Additions - HID Device");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1200");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Hardware Additions");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Spearphishing via Service - Messaging App Child Process (T1566.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Spearphishing via Service (T1566.003)",
    "description": "Detects child processes from messaging apps (Teams, Slack, Discord) indicating potential phishing payload.",
    "source": `rule "Sigma: Spearphishing via Service (T1566.003)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Teams.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "slack.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Discord.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Telegram.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Signal.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "WhatsApp.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Zoom.exe")
    ) AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "wscript.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "cscript.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "rundll32.exe")
    )
then
    set_field("sigma_rule_title", "Spearphishing via Service");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1566.003");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Spearphishing via Service");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Spearphishing Voice - RMM Tool Installation (T1566.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Spearphishing Voice - RMM Tool Install (T1566.004)",
    "description": "Detects RMM tool installation from browser, common in callback phishing. Real campaigns: BazarCall, Luna Moth, Royal ransomware.",
    "source": `rule "Sigma: Spearphishing Voice - RMM Tool Install (T1566.004)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "chrome.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msedge.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "firefox.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "iexplore.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Downloads")
    ) AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "AnyDesk") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "TeamViewer") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "ScreenConnect") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "ConnectWise") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "RemotePC") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Splashtop") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "LogMeIn") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "GoToAssist") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Zoho") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "Atera") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "rustdesk")
    )
then
    set_field("sigma_rule_title", "Spearphishing Voice - RMM Tool Install");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1566.004");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Spearphishing Voice");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Content Injection - Browser Payload Execution (T1659)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Content Injection - Browser Payload (T1659)",
    "description": "Detects payload execution from browser temp/AppData after browsing. Real adversaries: MoustachedBouncer (DNS/HTTP/SMB reply injection).",
    "source": `rule "Sigma: Content Injection - Browser Payload (T1659)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "chrome.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msedge.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "firefox.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "iexplore.exe")
    ) AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "Temp") AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), ".exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), ".dll"))) OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "wscript.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "cscript.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "regsvr32.exe")
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "update") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "install")
    )
then
    set_field("sigma_rule_title", "Content Injection - Browser Payload");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1659");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Content Injection");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Wi-Fi Networks - Rogue AP Indicators (T1669)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Wi-Fi Networks - Wireless Recon Tools (T1669)",
    "description": "Detects wireless reconnaissance tools. Real adversaries: APT28 Nearest Neighbor attack. Limited host-based detection.",
    "source": `rule "Sigma: Wi-Fi Networks - Wireless Recon Tools (T1669)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "aircrack") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "airmon") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "airodump") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "kismet") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "wifite") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "hostapd-wpe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "fluxion") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "bettercap")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_image), "aircrack") OR
          contains(to_string($message.filebeat_data_eventdata_image), "airmon") OR
          contains(to_string($message.filebeat_data_eventdata_image), "airodump") OR
          contains(to_string($message.filebeat_data_eventdata_image), "kismet") OR
          contains(to_string($message.filebeat_data_eventdata_image), "wifite") OR
          contains(to_string($message.filebeat_data_eventdata_image), "hostapd-wpe") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "iwconfig") AND
          contains(to_string($message.filebeat_data_eventdata_commandLine), "mode") OR
          contains(to_string($message.filebeat_data_eventdata_image), "bettercap")))
    )
then
    set_field("sigma_rule_title", "Wi-Fi Networks - Wireless Recon Tools");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1669");
    set_field("sigma_mitre_tactic", "Initial Access");
    set_field("sigma_mitre_technique", "Wi-Fi Networks");
    set_field("sigma_detection_source", "Batch 1 Coverage");
    set_field("alert", true);
end`
});

// =============================================================================
// Summary Output
// =============================================================================
print("=============================================================================");
print("Batch 1 MITRE ATT&CK Coverage - Sigma Rules Deployed");
print("=============================================================================");
print("");
print("DISCOVERY (16 techniques, 18 rules):");
print("  T1010    - Application Window Discovery");
print("  T1016.001 - Internet Connection Discovery");
print("  T1016.002 - Wi-Fi Discovery");
print("  T1069.003 - Cloud Groups Discovery");
print("  T1497.002 - User Activity Based Checks (Sandbox Evasion)");
print("  T1497.003 - Time Based Checks (Sandbox Evasion)");
print("  T1518.002 - Backup Software Discovery");
print("  T1538    - Cloud Service Dashboard");
print("  T1580    - Cloud Infrastructure Discovery");
print("  T1613    - Container and Resource Discovery");
print("  T1614.001 - System Language Discovery");
print("  T1619    - Cloud Storage Object Discovery");
print("  T1622    - Debugger Evasion (Windows + Linux = 2 rules)");
print("  T1652    - Device Driver Discovery (Windows + Linux = 2 rules)");
print("  T1673    - Virtual Machine Discovery");
print("  T1680    - Local Storage Discovery");
print("");
print("LATERAL MOVEMENT (9 techniques, 9 rules):");
print("  T1021.005 - VNC");
print("  T1021.007 - Cloud Services");
print("  T1021.008 - Direct Cloud VM Connections");
print("  T1072    - Software Deployment Tools");
print("  T1080    - Taint Shared Content");
print("  T1091    - Replication Through Removable Media");
print("  T1210    - Exploitation of Remote Services");
print("  T1550.004 - Web Session Cookie");
print("  T1563.001 - SSH Hijacking");
print("");
print("INITIAL ACCESS (11 techniques, 11 rules):");
print("  T1078.001 - Default Accounts");
print("  T1078.002 - Domain Accounts");
print("  T1078.003 - Local Accounts");
print("  T1091    - (Shared with Lateral Movement)");
print("  T1195.001 - Supply Chain: Software Dependencies");
print("  T1195.003 - Supply Chain: Hardware");
print("  T1200    - Hardware Additions");
print("  T1566.003 - Spearphishing via Service");
print("  T1566.004 - Spearphishing Voice (Callback Phishing)");
print("  T1659    - Content Injection");
print("  T1669    - Wi-Fi Networks");
print("");
print("TOTAL: 36 unique techniques, 38 rules (including dual OS variants)");
print("=============================================================================");
print("");
print("Next steps:");
print("1. Rebuild Sigma Detection Pipeline to include new rules");
print("2. Restart Graylog: docker restart graylog");
print("3. Test with Fomorian attack logs");
print("");
