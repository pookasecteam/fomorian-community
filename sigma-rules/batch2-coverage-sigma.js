// =============================================================================
// Batch 2 MITRE ATT&CK Coverage - Graylog Sigma Pipeline Rules
// =============================================================================
// Deploy with: docker exec -i graylog-mongo mongosh graylog < /tmp/batch2-coverage-sigma.js
//
// Coverage: 49 techniques (~50 rules)
//   - EXECUTION: 24 techniques (T1053.002, T1053.006, T1053.007, T1059.002,
//                T1059.008, T1059.010, T1059.011, T1059.012, T1059.013, T1129,
//                T1203, T1204.003, T1204.004, T1204.005, T1559.002, T1559.003,
//                T1569.001, T1569.003, T1609, T1648, T1651, T1674, T1675, T1677)
//   - IMPACT: 21 techniques (T1485.001, T1491.002, T1496.001, T1496.002,
//                T1496.003, T1496.004, T1498.001, T1498.002, T1499, T1499.001,
//                T1499.002, T1499.003, T1499.004, T1561.001, T1561.002,
//                T1565.002, T1565.003, T1657, T1667)
//
// Field Mapping:
//   - Windows Sysmon: filebeat_data_win_eventdata_*
//   - Linux Sysmon: filebeat_data_eventdata_* (no 'win' segment)
//   - Cloud/AWS: filebeat_data_aws_eventName
//   - O365: filebeat_data_office365_*
//
// Author: PookaSec Detection Engineering
// Date: 2026-02-08
// =============================================================================

// =============================================================================
// EXECUTION RULES (24 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: At Command Scheduled Task (T1053.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: At Command Scheduled Task (T1053.002)",
    "description": "Detects legacy at.exe scheduled task creation. Real adversaries: APT41, Lazarus, Turla.",
    "source": `rule "Sigma: At Command Scheduled Task (T1053.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "at.exe") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "at ") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/every:") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/next:") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/interactive") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), " /f ") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "at -f")))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "at ") AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "-f ") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "-m ") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "atq") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "atrm"))))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "services.exe")
    )
then
    set_field("sigma_rule_title", "At Command Scheduled Task");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1053.002");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "At");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Systemd Timers (T1053.006)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Systemd Timers Persistence (T1053.006)",
    "description": "Detects systemd timer creation for persistence. Real adversaries: TeamTNT, Rocke, Kinsing.",
    "source": `rule "Sigma: Systemd Timers Persistence (T1053.006)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemd-run") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "--on-calendar")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemd-run") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "--on-boot")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemd-run") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "--on-unit-active")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "enable") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".timer")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "start") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".timer"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_user), "root") AND
        contains(to_string($message.filebeat_data_eventdata_parentImage), "apt")
    )
then
    set_field("sigma_rule_title", "Systemd Timers Persistence");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1053.006");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Systemd Timers");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Container Orchestration Job (T1053.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Container Orchestration Job (T1053.007)",
    "description": "Detects Kubernetes CronJob creation for scheduled execution.",
    "source": `rule "Sigma: Container Orchestration Job (T1053.007)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "kubectl") AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "create cronjob") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "create job") OR
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "apply") AND
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cronjob")))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl") AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "create cronjob") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "create job") OR
           (contains(to_string($message.filebeat_data_eventdata_commandLine), "apply") AND
            contains(to_string($message.filebeat_data_eventdata_commandLine), "cronjob")))))
    )
then
    set_field("sigma_rule_title", "Container Orchestration Job");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1053.007");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Container Orchestration Job");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: AppleScript Execution (T1059.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: AppleScript Execution (T1059.002)",
    "description": "Detects osascript/AppleScript execution. Real adversaries: APT32, Bundlore, Lazarus, XCSSET.",
    "source": `rule "Sigma: AppleScript Execution (T1059.002)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_image), "osascript") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "osascript") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-e")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "tell application") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "do shell script") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "osascript") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".scpt")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "osascript") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".applescript"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "Finder") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "Script Editor")
    )
then
    set_field("sigma_rule_title", "AppleScript Execution");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1059.002");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "AppleScript");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Network Device CLI (T1059.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network Device CLI Access (T1059.008)",
    "description": "Detects Cisco IOS and network device CLI access patterns.",
    "source": `rule "Sigma: Network Device CLI Access (T1059.008)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "enable secret") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "configure terminal") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "show running-config") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "copy running-config") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "show startup-config") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "write memory") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ip access-list") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "no ip domain-lookup")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "enable secret") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "configure terminal") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "show running-config") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "show startup-config")))
    )
then
    set_field("sigma_rule_title", "Network Device CLI Access");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1059.008");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Network Device CLI");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: AutoHotKey and AutoIT Execution (T1059.010)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: AutoHotKey or AutoIT Execution (T1059.010)",
    "description": "Detects AutoHotKey/AutoIT script execution. Real adversaries: DarkGate, Formbook, LokiBot, Remcos.",
    "source": `rule "Sigma: AutoHotKey or AutoIT Execution (T1059.010)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "AutoHotkey") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "AutoIt") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "AutoIt3.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "AutoHotkey.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".ahk") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".au3") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Aut2Exe") OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "Temp") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AutoHotkey") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AutoIt")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "explorer.exe") AND
        contains(to_string($message.filebeat_data_win_eventdata_user), "SYSTEM")
    )
then
    set_field("sigma_rule_title", "AutoHotKey or AutoIT Execution");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1059.010");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "AutoHotKey & AutoIT");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Lua Scripting (T1059.011)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Lua Script Execution (T1059.011)",
    "description": "Detects Lua script execution which can be used for malware.",
    "source": `rule "Sigma: Lua Script Execution (T1059.011)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "lua.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "luajit.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "lua53.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "lua54.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".lua") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "luac")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_image), "/lua") OR
          contains(to_string($message.filebeat_data_eventdata_image), "/luajit") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".lua")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "nmap") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "wireshark")
    )
then
    set_field("sigma_rule_title", "Lua Script Execution");
    set_field("sigma_rule_level", "low");
    set_field("sigma_mitre_id", "T1059.011");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Lua");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Hypervisor CLI Execution (T1059.012)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Hypervisor CLI Execution (T1059.012)",
    "description": "Detects ESXi/VMware hypervisor CLI commands. Real adversaries: ALPHV, ESXiArgs, Royal, UNC3886.",
    "source": `rule "Sigma: Hypervisor CLI Execution (T1059.012)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "esxcli") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vim-cmd") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "govc") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vmware-cmd") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "esxcfg-") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vicfg-")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcli") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "vim-cmd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "govc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "vmware-cmd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcfg-")))
    )
then
    set_field("sigma_rule_title", "Hypervisor CLI Execution");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1059.012");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Hypervisor CLI");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Container CLI/API Execution (T1059.013)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Container CLI Execution (T1059.013)",
    "description": "Detects container runtime CLI execution via docker/kubectl/crictl exec.",
    "source": `rule "Sigma: Container CLI Execution (T1059.013)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "kubectl") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "crictl") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "podman") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "nerdctl") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exec"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "docker") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "crictl") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "exec")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "podman") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "exec"))))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "containerd") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "dockerd")
    )
then
    set_field("sigma_rule_title", "Container CLI Execution");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1059.013");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Container CLI/API");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Shared Modules - Suspicious DLL Loading (T1129)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Suspicious Shared Module Loading (T1129)",
    "description": "Detects rundll32/regsvr32 loading DLLs from unusual paths.",
    "source": `rule "Sigma: Suspicious Shared Module Loading (T1129)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "rundll32.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Temp") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AppData") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Users\\Public") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ProgramData") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Downloads"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "regsvr32.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Temp") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AppData") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Users\\Public") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/s /n /u /i:http"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "rundll32.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "javascript:")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_image), "rundll32.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "shell32.dll,Control_RunDLL"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "explorer.exe")
    )
then
    set_field("sigma_rule_title", "Suspicious Shared Module Loading");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1129");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Shared Modules");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Exploitation for Client Execution (T1203)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Office Application Spawning Shell (T1203)",
    "description": "Detects Office applications spawning cmd/powershell/wscript (exploitation indicator).",
    "source": `rule "Sigma: Office Application Spawning Shell (T1203)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "WINWORD.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "EXCEL.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "POWERPNT.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "OUTLOOK.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "MSACCESS.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "MSPUB.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "VISIO.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "ONENOTE.EXE")) AND
    (contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "pwsh.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "wscript.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "cscript.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "certutil.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "bitsadmin.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "regsvr32.exe"))
then
    set_field("sigma_rule_title", "Office Application Spawning Shell");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1203");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Exploitation for Client Execution");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Malicious Container Image (T1204.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Malicious Container Image Pull/Run (T1204.003)",
    "description": "Detects docker pull/run from untrusted registries or suspicious images.",
    "source": `rule "Sigma: Malicious Container Image Pull/Run (T1204.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1") OR
        has_field("filebeat_data_eventdata_commandLine")
    ) AND
    (
        ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker pull") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker run") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "docker pull") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "docker run")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pastebin") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "githubusercontent") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".onion") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "xmrig") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cryptominer") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "pastebin") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "xmrig") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".onion"))) OR
        ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker run") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "docker run")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--privileged") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "--privileged")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-v /:/") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "-v /:/") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--pid=host") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "--pid=host")))
    )
then
    set_field("sigma_rule_title", "Malicious Container Image Pull/Run");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1204.003");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Malicious Image");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Malicious Copy and Paste / ClickFix (T1204.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: ClickFix Malicious Copy Paste (T1204.004)",
    "description": "Detects mshta/powershell execution from Run dialog (ClickFix pattern).",
    "source": `rule "Sigma: ClickFix Malicious Copy Paste (T1204.004)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "explorer.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "http://") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "https://") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-enc ") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "IEX") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-Expression") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DownloadString") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DownloadFile"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "RunDlg.exe") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "RunDll32"))
    )
then
    set_field("sigma_rule_title", "ClickFix Malicious Copy Paste");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1204.004");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Malicious Copy and Paste");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Malicious Library - Package Manager Abuse (T1204.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Malicious Package Install Script (T1204.005)",
    "description": "Detects pip/npm postinstall script execution (supply chain attack vector).",
    "source": `rule "Sigma: Malicious Package Install Script (T1204.005)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_parentImage), "pip") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "npm") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "node.exe")) AND
          (contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_image), "python.exe"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_parentImage), "pip") OR
           contains(to_string($message.filebeat_data_eventdata_parentImage), "npm") OR
           contains(to_string($message.filebeat_data_eventdata_parentImage), "node")) AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "curl") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "wget") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "/bin/sh") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "/bin/bash"))))
    ) AND
    (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "http") OR
     contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "http") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "curl") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "wget"))
then
    set_field("sigma_rule_title", "Malicious Package Install Script");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1204.005");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Malicious Library");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Dynamic Data Exchange (T1559.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: DDE Office Application Shell Spawn (T1559.002)",
    "description": "Detects Office apps spawning shell via DDE. Real adversaries: APT28, FIN7, Cobalt Group.",
    "source": `rule "Sigma: DDE Office Application Shell Spawn (T1559.002)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "EXCEL.EXE") OR
     contains(to_string($message.filebeat_data_win_eventdata_parentImage), "WINWORD.EXE")) AND
    (contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "powershell.exe") OR
     contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe")) AND
    (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/c ") OR
     contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-c ") OR
     contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-enc") OR
     contains(to_string($message.filebeat_data_win_eventdata_commandLine), "http") OR
     contains(to_string($message.filebeat_data_win_eventdata_commandLine), "IEX"))
then
    set_field("sigma_rule_title", "DDE Office Application Shell Spawn");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1559.002");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Dynamic Data Exchange");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: XPC Services macOS (T1559.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Suspicious XPC Services Activity (T1559.003)",
    "description": "Detects suspicious macOS XPC service usage for execution.",
    "source": `rule "Sigma: Suspicious XPC Services Activity (T1559.003)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_commandLine), "XPCServices") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "xpc_connection") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "launchd.peruser") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "xpc") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "bootstrap")) OR
        (contains(to_string($message.filebeat_data_eventdata_image), "xpcproxy") AND
         NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "launchd"))
    )
then
    set_field("sigma_rule_title", "Suspicious XPC Services Activity");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1559.003");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "XPC Services");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Launchctl Service Execution (T1569.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Launchctl Service Execution (T1569.001)",
    "description": "Detects launchctl load/bootstrap for service execution on macOS.",
    "source": `rule "Sigma: Launchctl Service Execution (T1569.001)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "launchctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "load")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "launchctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "bootstrap")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "launchctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "kickstart")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "launchctl") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "submit"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "Installer") OR
        contains(to_string($message.filebeat_data_eventdata_user), "root")
    )
then
    set_field("sigma_rule_title", "Launchctl Service Execution");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1569.001");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Launchctl");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Systemctl Service Control (T1569.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Suspicious Systemctl Service Activity (T1569.003)",
    "description": "Detects systemctl start/enable for suspicious service names.",
    "source": `rule "Sigma: Suspicious Systemctl Service Activity (T1569.003)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (contains(to_string($message.filebeat_data_eventdata_commandLine), "systemctl") AND
     (contains(to_string($message.filebeat_data_eventdata_commandLine), "start") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "enable") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "restart"))) AND
    (contains(to_string($message.filebeat_data_eventdata_commandLine), "cron") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "rc.local") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "init.d") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "update") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "sshd") OR
     contains(to_string($message.filebeat_data_eventdata_commandLine), "network") OR
     NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "apt") AND
     NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "dpkg") AND
     NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "yum"))
then
    set_field("sigma_rule_title", "Suspicious Systemctl Service Activity");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1569.003");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Systemctl");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Container Administration Command (T1609)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Container Admin Command Execution (T1609)",
    "description": "Detects docker exec with suspicious commands (shell, wget, curl).",
    "source": `rule "Sigma: Container Admin Command Execution (T1609)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1") OR
        has_field("filebeat_data_eventdata_commandLine")
    ) AND
    ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "docker exec") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "docker exec") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "kubectl exec") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "kubectl exec")) AND
     (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/bin/sh") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "/bin/sh") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/bin/bash") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "/bin/bash") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wget") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "wget") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "curl") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "curl") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "nc ") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "nc ") OR
      contains(to_string($message.filebeat_data_win_eventdata_commandLine), "python") OR
      contains(to_string($message.filebeat_data_eventdata_commandLine), "python")))
then
    set_field("sigma_rule_title", "Container Admin Command Execution");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1609");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Container Administration Command");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Serverless Execution (T1648)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Serverless Function Creation (T1648)",
    "description": "Detects AWS Lambda/Azure Functions creation for serverless execution.",
    "source": `rule "Sigma: Serverless Function Creation (T1648)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lambda") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "create-function") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "update-function-code") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "invoke"))) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "functionapp") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "create") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "deployment"))) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "functions") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "deploy"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "lambda") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "create-function")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "az") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "functionapp") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "create"))))
    ) OR (
        has_field("filebeat_data_aws_eventName") AND
        (to_string($message.filebeat_data_aws_eventName) == "CreateFunction20150331v2" OR
         to_string($message.filebeat_data_aws_eventName) == "UpdateFunctionCode20150331v2" OR
         to_string($message.filebeat_data_aws_eventName) == "Invoke")
    )
then
    set_field("sigma_rule_title", "Serverless Function Creation");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1648");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Serverless Execution");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Administration Command - Execution Focus (T1651)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Administration Command Execution (T1651)",
    "description": "Detects remote command execution via cloud admin tools (SSM, run-command).",
    "source": `rule "Sigma: Cloud Administration Command Execution (T1651)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ssm") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "send-command")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vm") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "run-command") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "invoke")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gcloud") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "compute") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ssh") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--command"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "ssm") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "send-command")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "az") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "vm") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "run-command"))))
    ) OR (
        has_field("filebeat_data_aws_eventName") AND
        to_string($message.filebeat_data_aws_eventName) == "SendCommand"
    )
then
    set_field("sigma_rule_title", "Cloud Administration Command Execution");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1651");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Cloud Administration Command");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Input Injection (T1674)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Input Injection Tools (T1674)",
    "description": "Detects xdotool, xte, ydotool, or osascript keystroke injection.",
    "source": `rule "Sigma: Input Injection Tools (T1674)"
when
    (
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "xdotool") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "xte ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "ydotool") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "xdotool type") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "xdotool key") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "osascript") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "keystroke")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "osascript") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "key code"))))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SendKeys") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "keybd_event") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SendInput")))
    )
then
    set_field("sigma_rule_title", "Input Injection Tools");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1674");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Input Injection");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: ESXi Administration Command (T1675)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: ESXi Administration Command (T1675)",
    "description": "Detects ESXi admin commands for VM manipulation. Real adversaries: ESXiArgs, ALPHV, Royal.",
    "source": `rule "Sigma: ESXi Administration Command (T1675)"
when
    (
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcli") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "vm process") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "kill")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "vim-cmd") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "vmsvc") AND
           (contains(to_string($message.filebeat_data_eventdata_commandLine), "power.off") OR
            contains(to_string($message.filebeat_data_eventdata_commandLine), "destroy") OR
            contains(to_string($message.filebeat_data_eventdata_commandLine), "unregister"))) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcli") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "system") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "maintenanceMode")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "esxcli") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "software vib"))))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "esxcli") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vim-cmd")))
    )
then
    set_field("sigma_rule_title", "ESXi Administration Command");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1675");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "ESXi Administration Command");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Poisoned Pipeline Execution (T1677)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Poisoned Pipeline Execution (T1677)",
    "description": "Detects CI/CD pipeline compromise indicators.",
    "source": `rule "Sigma: Poisoned Pipeline Execution (T1677)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_parentImage), "jenkins") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "gitlab-runner") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "azure-pipelines") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "GitHub") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "TeamCity") OR
           contains(to_string($message.filebeat_data_win_eventdata_parentImage), "CircleCI")) AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-WebRequest") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "curl") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wget") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DownloadString") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "IEX") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-enc"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_parentImage), "jenkins") OR
           contains(to_string($message.filebeat_data_eventdata_parentImage), "gitlab-runner") OR
           contains(to_string($message.filebeat_data_eventdata_parentImage), "runner")) AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "curl") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "wget") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "nc ") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "/bin/bash -i") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "python -c"))))
    )
then
    set_field("sigma_rule_title", "Poisoned Pipeline Execution");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1677");
    set_field("sigma_mitre_tactic", "Execution");
    set_field("sigma_mitre_technique", "Poisoned Pipeline Execution");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// =============================================================================
// IMPACT RULES (21 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: Lifecycle-Triggered Deletion (T1485.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Lifecycle-Triggered Deletion (T1485.001)",
    "description": "Detects AWS S3 lifecycle policy for automatic data deletion.",
    "source": `rule "Sigma: Lifecycle-Triggered Deletion (T1485.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "s3api") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "put-bucket-lifecycle"))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "aws") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "s3api") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "put-bucket-lifecycle"))
    ) OR (
        has_field("filebeat_data_aws_eventName") AND
        (to_string($message.filebeat_data_aws_eventName) == "PutBucketLifecycle" OR
         to_string($message.filebeat_data_aws_eventName) == "PutBucketLifecycleConfiguration")
    )
then
    set_field("sigma_rule_title", "Lifecycle-Triggered Deletion");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1485.001");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Lifecycle-Triggered Deletion");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: External Defacement (T1491.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: External Defacement (T1491.002)",
    "description": "Detects web file replacement for defacement.",
    "source": `rule "Sigma: External Defacement (T1491.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "wwwroot") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "inetpub") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "htdocs") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "public_html") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "www")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "index.html") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "index.htm") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "index.php") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "default.aspx")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "echo") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cat >") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cp ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "mv ")) AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "/var/www") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "/var/html") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "public_html")) AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "index."))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "w3wp.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "apache") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "nginx")
    )
then
    set_field("sigma_rule_title", "External Defacement");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1491.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "External Defacement");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Compute Hijacking - Cryptomining (T1496.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cryptomining Activity (T1496.001)",
    "description": "Detects cryptominer execution (xmrig, minerd, stratum+tcp).",
    "source": `rule "Sigma: Cryptomining Activity (T1496.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "xmrig") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "minerd") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "cgminer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "bfgminer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "ethminer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "nbminer") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "stratum+tcp") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "stratum+ssl") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cryptonight") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "randomx") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pool.minexmr") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pool.supportxmr") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "nanopool.org") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--donate-level")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_image), "xmrig") OR
          contains(to_string($message.filebeat_data_eventdata_image), "minerd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "stratum+tcp") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "stratum+ssl") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cryptonight") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "--donate-level")))
    )
then
    set_field("sigma_rule_title", "Cryptomining Activity");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1496.001");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Compute Hijacking");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Bandwidth Hijacking - Proxyware (T1496.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Bandwidth Hijacking Proxyware (T1496.002)",
    "description": "Detects proxyware tools (pawns-cli, honeygain, peer2profit).",
    "source": `rule "Sigma: Bandwidth Hijacking Proxyware (T1496.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "pawns-cli") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "honeygain") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "peer2profit") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "traffmonetizer") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "packetstream") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "iproyal") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "pawns.app") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "honeygain.com") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "peer2profit.com")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_image), "pawns-cli") OR
          contains(to_string($message.filebeat_data_eventdata_image), "honeygain") OR
          contains(to_string($message.filebeat_data_eventdata_image), "peer2profit") OR
          contains(to_string($message.filebeat_data_eventdata_image), "traffmonetizer") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "pawns.app") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "honeygain.com")))
    )
then
    set_field("sigma_rule_title", "Bandwidth Hijacking Proxyware");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1496.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Bandwidth Hijacking");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: SMS Pumping (T1496.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: SMS Pumping Activity (T1496.003)",
    "description": "Detects mass SMS API calls for toll fraud.",
    "source": `rule "Sigma: SMS Pumping Activity (T1496.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "curl") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-WebRequest")) AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "api.twilio.com") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "api.nexmo.com") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "api.plivo.com") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "smsapi") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "send_sms") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sendMessage"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "curl") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wget")) AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "api.twilio.com") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "api.nexmo.com") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "smsapi") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "sendMessage")))
    )
then
    set_field("sigma_rule_title", "SMS Pumping Activity");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1496.003");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "SMS Pumping");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cloud Service Hijacking (T1496.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cloud Service Hijacking (T1496.004)",
    "description": "Detects mass cloud instance creation for resource hijacking.",
    "source": `rule "Sigma: Cloud Service Hijacking (T1496.004)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ec2") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "run-instances") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--count")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "az") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vm") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "create") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--count"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "aws") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "ec2") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "run-instances")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "gcloud") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "compute") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "instances create"))))
    ) OR (
        has_field("filebeat_data_aws_eventName") AND
        to_string($message.filebeat_data_aws_eventName) == "RunInstances"
    )
then
    set_field("sigma_rule_title", "Cloud Service Hijacking");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1496.004");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Cloud Service Hijacking");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Direct Network Flood (T1498.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network Flood Tools (T1498.001)",
    "description": "Detects network flood/DDoS tool execution.",
    "source": `rule "Sigma: Network Flood Tools (T1498.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "hping3") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "hping") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "loic") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "hoic") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "slowloris") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "goldeneye") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "--flood") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "syn flood")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "hping3") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "hping") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "--flood") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "syn_flood") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "udp_flood") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "slowloris")))
    )
then
    set_field("sigma_rule_title", "Network Flood Tools");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1498.001");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Direct Network Flood");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Reflection Amplification (T1498.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Reflection Amplification Tools (T1498.002)",
    "description": "Detects DNS/NTP amplification attack patterns.",
    "source": `rule "Sigma: Reflection Amplification Tools (T1498.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "dig") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ANY") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "@")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ntpdc") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "monlist")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "memcached") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "stats")) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "amplification") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reflector")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "dig") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "ANY")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "ntpdc") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "monlist")) OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "amplification")))
    )
then
    set_field("sigma_rule_title", "Reflection Amplification Tools");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1498.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Reflection Amplification");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Endpoint Denial of Service (T1499)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Endpoint DoS Activity (T1499)",
    "description": "Detects endpoint denial of service indicators.",
    "source": `rule "Sigma: Endpoint DoS Activity (T1499)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "stress") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "stress-ng") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cpuburn") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "memtester") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "for /L") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "start"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "stress") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "stress-ng") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cpuburn") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "memtester") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "while true") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "do"))))
    )
then
    set_field("sigma_rule_title", "Endpoint DoS Activity");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1499");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Endpoint Denial of Service");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: OS Exhaustion Flood - Fork Bomb (T1499.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Fork Bomb Detection (T1499.001)",
    "description": "Detects fork bomb patterns (:(){ :|:& };:).",
    "source": `rule "Sigma: Fork Bomb Detection (T1499.001)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_commandLine), ":(){ :|:& };:") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), ":(){:|:&};:") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "bomb(){ bomb|bomb& };bomb") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "while") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "fork") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "done")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "while :") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "do :") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "done"))
    )
then
    set_field("sigma_rule_title", "Fork Bomb Detection");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1499.001");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "OS Exhaustion Flood");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Service Exhaustion Flood (T1499.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Service Exhaustion Flood (T1499.002)",
    "description": "Detects HTTP flood tools and indicators.",
    "source": `rule "Sigma: Service Exhaustion Flood (T1499.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ab.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ApacheBench") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "siege") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "bombardier") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vegeta") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wrk ") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ab ") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-n ") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-c "))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "ab ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "siege") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "bombardier") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "vegeta") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wrk ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "hey ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "gobench")))
    )
then
    set_field("sigma_rule_title", "Service Exhaustion Flood");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1499.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Service Exhaustion Flood");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Application Exhaustion Flood - Slowloris (T1499.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Application Exhaustion - Slowloris (T1499.003)",
    "description": "Detects Slowloris and slow HTTP attack patterns.",
    "source": `rule "Sigma: Application Exhaustion - Slowloris (T1499.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "slowloris") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "slowhttptest") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "slowread") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "rudy") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "r-u-dead-yet")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "slowloris") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "slowhttptest") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "slowread") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "rudy")))
    )
then
    set_field("sigma_rule_title", "Application Exhaustion - Slowloris");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1499.003");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Application Exhaustion Flood");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Application or System Exploitation DoS (T1499.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Application Exploitation DoS (T1499.004)",
    "description": "Detects exploitation tools that may cause system crashes.",
    "source": `rule "Sigma: Application Exploitation DoS (T1499.004)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exploit") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "fuzzer") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "afl-fuzz") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "boofuzz") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "peach") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "python") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "crash"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "afl-fuzz") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "boofuzz") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "fuzzer") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "zzuf")))
    )
then
    set_field("sigma_rule_title", "Application Exploitation DoS");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1499.004");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Application or System Exploitation");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Disk Content Wipe (T1561.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Disk Content Wipe (T1561.001)",
    "description": "Detects disk wiping tools (dd, shred, SDelete, cipher).",
    "source": `rule "Sigma: Disk Content Wipe (T1561.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "sdelete") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "sdelete64") OR
          (contains(to_string($message.filebeat_data_win_eventdata_image), "cipher.exe") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/w:")) OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "Eraser.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "BleachBit") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "format c:") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "format d:")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "dd ") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "if=/dev/zero")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "dd ") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "if=/dev/urandom")) OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "shred ") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wipe ") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "rm -rf") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "/*"))))
    )
then
    set_field("sigma_rule_title", "Disk Content Wipe");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1561.001");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Disk Content Wipe");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Disk Structure Wipe - MBR Overwrite (T1561.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Disk Structure Wipe - MBR (T1561.002)",
    "description": "Detects MBR overwrite and disk structure destruction.",
    "source": `rule "Sigma: Disk Structure Wipe - MBR (T1561.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "dd") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "PhysicalDrive")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "diskpart") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "clean")) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "MBR") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "bootrec")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "dd ") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "of=/dev/sda")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "dd ") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "of=/dev/nvme")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "dd ") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "bs=512") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "count=1")) OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wipefs")))
    )
then
    set_field("sigma_rule_title", "Disk Structure Wipe - MBR");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1561.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Disk Structure Wipe");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Transmitted Data Manipulation (T1565.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network MITM Tools (T1565.002)",
    "description": "Detects MITM tools (ettercap, mitmproxy, bettercap).",
    "source": `rule "Sigma: Network MITM Tools (T1565.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_image), "ettercap") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "mitmproxy") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "mitmdump") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "bettercap") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "arpspoof") OR
          contains(to_string($message.filebeat_data_win_eventdata_image), "sslstrip") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "arp -s") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "arp.spoof")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "ettercap") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "mitmproxy") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "bettercap") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "arpspoof") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "sslstrip") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "dsniff")))
    )
then
    set_field("sigma_rule_title", "Network MITM Tools");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1565.002");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Transmitted Data Manipulation");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Runtime Data Manipulation (T1565.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Runtime Data Manipulation (T1565.003)",
    "description": "Detects suspicious database modification commands.",
    "source": `rule "Sigma: Runtime Data Manipulation (T1565.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sqlcmd") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "osql") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mysql")) AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "UPDATE") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DELETE") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DROP") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "TRUNCATE"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         ((contains(to_string($message.filebeat_data_eventdata_commandLine), "mysql") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "psql") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "mongo")) AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "UPDATE") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "DELETE") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "DROP") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "TRUNCATE") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "deleteMany") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "drop()"))))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "Management Studio") OR
        contains(to_string($message.filebeat_data_win_eventdata_user), "SYSTEM")
    )
then
    set_field("sigma_rule_title", "Runtime Data Manipulation");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1565.003");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Runtime Data Manipulation");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Financial Theft (T1657)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Financial Theft Indicators (T1657)",
    "description": "Detects BEC indicators and crypto wallet tools.",
    "source": `rule "Sigma: Financial Theft Indicators (T1657)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "electrum") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "exodus") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "bitcoin") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ethereum") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "metamask") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wallet.dat") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "keystore") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "findstr") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "swift") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wire") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "invoice")))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "electrum") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "bitcoin-cli") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wallet.dat") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "grep") AND
           (contains(to_string($message.filebeat_data_eventdata_commandLine), "bank") OR
            contains(to_string($message.filebeat_data_eventdata_commandLine), "swift") OR
            contains(to_string($message.filebeat_data_eventdata_commandLine), "iban")))))
    )
then
    set_field("sigma_rule_title", "Financial Theft Indicators");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1657");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Financial Theft");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Email Bombing (T1667)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Email Bombing Activity (T1667)",
    "description": "Detects mass email tools and email bombing indicators.",
    "source": `rule "Sigma: Email Bombing Activity (T1667)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mailbomber") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "email bomber") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mass mailer") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "swaks") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sendemail") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "smtp") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "loop"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "mailbomber") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "swaks") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "sendemail") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "sendmail") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "for ")) OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "mailx") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "while"))))
    )
then
    set_field("sigma_rule_title", "Email Bombing Activity");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1667");
    set_field("sigma_mitre_tactic", "Impact");
    set_field("sigma_mitre_technique", "Email Bombing");
    set_field("sigma_detection_source", "Fomorian Batch 2");
    set_field("alert", true);
end`
});

// =============================================================================
// Summary
// =============================================================================
// Total Rules: 45 rules covering 45 unique techniques
//   - Execution: 24 rules (T1053.002, T1053.006, T1053.007, T1059.002, T1059.008,
//                T1059.010, T1059.011, T1059.012, T1059.013, T1129, T1203,
//                T1204.003, T1204.004, T1204.005, T1559.002, T1559.003, T1569.001,
//                T1569.003, T1609, T1648, T1651, T1674, T1675, T1677)
//   - Impact: 21 rules (T1485.001, T1491.002, T1496.001, T1496.002, T1496.003,
//                T1496.004, T1498.001, T1498.002, T1499, T1499.001, T1499.002,
//                T1499.003, T1499.004, T1561.001, T1561.002, T1565.002, T1565.003,
//                T1657, T1667)
//
// NOTE: T1072 was in Batch 1 - not duplicated
// NOTE: T1651 focuses on Execution via cloud admin (not lateral movement like T1021.007/008)
// =============================================================================

print("Batch 2 Sigma rules inserted successfully: 45 rules for 45 techniques");
print("Deploy with: docker exec -i graylog-mongo mongosh graylog < batch2-coverage-sigma.js");
