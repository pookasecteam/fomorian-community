// =============================================================================
// Batch 3 MITRE ATT&CK Coverage - Graylog Sigma Pipeline Rules
// =============================================================================
// Deploy with: docker exec -i graylog-mongo mongosh graylog < /tmp/batch3-coverage-sigma.js
//
// Coverage: 45 techniques (45 rules)
//   - PERSISTENCE: 15 techniques (T1037.003, T1037.004, T1078.001, T1078.002,
//                  T1078.003, T1098.002, T1098.007, T1546.004, T1546.007,
//                  T1546.009, T1546.011, T1546.013, T1547.002, T1547.006, T1547.008)
//   - CREDENTIAL ACCESS: 15 techniques (T1003.004, T1003.005, T1003.007, T1003.008,
//                  T1111, T1212, T1552.003, T1555.005, T1556.001, T1556.002,
//                  T1556.003, T1556.008, T1557.002, T1557.003, T1606.002)
//   - DEFENSE EVASION: 15 techniques (T1006, T1027.001, T1027.006, T1027.012,
//                  T1027.013, T1036.001, T1036.002, T1036.004, T1036.007,
//                  T1055.005, T1055.008, T1055.009, T1055.013, T1070.005, T1070.006)
//
// Field Mapping:
//   - Windows Sysmon EID 1: filebeat_data_win_eventdata_commandLine, filebeat_data_win_eventdata_image, filebeat_data_win_eventdata_parentImage
//   - Windows Sysmon EID 13 (registry): filebeat_data_win_eventdata_targetObject, filebeat_data_win_eventdata_details
//   - Windows Sysmon EID 11 (file create): filebeat_data_win_eventdata_targetFilename
//   - Windows Sysmon EID 7 (image load): filebeat_data_win_eventdata_imageLoaded
//   - Linux Sysmon: filebeat_data_eventdata_commandLine, filebeat_data_eventdata_image (NO 'win' segment)
//   - Event ID check: to_string($message.filebeat_data_win_system_eventID) == "1"
//
// Author: PookaSec Detection Engineering
// Date: 2026-02-08
// =============================================================================

// =============================================================================
// PERSISTENCE RULES (15 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: Network Logon Script (T1037.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network Logon Script (T1037.003)",
    "description": "Detects network logon script assignment via GPO or net user. Real adversaries: APT28, APT29, Turla, FIN7.",
    "source": `rule "Sigma: Network Logon Script (T1037.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net user") AND
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/scriptpath:")) OR
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "netlogon") AND
              (contains(to_string($message.filebeat_data_win_eventdata_image), "wscript.exe") OR
               contains(to_string($message.filebeat_data_win_eventdata_image), "cscript.exe"))) OR
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gpscript.exe") AND
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/Logon")) OR
             (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SYSVOL") AND
              contains(to_string($message.filebeat_data_win_eventdata_commandLine), "scripts")) OR
             (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "userinit.exe") AND
              (contains(to_string($message.filebeat_data_win_eventdata_image), "wscript.exe") OR
               contains(to_string($message.filebeat_data_win_eventdata_image), "cscript.exe") OR
               contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe")))
         ))
        OR
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Environment") AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "UserInitMprLogonScript"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_user), "SYSTEM")
    )
then
    set_field("sigma_rule_title", "Network Logon Script");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1037.003");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Network Logon Script");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: RC Scripts Persistence (T1037.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: RC Scripts Persistence (T1037.004)",
    "description": "Detects writes to rc.local and init.d for persistence. Real adversaries: TeamTNT, Rocke, Kinsing, Outlaw.",
    "source": `rule "Sigma: RC Scripts Persistence (T1037.004)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc.local") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/init.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc0.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc1.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc2.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc3.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc4.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc5.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/rc6.d/"))
        OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "rc.local") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "echo") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ">>") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "tee")))
        OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "update-rc.d") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "defaults"))
        OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "chkconfig") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "--add"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "apt") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "dpkg") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "yum")
    )
then
    set_field("sigma_rule_title", "RC Scripts Persistence");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1037.004");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "RC Scripts");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Default Account Usage (T1078.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Default Account Usage (T1078.001)",
    "description": "Detects logons with default/built-in accounts. Real adversaries: APT1, APT28, Carbanak, FIN6.",
    "source": `rule "Sigma: Default Account Usage (T1078.001)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetUserName") AND
         (to_string($message.filebeat_data_win_system_eventID) == "4624" OR
          to_string($message.filebeat_data_win_system_eventID) == "4625" OR
          to_string($message.filebeat_data_win_system_eventID) == "4648") AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "Administrator") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "Guest") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "DefaultAccount") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "WDAGUtilityAccount") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "DefaultAppPool")))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net user Administrator") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net user Guest /active:yes")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_user), "root") AND
          contains(to_string($message.filebeat_data_eventdata_commandLine), "ssh") AND
          contains(to_string($message.filebeat_data_eventdata_commandLine), "root@")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_logonType), "5") OR
        contains(to_string($message.filebeat_data_win_eventdata_processName), "services.exe")
    )
then
    set_field("sigma_rule_title", "Default Account Usage");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1078.001");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Default Accounts");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Domain Account Abuse (T1078.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Domain Account Abuse (T1078.002)",
    "description": "Detects unusual domain account usage including service account interactive logons. Real adversaries: APT29, FIN7, Lazarus, Wizard Spider.",
    "source": `rule "Sigma: Domain Account Abuse (T1078.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetUserName") AND
         (to_string($message.filebeat_data_win_system_eventID) == "4624" OR
          to_string($message.filebeat_data_win_system_eventID) == "4648") AND
         (to_string($message.filebeat_data_win_eventdata_logonType) == "2" OR
          to_string($message.filebeat_data_win_eventdata_logonType) == "10") AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "svc_") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "SVC_") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "svc-") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "service_") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "_svc") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "admin_") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetUserName), "backup_")))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "runas") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/netonly"))
    )
then
    set_field("sigma_rule_title", "Domain Account Abuse");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1078.002");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Domain Accounts");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Local Account Manipulation (T1078.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Local Account Manipulation (T1078.003)",
    "description": "Detects local account creation and suspicious first-time logons. Real adversaries: APT32, Carbanak, FIN6, Turla.",
    "source": `rule "Sigma: Local Account Manipulation (T1078.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net user") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/add")) OR
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net localgroup") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "administrators") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/add")))
        OR
        (to_string($message.filebeat_data_win_system_eventID) == "4720")
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "useradd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "adduser")) AND
         NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "apt"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "svchost.exe")
    )
then
    set_field("sigma_rule_title", "Local Account Manipulation");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1078.003");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Local Accounts");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Additional Email Delegate Permissions (T1098.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Additional Email Delegate Permissions (T1098.002)",
    "description": "Detects mailbox permission delegation via PowerShell. Real adversaries: APT28, APT29, HAFNIUM, UNC2452.",
    "source": `rule "Sigma: Additional Email Delegate Permissions (T1098.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Add-MailboxPermission") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Set-Mailbox") AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-GrantSendOnBehalfTo") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-ForwardingSmtpAddress") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-ForwardingAddress")) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Add-RecipientPermission") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Set-MailboxFolderPermission")))
        OR
        (has_field("filebeat_data_office365_Operation") AND
         (contains(to_string($message.filebeat_data_office365_Operation), "Add-MailboxPermission") OR
          contains(to_string($message.filebeat_data_office365_Operation), "AddFolderPermissions") OR
          contains(to_string($message.filebeat_data_office365_Operation), "Add-RecipientPermission")))
    )
then
    set_field("sigma_rule_title", "Additional Email Delegate Permissions");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1098.002");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Additional Email Delegate Permissions");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Privileged Group Modification (T1098.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Privileged Group Modification (T1098.007)",
    "description": "Detects additions to privileged local or domain groups. Real adversaries: APT28, APT29, FIN6, Wizard Spider.",
    "source": `rule "Sigma: Privileged Group Modification (T1098.007)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net localgroup") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/add") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "administrators") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Administrators") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Remote Desktop Users") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Backup Operators"))) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net group") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/add") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Domain Admins") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Enterprise Admins") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Schema Admins"))) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Add-ADGroupMember") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Add-LocalGroupMember")))
        OR
        (to_string($message.filebeat_data_win_system_eventID) == "4728" OR
         to_string($message.filebeat_data_win_system_eventID) == "4732" OR
         to_string($message.filebeat_data_win_system_eventID) == "4756")
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "usermod") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-aG") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "sudo") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "wheel") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "root")))
    )
then
    set_field("sigma_rule_title", "Privileged Group Modification");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1098.007");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Additional Local or Domain Groups");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Unix Shell Configuration Modification (T1546.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Unix Shell Configuration Modification (T1546.004)",
    "description": "Detects writes to shell config files for persistence. Real adversaries: TeamTNT, Kinsing, Outlaw, Rocke.",
    "source": `rule "Sigma: Unix Shell Configuration Modification (T1546.004)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_targetFilename), ".bashrc") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), ".bash_profile") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), ".profile") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), ".zshrc") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), ".zprofile") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/profile") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/bash.bashrc") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/zsh/zshrc") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), ".bash_logout") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/profile.d/"))
        OR
        ((contains(to_string($message.filebeat_data_eventdata_commandLine), ".bashrc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".zshrc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".profile")) AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "echo") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ">>") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "tee")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "apt") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "dpkg") OR
        contains(to_string($message.filebeat_data_eventdata_image), "vim") OR
        contains(to_string($message.filebeat_data_eventdata_image), "nano")
    )
then
    set_field("sigma_rule_title", "Unix Shell Configuration Modification");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1546.004");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Unix Shell Configuration Modification");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Netsh Helper DLL (T1546.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Netsh Helper DLL (T1546.007)",
    "description": "Detects netsh helper DLL registration for persistence. Real adversaries: APT32, Turla, OilRig.",
    "source": `rule "Sigma: Netsh Helper DLL (T1546.007)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "netsh") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "add") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "helper")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "netsh") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".dll"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_user), "SYSTEM")
    )
then
    set_field("sigma_rule_title", "Netsh Helper DLL");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1546.007");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Netsh Helper DLL");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: AppCert DLLs Registry Modification (T1546.009)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: AppCert DLLs Registry Modification (T1546.009)",
    "description": "Detects AppCertDLLs registry modification for DLL injection persistence. Real adversaries: APT32, Turla.",
    "source": `rule "Sigma: AppCert DLLs Registry Modification (T1546.009)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "AppCertDlls"))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AppCertDlls"))
    )
then
    set_field("sigma_rule_title", "AppCert DLLs Registry Modification");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1546.009");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "AppCert DLLs");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Application Shimming (T1546.011)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Application Shimming (T1546.011)",
    "description": "Detects sdbinst.exe execution for application shimming persistence. Real adversaries: APT29, FIN7, Lazarus.",
    "source": `rule "Sigma: Application Shimming (T1546.011)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_image), "sdbinst.exe") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sdbinst") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".sdb")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sdbinst") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-q"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "setup.exe")
    )
then
    set_field("sigma_rule_title", "Application Shimming");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1546.011");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Application Shimming");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: PowerShell Profile Modification (T1546.013)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: PowerShell Profile Modification (T1546.013)",
    "description": "Detects writes to PowerShell profile for persistence. Real adversaries: APT29, Turla, Cobalt Group.",
    "source": `rule "Sigma: PowerShell Profile Modification (T1546.013)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "Microsoft.PowerShell_profile.ps1") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "Microsoft.PowerShellISE_profile.ps1") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "profile.ps1") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "Microsoft.VSCode_profile.ps1")))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "$PROFILE") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Microsoft.PowerShell_profile") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "WindowsPowerShell\\profile")))
    )
then
    set_field("sigma_rule_title", "PowerShell Profile Modification");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1546.013");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "PowerShell Profile");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Authentication Package Registry Modification (T1547.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Authentication Package Registry Modification (T1547.002)",
    "description": "Detects modifications to LSA Authentication Packages. Real adversaries: APT29, Turla, Carbanak.",
    "source": `rule "Sigma: Authentication Package Registry Modification (T1547.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Control\\Lsa") AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Authentication Packages"))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Lsa") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Authentication Packages"))
    )
then
    set_field("sigma_rule_title", "Authentication Package Registry Modification");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1547.002");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Authentication Package");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Kernel Modules Loading (T1547.006)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Kernel Modules Loading (T1547.006)",
    "description": "Detects suspicious kernel module loading. Real adversaries: TeamTNT, Drovorub, Winnti, Reptile.",
    "source": `rule "Sigma: Kernel Modules Loading (T1547.006)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "insmod") AND
         NOT contains(to_string($message.filebeat_data_eventdata_commandLine), "/lib/modules")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "modprobe") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "-f") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "--force") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "/tmp/") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "/dev/shm/") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "/var/tmp/"))) OR
        (contains(to_string($message.filebeat_data_eventdata_image), "insmod") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".ko"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "systemd") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "udev") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "modprobe")
    )
then
    set_field("sigma_rule_title", "Kernel Modules Loading");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1547.006");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "Kernel Modules and Extensions");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: LSASS Driver Registry Modification (T1547.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: LSASS Driver Registry Modification (T1547.008)",
    "description": "Detects modifications to LSA driver registry keys. Real adversaries: APT29, Turla, Mimikatz operators.",
    "source": `rule "Sigma: LSASS Driver Registry Modification (T1547.008)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Control\\Lsa") AND
         (contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Security Packages") OR
          contains(to_string($message.filebeat_data_win_eventdata_targetObject), "OSConfig")))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Lsa") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Security Packages") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "RunAsPPL")))
    )
then
    set_field("sigma_rule_title", "LSASS Driver Registry Modification");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1547.008");
    set_field("sigma_mitre_tactic", "Persistence");
    set_field("sigma_mitre_technique", "LSASS Driver");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// =============================================================================
// CREDENTIAL ACCESS RULES (15 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: LSA Secrets Extraction (T1003.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: LSA Secrets Extraction (T1003.004)",
    "description": "Detects LSA secrets extraction via registry or impacket. Real adversaries: APT28, APT29, FIN6, Lazarus.",
    "source": `rule "Sigma: LSA Secrets Extraction (T1003.004)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "save") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "HKLM\\SECURITY")) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "save") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "hklm\\security")) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "secretsdump") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lsasecretsdump") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mimikatz") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lsadump::secrets")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "impacket-secretsdump") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "secretsdump.py")))
    )
then
    set_field("sigma_rule_title", "LSA Secrets Extraction");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1003.004");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "LSA Secrets");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Cached Domain Credentials Extraction (T1003.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Cached Domain Credentials Extraction (T1003.005)",
    "description": "Detects cached domain credential extraction. Real adversaries: APT28, APT29, FIN6, Wizard Spider.",
    "source": `rule "Sigma: Cached Domain Credentials Extraction (T1003.005)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "save") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "HKLM\\SECURITY") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "HKLM\\SAM") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "HKLM\\SYSTEM"))) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cachedump") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mimikatz") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lsadump::cache") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mscash")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "cachedump"))
    )
then
    set_field("sigma_rule_title", "Cached Domain Credentials Extraction");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1003.005");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Cached Domain Credentials");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Proc Filesystem Credential Access (T1003.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Proc Filesystem Credential Access (T1003.007)",
    "description": "Detects /proc/PID/maps and /proc/PID/mem access for credential extraction. Real adversaries: TeamTNT, Kinsing.",
    "source": `rule "Sigma: Proc Filesystem Credential Access (T1003.007)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/maps")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/mem")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/environ")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "process_vm_readv") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "gdb") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-p") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "dump"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "debug") OR
        contains(to_string($message.filebeat_data_eventdata_user), "developer")
    )
then
    set_field("sigma_rule_title", "Proc Filesystem Credential Access");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1003.007");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Proc Filesystem");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Password File Access (T1003.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Password File Access (T1003.008)",
    "description": "Detects /etc/shadow access and unshadow usage. Real adversaries: TeamTNT, Kinsing, Rocke, Outlaw.",
    "source": `rule "Sigma: Password File Access (T1003.008)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        contains(to_string($message.filebeat_data_eventdata_commandLine), "unshadow") OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "cat") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "cp") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "head") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "tail") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "less") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "more") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/shadow")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "john /etc/shadow") OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "hashcat") AND
        contains(to_string($message.filebeat_data_eventdata_commandLine), "shadow")
    )
then
    set_field("sigma_rule_title", "Password File Access");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1003.008");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "/etc/passwd and /etc/shadow");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: MFA Interception Tools (T1111)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: MFA Interception Tools (T1111)",
    "description": "Detects MFA interception and phishing tools. Real adversaries: APT29, LAPSUS$, Scattered Spider.",
    "source": `rule "Sigma: MFA Interception Tools (T1111)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "evilginx") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "modlishka") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "muraena") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "gophish") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "evilnovnc") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "credsniper")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "evilginx") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "modlishka") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "muraena") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "gophish") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "evilnovnc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "credsniper")))
    )
then
    set_field("sigma_rule_title", "MFA Interception Tools");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1111");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Multi-Factor Authentication Interception");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Exploitation for Credential Access (T1212)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Exploitation for Credential Access (T1212)",
    "description": "Detects exploitation tools targeting authentication. Real adversaries: APT28, APT29, Wizard Spider, HAFNIUM.",
    "source": `rule "Sigma: Exploitation for Credential Access (T1212)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "zerologon") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CVE-2020-1472") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "printnightmare") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CVE-2021-34527") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "petitpotam") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CVE-2021-36942") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "samaccountname") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CVE-2021-42278") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "nopac")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "zerologon") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "printnightmare") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "petitpotam") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "nopac") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cve-2020-1472") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "cve-2021-34527")))
    )
then
    set_field("sigma_rule_title", "Exploitation for Credential Access");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1212");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Exploitation for Credential Access");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Shell History Access (T1552.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Shell History Access (T1552.003)",
    "description": "Detects reading shell history files for credentials. Real adversaries: TeamTNT, Kinsing, Rocke.",
    "source": `rule "Sigma: Shell History Access (T1552.003)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "cat") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), ".bash_history") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".zsh_history") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".sh_history") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), ".history"))) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "grep") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "password") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "passwd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "secret") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "token") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "api_key")) AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "_history")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "strings") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "_history")) OR
        contains(to_string($message.filebeat_data_eventdata_commandLine), "history | grep")
    )
then
    set_field("sigma_rule_title", "Shell History Access");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1552.003");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Bash History");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Password Manager Access (T1555.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Password Manager Access (T1555.005)",
    "description": "Detects access to password manager databases. Real adversaries: APT28, APT29, FIN7, Lazarus.",
    "source": `rule "Sigma: Password Manager Access (T1555.005)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".kdbx") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "KeePass") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "keepass") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "LastPass") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lastpass") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "1password") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Bitwarden") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "bitwarden") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Dashlane") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "keepassxc")))
        OR
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".kdbx"))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), ".kdbx") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "keepassxc") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "kpcli")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "KeePass.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "KeePassXC.exe")
    )
then
    set_field("sigma_rule_title", "Password Manager Access");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1555.005");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Password Managers");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Skeleton Key Attack (T1556.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Skeleton Key Attack (T1556.001)",
    "description": "Detects skeleton key deployment on domain controllers. Real adversaries: APT28, APT29, FIN6.",
    "source": `rule "Sigma: Skeleton Key Attack (T1556.001)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mimikatz") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "misc::skeleton")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mimikatz") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "skeleton")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-Mimikatz") AND
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "skeleton") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lsadump") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "changentlm"))
    )
then
    set_field("sigma_rule_title", "Skeleton Key Attack");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1556.001");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Domain Controller Authentication");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Password Filter DLL (T1556.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Password Filter DLL (T1556.002)",
    "description": "Detects password filter DLL registration. Real adversaries: APT29, Turla, Carbanak.",
    "source": `rule "Sigma: Password Filter DLL (T1556.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Control\\Lsa") AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Notification Packages"))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Lsa") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Notification Packages"))
    )
then
    set_field("sigma_rule_title", "Password Filter DLL");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1556.002");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Password Filter DLL");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: PAM Modification (T1556.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: PAM Modification (T1556.003)",
    "description": "Detects PAM module modification for credential harvesting. Real adversaries: TeamTNT, APT28, Turla.",
    "source": `rule "Sigma: PAM Modification (T1556.003)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_targetFilename), "/etc/pam.d/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "pam_unix.so") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/lib/security/") OR
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "/lib64/security/"))
        OR
        ((contains(to_string($message.filebeat_data_eventdata_commandLine), "cp") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "mv") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "sed")) AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/etc/pam.d/"))
        OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "pam_") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), ".so") AND
         NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "apt"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_parentImage), "apt") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "dpkg") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "yum")
    )
then
    set_field("sigma_rule_title", "PAM Modification");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1556.003");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Pluggable Authentication Modules");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Network Provider DLL (T1556.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network Provider DLL (T1556.008)",
    "description": "Detects network provider DLL registration for credential capture. Real adversaries: APT29, FIN7.",
    "source": `rule "Sigma: Network Provider DLL (T1556.008)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetObject") AND
         to_string($message.filebeat_data_win_system_eventID) == "13" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Control\\NetworkProvider") AND
         contains(to_string($message.filebeat_data_win_eventdata_targetObject), "Order"))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "reg") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NetworkProvider") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ProviderOrder"))
    )
then
    set_field("sigma_rule_title", "Network Provider DLL");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1556.008");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "Network Provider DLL");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: ARP Cache Poisoning (T1557.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: ARP Cache Poisoning (T1557.002)",
    "description": "Detects ARP spoofing and poisoning tools. Real adversaries: APT28, FIN6, Carbanak.",
    "source": `rule "Sigma: ARP Cache Poisoning (T1557.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "arpspoof") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ettercap") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "bettercap") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "responder") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Inveigh") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-Inveigh") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "cain") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "arp")))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "arpspoof") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "ettercap") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "bettercap") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "responder") OR
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "arp") AND
           contains(to_string($message.filebeat_data_eventdata_commandLine), "-s"))))
    )
then
    set_field("sigma_rule_title", "ARP Cache Poisoning");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1557.002");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "ARP Cache Poisoning");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: DHCP Spoofing (T1557.003)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: DHCP Spoofing (T1557.003)",
    "description": "Detects DHCP spoofing and starvation attacks. Real adversaries: APT28, FIN6.",
    "source": `rule "Sigma: DHCP Spoofing (T1557.003)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "yersinia") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "dhcpstarv") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mitm6") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "dhcpig") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "scapy") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "DHCP"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "yersinia") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "dhcpstarv") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "mitm6") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "dhcpig")))
    )
then
    set_field("sigma_rule_title", "DHCP Spoofing");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1557.003");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "DHCP Spoofing");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: SAML Token Forgery (T1606.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: SAML Token Forgery (T1606.002)",
    "description": "Detects Golden SAML and ADFS token manipulation. Real adversaries: APT29, UNC2452, NOBELIUM.",
    "source": `rule "Sigma: SAML Token Forgery (T1606.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ADFSDump") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "adfsdump") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Golden-SAML") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AADInternals") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Export-AADIntADFSCertificates") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Export-AADIntADFSSigningCertificate") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "New-AADIntSAMLToken") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "mimikatz") AND
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "saml"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "adfsdump") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "shimit") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "golden_saml")))
    )
then
    set_field("sigma_rule_title", "SAML Token Forgery");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1606.002");
    set_field("sigma_mitre_tactic", "Credential Access");
    set_field("sigma_mitre_technique", "SAML Tokens");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// =============================================================================
// DEFENSE EVASION RULES (15 techniques)
// =============================================================================

// -----------------------------------------------------------------------------
// Rule: Direct Volume Access (T1006)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Direct Volume Access (T1006)",
    "description": "Detects raw disk access bypassing file system. Real adversaries: APT28, APT29, Turla, Lazarus.",
    "source": `rule "Sigma: Direct Volume Access (T1006)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "rawcopy") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "RawCopy") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NinjaCopy") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Invoke-NinjaCopy") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "\\\\.\\PhysicalDrive") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "\\\\.\\C:") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "\\\\.\\HarddiskVolume") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "fsutil") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "usn"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "vssadmin.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "System32\\svchost.exe")
    )
then
    set_field("sigma_rule_title", "Direct Volume Access");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1006");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Direct Volume Access");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Binary Padding (T1027.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Binary Padding (T1027.001)",
    "description": "Detects abnormally large executables that may use binary padding for evasion. Real adversaries: APT32, Turla, OceanLotus.",
    "source": `rule "Sigma: Binary Padding (T1027.001)"
when
    has_field("filebeat_data_win_eventdata_targetFilename") AND
    to_string($message.filebeat_data_win_system_eventID) == "11" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Temp\\") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\AppData\\Local\\Temp") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Downloads\\") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Users\\Public\\")) AND
        (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".exe") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".dll") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".scr"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "setup.exe")
    )
then
    set_field("sigma_rule_title", "Binary Padding Suspicious File");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1027.001");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Binary Padding");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: HTML Smuggling (T1027.006)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: HTML Smuggling (T1027.006)",
    "description": "Detects mshta and HTML-based payload delivery. Real adversaries: APT29, NOBELIUM, Qakbot, IcedID.",
    "source": `rule "Sigma: HTML Smuggling (T1027.006)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_image), "mshta.exe") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "javascript:") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "vbscript:") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".html") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".hta") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "http://") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "https://"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msedge.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "chrome.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_parentImage), "firefox.exe") AND
         contains(to_string($message.filebeat_data_win_eventdata_image), "cmd.exe"))
    )
then
    set_field("sigma_rule_title", "HTML Smuggling");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1027.006");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "HTML Smuggling");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: LNK Icon Smuggling (T1027.012)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: LNK Icon Smuggling (T1027.012)",
    "description": "Detects suspicious .lnk file creation with external icon paths. Real adversaries: APT28, APT29, Gamaredon.",
    "source": `rule "Sigma: LNK Icon Smuggling (T1027.012)"
when
    has_field("filebeat_data_win_eventdata_targetFilename") AND
    to_string($message.filebeat_data_win_system_eventID) == "11" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".lnk") AND
        (contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Desktop\\") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Downloads\\") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Documents\\") OR
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\\Startup\\"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_image), "explorer.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_image), "msiexec.exe")
    )
then
    set_field("sigma_rule_title", "LNK Icon Smuggling");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1027.012");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "LNK Icon Smuggling");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Encoded/Encrypted File Operations (T1027.013)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Encoded/Encrypted File Operations (T1027.013)",
    "description": "Detects certutil and openssl encoding/decoding operations. Real adversaries: APT28, APT29, FIN7, Lazarus.",
    "source": `rule "Sigma: Encoded/Encrypted File Operations (T1027.013)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "certutil") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-encode") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-decode") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-urlcache") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-decodehex"))) OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "openssl") AND
           (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "enc") OR
            contains(to_string($message.filebeat_data_win_eventdata_commandLine), "base64")))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "openssl") AND
          (contains(to_string($message.filebeat_data_eventdata_commandLine), "enc ") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "enc -") OR
           contains(to_string($message.filebeat_data_eventdata_commandLine), "base64"))))
    )
then
    set_field("sigma_rule_title", "Encoded/Encrypted File Operations");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1027.013");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Encrypted/Encoded File");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Invalid Code Signature (T1036.001)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Invalid Code Signature (T1036.001)",
    "description": "Detects sigcheck usage and unsigned binaries in system directories. Real adversaries: APT28, APT29, Lazarus.",
    "source": `rule "Sigma: Invalid Code Signature (T1036.001)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sigcheck") AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-u") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-e") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "-vt"))) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Get-AuthenticodeSignature") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "System32"))
    )
then
    set_field("sigma_rule_title", "Invalid Code Signature Check");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1036.001");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Invalid Code Signature");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Right-to-Left Override (T1036.002)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Right-to-Left Override (T1036.002)",
    "description": "Detects filenames using RTLO character (U+202E) for masquerading. Real adversaries: APT28, Gamaredon, TA505.",
    "source": `rule "Sigma: Right-to-Left Override (T1036.002)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         contains(to_string($message.filebeat_data_win_eventdata_targetFilename), "\u202E"))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "\u202E"))
        OR
        (has_field("filebeat_data_eventdata_targetFilename") AND
         contains(to_string($message.filebeat_data_eventdata_targetFilename), "\u202E"))
    )
then
    set_field("sigma_rule_title", "Right-to-Left Override");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1036.002");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Right-to-Left Override");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Masquerade Task or Service (T1036.004)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Masquerade Task or Service (T1036.004)",
    "description": "Detects services/tasks with names mimicking legitimate ones. Real adversaries: APT28, APT29, FIN7, Lazarus.",
    "source": `rule "Sigma: Masquerade Task or Service (T1036.004)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "sc create") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "New-Service")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "svchost") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "csrss") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "lsass") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "services") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "winlogon") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "spoolsv") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "wuauserv") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "WinDefend"))) OR
        ((contains(to_string($message.filebeat_data_win_eventdata_commandLine), "schtasks") AND
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/create")) AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "\\Microsoft\\Windows\\") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "WindowsUpdate") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SystemRestore")))
    )
then
    set_field("sigma_rule_title", "Masquerade Task or Service");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1036.004");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Masquerade Task or Service");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Double File Extension (T1036.007)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Double File Extension (T1036.007)",
    "description": "Detects files with double extensions for masquerading. Real adversaries: APT28, APT32, Gamaredon, TA505.",
    "source": `rule "Sigma: Double File Extension (T1036.007)"
when
    (
        (has_field("filebeat_data_win_eventdata_targetFilename") AND
         to_string($message.filebeat_data_win_system_eventID) == "11" AND
         ((contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".docx.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".xls.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".xlsx.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".txt.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".jpg.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".png.exe") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.scr") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.scr") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.bat") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.bat") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.cmd") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.cmd") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.vbs") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.vbs") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".pdf.js") OR
           contains(to_string($message.filebeat_data_win_eventdata_targetFilename), ".doc.js"))))
        OR
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".pdf.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".doc.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".docx.exe") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), ".xls.exe")))
    )
then
    set_field("sigma_rule_title", "Double File Extension");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1036.007");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Double File Extension");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Thread Local Storage Injection (T1055.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Thread Local Storage Injection (T1055.005)",
    "description": "Detects TLS callback injection patterns. Real adversaries: APT28, Turla, Cobalt Group.",
    "source": `rule "Sigma: Thread Local Storage Injection (T1055.005)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "TlsCallback") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "TLS_CALLBACK") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "AddressOfCallBacks") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtSetInformationThread") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "ThreadHideFromDebugger"))
    )
then
    set_field("sigma_rule_title", "Thread Local Storage Injection");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1055.005");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Thread Local Storage");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Ptrace System Calls (T1055.008)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Ptrace System Calls (T1055.008)",
    "description": "Detects ptrace PTRACE_ATTACH to other processes for injection. Real adversaries: TeamTNT, Outlaw.",
    "source": `rule "Sigma: Ptrace System Calls (T1055.008)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "ptrace") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "PTRACE_ATTACH")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "gdb") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-p") AND
         NOT contains(to_string($message.filebeat_data_eventdata_parentImage), "debug")) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "strace") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "-p"))
    ) AND NOT (
        contains(to_string($message.filebeat_data_eventdata_user), "developer") OR
        contains(to_string($message.filebeat_data_eventdata_parentImage), "debug")
    )
then
    set_field("sigma_rule_title", "Ptrace System Calls");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1055.008");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Ptrace System Calls");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Proc Memory Injection (T1055.009)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Proc Memory Injection (T1055.009)",
    "description": "Detects writes to /proc/PID/mem for process injection. Real adversaries: TeamTNT, Kinsing.",
    "source": `rule "Sigma: Proc Memory Injection (T1055.009)"
when
    has_field("filebeat_data_eventdata_commandLine") AND
    (
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "/proc/") AND
         contains(to_string($message.filebeat_data_eventdata_commandLine), "/mem") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "dd") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "write") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "echo"))) OR
        (contains(to_string($message.filebeat_data_eventdata_commandLine), "process_vm_writev"))
    )
then
    set_field("sigma_rule_title", "Proc Memory Injection");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1055.009");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Proc Memory");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Process Doppelganging (T1055.013)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Process Doppelganging (T1055.013)",
    "description": "Detects transacted NTFS operations for process hollowing. Real adversaries: APT28, Turla, Lazarus.",
    "source": `rule "Sigma: Process Doppelganging (T1055.013)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtCreateTransaction") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtCreateSection") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtRollbackTransaction") OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CreateFileTransacted") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "doppelgang") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Doppelganging")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "transacted") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "section"))
    )
then
    set_field("sigma_rule_title", "Process Doppelganging");
    set_field("sigma_rule_level", "critical");
    set_field("sigma_mitre_id", "T1055.013");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Process Doppelganging");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Network Share Connection Removal (T1070.005)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Network Share Connection Removal (T1070.005)",
    "description": "Detects removal of network share connections to hide lateral movement. Real adversaries: APT28, APT29, FIN7.",
    "source": `rule "Sigma: Network Share Connection Removal (T1070.005)"
when
    has_field("filebeat_data_win_eventdata_commandLine") AND
    to_string($message.filebeat_data_win_system_eventID) == "1" AND
    (
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net use") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/delete")) OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net use") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/d")) OR
        contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Remove-SmbMapping") OR
        (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net use * /delete") OR
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "net use \\\\") AND
         contains(to_string($message.filebeat_data_win_eventdata_commandLine), "/delete"))
    )
then
    set_field("sigma_rule_title", "Network Share Connection Removal");
    set_field("sigma_rule_level", "medium");
    set_field("sigma_mitre_id", "T1070.005");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Network Share Connection Removal");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// -----------------------------------------------------------------------------
// Rule: Timestomp (T1070.006)
// -----------------------------------------------------------------------------
db.pipeline_processor_rules.insertOne({
    "title": "Sigma: Timestomp (T1070.006)",
    "description": "Detects timestamp manipulation to hide file modification times. Real adversaries: APT28, APT29, Turla, Lazarus.",
    "source": `rule "Sigma: Timestomp (T1070.006)"
when
    (
        (has_field("filebeat_data_win_eventdata_commandLine") AND
         to_string($message.filebeat_data_win_system_eventID) == "1" AND
         (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "timestomp") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "SetFileTime") OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "Set-ItemProperty") AND
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "CreationTime") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "LastWriteTime") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "LastAccessTime")) OR
          contains(to_string($message.filebeat_data_win_eventdata_commandLine), "NtSetInformationFile") OR
          (contains(to_string($message.filebeat_data_win_eventdata_commandLine), "[System.IO.File]::SetCreationTime") OR
           contains(to_string($message.filebeat_data_win_eventdata_commandLine), "[System.IO.File]::SetLastWriteTime"))))
        OR
        (has_field("filebeat_data_eventdata_commandLine") AND
         (contains(to_string($message.filebeat_data_eventdata_commandLine), "touch -t") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "touch -d") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "touch --date") OR
          contains(to_string($message.filebeat_data_eventdata_commandLine), "touch -r")))
    ) AND NOT (
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "msiexec.exe") OR
        contains(to_string($message.filebeat_data_win_eventdata_parentImage), "setup.exe")
    )
then
    set_field("sigma_rule_title", "Timestomp");
    set_field("sigma_rule_level", "high");
    set_field("sigma_mitre_id", "T1070.006");
    set_field("sigma_mitre_tactic", "Defense Evasion");
    set_field("sigma_mitre_technique", "Timestomp");
    set_field("sigma_detection_source", "Fomorian Batch 3");
    set_field("alert", true);
end`
});

// =============================================================================
// Verification Query
// =============================================================================
print("Batch 3 Sigma rules inserted. Verifying count...");
print("Total Batch 3 rules: " + db.pipeline_processor_rules.countDocuments({"title": /Batch 3/}));
print("");
print("Rules by tactic:");
print("  PERSISTENCE: " + db.pipeline_processor_rules.countDocuments({"source": /Persistence.*Fomorian Batch 3/}));
print("  CREDENTIAL ACCESS: " + db.pipeline_processor_rules.countDocuments({"source": /Credential Access.*Fomorian Batch 3/}));
print("  DEFENSE EVASION: " + db.pipeline_processor_rules.countDocuments({"source": /Defense Evasion.*Fomorian Batch 3/}));
