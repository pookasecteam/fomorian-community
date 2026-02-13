# Fomorian vs Other Attack Simulation Tools

## The Core Difference

**Atomic Red Team** runs attacks on your endpoints to see if they generate telemetry.

**Fomorian** generates attack logs and injects them into your SIEM to see if your detections actually fire.

These test different things:

```
Endpoint → Telemetry → Collection → Parsing → Enrichment → Detection → Alert
           ^                                                ^
           |                                                |
      ART tests here                               Fomorian tests here
```

You can have perfect endpoint telemetry and still miss attacks if your SIEM drops fields, your parsers break, or your detection rules have bad logic.

---

## Side-by-Side Comparison

| | Atomic Red Team | Fomorian |
|---|---|---|
| **What it does** | Executes real techniques on real systems | Generates realistic logs, injects into SIEM |
| **What it tests** | Endpoint telemetry generation | Detection pipeline end-to-end |
| **Execution risk** | Runs actual malicious commands | Zero execution, logs only |
| **Production safe** | Risky without isolation | Safe to run against production SIEM |
| **Output** | Artifacts on disk, memory, registry | Logs in your SIEM |
| **Scope** | One technique at a time | Full attack chains with correlation |
| **Customization** | Generic lab hostnames | Your hostnames, users, IPs, domain |
| **Time simulation** | Real-time only | Compressed or multi-day scenarios |

---

## What Fomorian Tests That Others Don't

### 1. Your Actual Detection Rules

Fomorian logs hit your real Sigma rules, YARA rules, and custom detections. If a rule has broken logic (wrong field names, bad OR/AND conditions), you find out before an actual attack.

We found 17 broken Sigma rules in Graylog during testing. They had syntax like:
```
when true AND (condition)
```
This always matches. These rules generated thousands of false positives on normal traffic but would have been invisible in an ART test.

### 2. Field Mapping and Parsing

Your SIEM might parse `CommandLine` as `commandLine`, `command_line`, or `filebeat_data_win_eventdata_commandLine`. If your detection expects the wrong field name, it never fires.

Fomorian logs go through your actual parsing pipeline. Broken parsers break detections.

### 3. Correlation Rules

Real attacks span multiple hosts. Attacker compromises workstation, dumps creds, moves to DC, pivots to file server.

Fomorian generates correlated GUIDs across hosts:
```
WS01: Parent {GUID-001} spawns Child {GUID-002}
DC01: Process {GUID-003} with ParentGuid {GUID-002}
```

Your multi-host correlation rules either catch this chain or they don't.

### 4. Time-Based Detection

APT actors dwell for weeks. Beaconing happens every 4 hours. Data exfil happens at 3am over 6 days.

Fomorian can generate week-long scenarios with realistic timing. Test whether your "unusual time" and "slow exfil" rules actually work.

---

## When to Use Each Tool

**Use Atomic Red Team when:**
- Validating that endpoints generate the right telemetry
- Testing EDR/AV response to real execution
- You need to verify Sysmon configs are capturing events
- Running isolated lab validation

**Use Fomorian when:**
- Testing your SIEM detection rules
- Validating parsing and field mappings
- Training SOC analysts on realistic scenarios
- Testing correlation and multi-host detection
- Running purple team exercises without endpoint risk
- You need customized logs matching your environment

**Use both for full coverage:**
1. ART confirms endpoints generate telemetry
2. Fomorian confirms your SOC will see the alert

---

## Other Tools in the Space

| Tool | Type | Fomorian Difference |
|------|------|---------------------|
| **Caldera** | Agent-based adversary emulation | Requires deployed agents, executes real techniques. Fomorian is agentless, log-only. |
| **PurpleSharp** | Windows adversary simulation | Executes on Windows endpoints. Fomorian generates logs without execution. |
| **DetectionLab** | Lab infrastructure | Provides the lab. Fomorian provides the attack scenarios for any environment. |
| **APTSimulator** | Batch script artifacts | Creates file/registry artifacts. Fomorian creates SIEM-ready logs. |

---

## Real-World Example

**Scenario:** Ransomware attack simulation

**With Atomic Red Team:**
1. Deploy test VM
2. Run T1566.001 (phishing macro)
3. Run T1059.001 (PowerShell)
4. Run T1003.001 (LSASS dump)
5. Run T1486 (encryption)
6. Check each technique generated logs
7. Hope your SIEM ingested them correctly

**With Fomorian:**
1. Configure your environment (hostnames, users, IPs)
2. Run: `fomorian generate --engagement ransomware`
3. Inject 80 correlated logs into your SIEM
4. Check which Sigma rules fired
5. Find the detection gaps immediately

Same coverage. No VMs. No execution risk. Logs look like they came from your actual network.

---

## The Bottom Line

Atomic Red Team answers: "Can my endpoint see this attack?"

Fomorian answers: "Will my SOC catch this attack?"

Both questions matter. Answer both.

---

*Fomorian by [Pooka Security](https://pookasec.com)*
