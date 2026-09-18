# MySQL-HoneyPot[honeypot-project-technical-write-up.md](https://github.com/user-attachments/files/32388631/honeypot-project-technical-write-up.md)
# Azure Windows and MySQL Honeypot Project

> **Portfolio note:** This project was performed in an isolated cyber-range environment. The intentionally weak configuration described below was used only for controlled observation of attacker behavior. It is not appropriate for production systems.

## Purpose

This project built, monitored, and analyzed an intentionally exposed Windows 11 virtual-machine honeypot hosting a MySQL database in Azure. The objective was to observe opportunistic internet activity, collect endpoint, database, and network telemetry, and practice an end-to-end SOC workflow: detection engineering, alert triage, threat hunting, containment, eradication, recovery, and incident reporting.

The honeypot was deployed in the Log Analytics workspace. The environment applied centralized outbound restrictions so that attempted command-and-control (C2), cryptomining, or pivoting activity would be blocked and logged rather than permitted to succeed.

## Executive Summary

I deployed a Windows 11 VM designed to appear like a legitimate corporate asset, installed MySQL with dummy data, and connected both endpoint and database telemetry to Microsoft Sentinel and Microsoft Defender for Endpoint (MDE). Before exposure, I created and validated detections for successful Windows logons and successful MySQL authentication.

After the detections were in place, I deliberately weakened only the isolated lab system to make Remote Desktop Protocol (RDP) and MySQL activity observable. I then used Sentinel and Defender telemetry to investigate authentication activity, database queries, endpoint behavior, and denied outbound connections. The exercise demonstrated how separate telemetry sources can be correlated into an attack narrative, from attempted initial access through post-compromise discovery, collection, and attempted outbound activity.

## Environment and Architecture

| Component | Implementation | Security-monitoring purpose |
|---|---|---|
| Honeypot host | Azure Windows 11 VM with a public IP address | Attract and record opportunistic access attempts in a controlled environment |
| Endpoint telemetry | Microsoft Defender for Endpoint | Capture logons, processes, files, registry changes, and endpoint network activity |
| SIEM/log platform | Microsoft Sentinel and Log Analytics workspace | Centralize telemetry, author analytics rules, investigate incidents, and run KQL hunts |
| Database service | MySQL Server with the dummy-data database | Create a second observable service and a collection target |
| Database logging | MySQL general/audit log ingested by Azure Monitor Agent (AMA) through a data collection rule (DCR) | Capture database connection attempts and SQL queries in `MySQLAudit_CL` |
| Network telemetry | `NTANetAnalytics` | Identify traffic to and from the honeypot, including denied outbound flows |
| Containment | Defender device isolation | Restrict a compromised endpoint while preserving evidence for investigation |

### Data flow

```text
Internet activity
      |
      v
Azure Windows 11 honeypot + MySQL
      |                         |
      |                         +--> MySQL general log
      |                                      |
      v                                      v
Microsoft Defender for Endpoint       AMA + DCR
      |                                      |
      +---------------+----------------------+
                      |
                      v
      Microsoft Sentinel / Log Analytics
      |
      +--> Analytics rules, incident triage, KQL hunting, reporting
```

## Threat Model

The intended observation path was an RDP compromise followed by local MySQL discovery and database access. Direct exposure of MySQL could also generate database-focused activity. These scenarios produce a useful defensive chain:

1. **Initial Access** — Opportunistic access attempts against exposed RDP or MySQL services.
2. **Valid Accounts** — Successful use of an intentionally weak or exposed local/guest account, or a database credential.
3. **Discovery** — Post-logon process activity that may enumerate the host, services, users, or local files.
4. **Collection** — MySQL queries against the dummy database.
5. **Command and Control / Exfiltration Attempts** — Outbound connections initiated after host compromise; in this range, restricted egress means denied attempts are especially important evidence.

### MITRE ATT&CK mapping

| Tactic | Technique | ATT&CK ID | Evidence source |
|---|---|---|---|
| Initial Access | External Remote Services | T1133 | RDP-related logons and network activity |
| Credential Access | Brute Force | T1110 | Repeated failed authentication activity, when available |
| Defense Evasion / Persistence context | Valid Accounts | T1078 | Successful logons using exposed local or database accounts |
| Discovery | System Network Connections Discovery | T1049 | Process and network telemetry following access |
| Discovery | Account Discovery | T1087 | Endpoint process telemetry and account-focused commands |
| Collection | Data from Information Repositories | T1213 | MySQL query activity against dummy database data |
| Command and Control | Application Layer Protocol | T1071 | Network telemetry and process context, if observed |
| Exfiltration / C2 attempt evidence | Exfiltration Over C2 Channel | T1041 | Denied outbound flows correlated with the compromised host |

> The ATT&CK mapping identifies behaviors the lab is designed to detect or investigate; it does not claim that every listed technique was observed in every run.

## Build and Instrumentation

### 1. Deploy the honeypot VM

- Created a Windows 11 VM in an isolated Azure resource group and assigned a public IP address.
- Used a realistic, corporate-style hostname rather than an obvious lab name.
- Initially denied internet inbound access while the VM was built and instrumented.
- Onboarded the VM to MDE and verified that it appeared in the `DeviceInfo` table.

### 2. Install and populate MySQL

- Installed MySQL Server and MySQL Workbench.
- Created and populated the database with dummy data.
- Enabled MySQL general logging so connection attempts and SQL queries were recorded.
- Verified that benign test queries appeared in the MySQL log before proceeding.

### 3. Send MySQL logs to Log Analytics

- Created a custom text-log DCR using AMA.
- Collected the MySQL general log from:

```text
C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log
```

- Sent the data to the custom `MySQLAudit_CL` table in the Log Analytics Workspace.
- Verified ingestion and filtered by `_ResourceId` because the shared table contains telemetry from multiple lab systems.

### 4. Author and baseline detections

Before exposing the host, I created Sentinel analytics rules and validated that the environment produced no unexpected successful-access alerts. This baseline step was important because it made later events more meaningful and reduced the risk of confusing pre-existing activity with internet-originated activity.

## Detection Engineering

### Detection 1: Successful logon to the honeypot

**Objective:** Alert when a successful logon occurs on the designated honeypot using a high-interest local account such as `administrator` or `guest`.

**Primary data source:** `DeviceLogonEvents`

```kql
// Successful logons to the Windows honeypot
let MyDevice = "<honeypot-device-name>";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
| order by TimeGenerated desc
```

**Suggested Sentinel entity mapping**

| Entity | Field |
|---|---|
| Host | `DeviceName` |
| Account | `AccountName` |
| IP address | `RemoteIP` |

**Analyst questions**

- Did the successful logon occur after the recorded exposure time?
- Is the source IP public and unfamiliar?
- Was the account `administrator` or `guest`?
- What logon type was used?
- What process, file, registry, and network activity followed the logon?

### Detection 2: Successful MySQL authentication

**Objective:** Parse raw MySQL general-log events and identify successful database connections while excluding connection IDs associated with access-denied events.

**Primary data source:** `MySQLAudit_CL`

```kql
// Successful MySQL authentication to the honeypot database
let MyDevice = "<honeypot-resource-name>";
let MyTimeframe = ago(24h);
let FailedConnections =
    MySQLAudit_CL
    | extend RawData = replace_string(RawData, "\t", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName == MyDevice
    | where RawData has "Access denied"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType = case(
    RawData has "Access denied", "LogonFailure",
    ConnectionId in (FailedConnections), "Ignore",
    "LogonSuccess"
)
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData, "@")[0]), " ")[-1]), "'", "")
| extend IpAddress = replace_string(tostring(split(split(RawData, "@")[1], " ")[0]), "'", "")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

**Why parsing matters:** MySQL events arrive as unstructured `RawData`. The query normalizes tab characters, derives the host from `_ResourceId`, extracts a connection ID, distinguishes failed from successful connections, and extracts username and source IP fields for investigation and entity mapping.

### Hunting query: Database activity after exposure

```kql
let MyDevice = "<honeypot-resource-name>";
let ExposureTime = todatetime("<UTC-exposure-timestamp>");
MySQLAudit_CL
| where TimeGenerated > ExposureTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend ActionType = "Query"
| extend Query = trim(" ", tostring(split(RawData, "Query")[1]))
| project TimeGenerated, DeviceName, ActionType, Query, RawData
| order by TimeGenerated desc
```

### Hunting query: Denied outbound traffic

```kql
let MyDevice = "<honeypot-resource-name>";
NTANetAnalytics
| where isnotempty(SrcVm)
| where SrcVm endswith MyDevice
| where DeniedOutFlows >= 1
| project TimeGenerated, DeviceName = MyDevice, FlowType, FlowStatus,
          SrcIp, SrcPorts, DestIp, DestPort, DeniedOutFlows
| order by TimeGenerated desc
```


## Investigation Workflow

### 1. Establish the incident window

Record the precise UTC time at which the honeypot was exposed. Use it as the lower time boundary for all investigations to distinguish deliberate setup activity from possible attacker behavior.

### 2. Validate access

- Review `DeviceLogonEvents` for successful `administrator` or `guest` logons.
- Review `MySQLAudit_CL` for successful database authentication.
- Identify the source IP, account, host, event time, and access path.
- Pivot on the same IP address and time range across available endpoint and network telemetry.

### 3. Investigate endpoint activity

For a confirmed or suspicious Windows logon, investigate the following MDE tables scoped to the honeypot host and incident window:

- `DeviceProcessEvents` for executed commands, interpreters, discovery tools, and suspicious parent-child process relationships.
- `DeviceFileEvents` for dropped tools, archives, staged data, or modified files.
- `DeviceRegistryEvents` for persistence or security-control changes.
- `DeviceNetworkEvents` for outbound connections and the initiating process.
- `NTANetAnalytics` for denied outbound flows and network-level context.

### 4. Investigate database activity

- Filter `MySQLAudit_CL` for `Query` events after the exposure timestamp.
- Review the extracted SQL statement for schema enumeration, table enumeration, data retrieval, account manipulation, or destructive queries.
- Correlate database timestamps and source IPs with Windows logons and endpoint activity.

### 5. Recommended evidence preservation steps

- Capture a Defender investigation package before exposure to establish a clean-state reference.
- Capture a second package after containment.
- Export relevant telemetry for the interval from exposure through isolation:
  - `DeviceLogonEvents`
  - `DeviceProcessEvents`
  - `DeviceRegistryEvents`
  - `DeviceNetworkEvents`
  - `DeviceFileEvents`
  - `MySQLAudit_CL` authentication and query data
  - `NTANetAnalytics`

## Example Attack Narrative Template

Use this structure when writing up observed activity. Replace bracketed values with evidence from your own environment.

> On `[date/time UTC]`, the honeypot was exposed to the internet. At `[date/time UTC]`, `DeviceLogonEvents` recorded a successful `[logon type]` logon to `[device]` using `[account]` from `[source IP]`. Following the logon, `DeviceProcessEvents` showed `[process/command]`, consistent with `[discovery/execution behavior]`. At `[date/time UTC]`, `MySQLAudit_CL` recorded `[username]` connecting from `[source IP]` and executing `[query or query type]` against the `lnp_corp` database. Network telemetry showed `[allowed/denied]` outbound traffic to `[destination:port]`. The sequence is consistent with `[assessment]`; however, the conclusion is limited by `[telemetry gap or uncertainty]`.

## Indicators and Observables

| Observable | Why it matters | Primary source |
|---|---|---|
| Successful `administrator` or `guest` logon | High-signal access event on a purposely exposed host | `DeviceLogonEvents` |
| Public `RemoteIP` | Supports attribution and correlation of internet-originated access | `DeviceLogonEvents` |
| MySQL `Connect` event | Indicates a database connection attempt or session | `MySQLAudit_CL` |
| `Access denied` in MySQL raw logs | Represents failed database authentication and potential credential guessing | `MySQLAudit_CL` |
| SQL `Query` events | Provides direct evidence of discovery, collection, or data manipulation | `MySQLAudit_CL` |
| New process executions after logon | Identifies post-compromise behavior | `DeviceProcessEvents` |
| File or registry modifications | Supports persistence, staging, or defense-evasion analysis | `DeviceFileEvents`, `DeviceRegistryEvents` |
| Denied outbound flows | Can indicate attempted C2, scanning, mining, pivoting, or exfiltration in this restricted environment | `NTANetAnalytics` |

## Limitations and Assumptions

- This was an intentionally vulnerable and isolated training system. Its security posture must not be copied to production.
- The central egress restrictions mean a lack of successful outbound C2 or exfiltration does not prove an attacker did not attempt it; denied flows may be the strongest available evidence.
- MySQL telemetry arrives as raw text and relies on correct log configuration, DCR configuration, parsing logic, and ingestion health.
- The shared `MySQLAudit_CL` table requires filtering on `_ResourceId` to avoid analyzing another participant's telemetry.
- The activity observed depends on when the host is discovered, what services are exposed, and the behavior of opportunistic internet actors.
- A successful logon or query alone is not enough to infer complete attacker intent. Correlation across timestamp, source IP, endpoint actions, database activity, and network telemetry is necessary.

## Evaluating False Positives and Benign Activity

| Activity | Why it may appear suspicious | Triage approach |
|---|---|---|
| Lab setup and validation | Administrators may generate successful local or MySQL logons while configuring the host | Compare event time to build and exposure records; validate expected source IP and account |
| MySQL Workbench testing | Test connections and `SELECT` statements resemble database access | Confirm the workstation/source IP, scheduled lab activity, and expected query text |
| Defender and Azure agent activity | Security tooling produces legitimate processes and network events | Check signer, file path, command line, parent process, and known agent behavior |
| Other shared-range telemetry | The custom MySQL table includes multiple environments | Filter precisely on `_ResourceId` / designated device name |
| Exposure and configuration changes | Firewall, NSG, service, and account changes occur during the lab setup | Treat the exposure timestamp and change log as authoritative context |

## Containment, Eradication, and Recovery

### Recommended Containment Steps

1. Record the time of suspected compromise and preserve the relevant event window.
2. Isolate the honeypot through the Microsoft Defender portal.
3. Capture a post-compromise Defender investigation package.
4. Preserve and export relevant logs before making recovery changes.

### Eradication and recovery

For a compromised honeypot, the preferred recovery action is to destroy the VM and restore the database from a known-good backup. If rebuilding is not feasible, the recovery process should include:

- Re-enable and harden the Network Security Group (NSG).
- Re-enable Windows Firewall.
- Remove or disable intentionally exposed local accounts.
- Replace weak passwords with strong, unique credentials stored appropriately.
- Prevent public MySQL access and remove unnecessary remote database accounts.
- Review persistence, processes, services, scheduled tasks, files, and registry changes before returning the host to service.
- Restore the database from a clean backup when integrity is uncertain.

## Lessons Learned

- **Instrumentation before exposure matters.** Creating and baselining detections before opening access establishes a trustworthy starting point for later investigations.
- **Database logs add critical context.** Endpoint telemetry may show that a user logged on, while MySQL logs show whether that access resulted in database authentication, enumeration, collection, or manipulation.
- **Raw logs require engineering.** Custom-log ingestion is only useful when the records are reliably scoped, parsed, and turned into investigation-ready fields.
- **Denied network activity is still evidence.** In a restricted lab, blocked outbound connections can reveal attempted attacker objectives even when the traffic does not succeed.
- **Timestamps connect the story.** The exposure time, initial access time, database-query times, and containment time provide the backbone for a defensible incident narrative.
- **Rebuild is often safer than clean.** A purposely compromised honeypot should generally be treated as untrusted; rebuilding and restoring data is often more reliable than attempting to remediate every possible change.


- `<honeypot-resource-name>`
- `<UTC-exposure-timestamp>`
- Public IP addresses, Azure subscription IDs, tenant IDs, resource IDs, passwords, and any real database records

Do not publish intentionally weak credentials, active public IP addresses, live resource names, or unredacted investigation-package contents.
