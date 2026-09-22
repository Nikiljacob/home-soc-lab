\# Home SOC \& Detection Engineering Lab



A hands-on home Security Operations Center (SOC) lab built to practice SIEM monitoring, endpoint telemetry, detection engineering, alert triage, incident investigation, and MITRE ATT\&CK mapping.



The lab uses \*\*Wazuh\*\* as the central security monitoring platform with both Linux and Windows endpoints. Windows telemetry is enriched using \*\*Sysmon\*\*.



\---



\## Project Objectives



The goal of this project was to build a small SOC environment and practice the workflow used by security analysts:



1\. Collect endpoint telemetry

2\. Detect suspicious or security-relevant behaviour

3\. Investigate alerts

4\. Review raw event data

5\. Map activity to MITRE ATT\&CK

6\. Determine whether activity is benign, suspicious, or malicious

7\. Document investigation findings

8\. Create and test custom detection logic



\---



\## Lab Architecture



The environment was built using Oracle VirtualBox.



```text

&#x20;                        Internet

&#x20;                           |

&#x20;                          NAT

&#x20;                           |

&#x20;                 +-------------------+

&#x20;                 |     VirtualBox    |

&#x20;                 +-------------------+

&#x20;                    |             |

&#x20;                    |             |

&#x20;             +-------------+   +----------------+

&#x20;             | Wazuh SOC   |   | Windows 11     |

&#x20;             | Server      |   | Endpoint       |

&#x20;             |             |   |                |

&#x20;             | Manager     |   | Wazuh Agent    |

&#x20;             | Indexer     |   | Sysmon         |

&#x20;             | Dashboard   |   +----------------+

&#x20;             +-------------+

&#x20;                    |

&#x20;                    |

&#x20;             +--------------+

&#x20;             | Ubuntu       |

&#x20;             | Endpoint     |

&#x20;             |              |

&#x20;             | Wazuh Agent  |

&#x20;             +--------------+



Private lab communication:

VirtualBox Host-Only Network

```



The virtual machines used both NAT and Host-Only networking.



\- NAT provided internet access for downloads and updates.

\- Host-Only networking provided private communication between the endpoints and the Wazuh server.



\---



\## Technologies Used



\- Wazuh 4.14.7

\- Oracle VirtualBox

\- Ubuntu 24.04 LTS

\- Windows 11 Enterprise Evaluation

\- Sysmon

\- Windows Security Event Logs

\- Linux journald

\- PowerShell

\- Windows Command Prompt

\- Wazuh custom detection rules

\- MITRE ATT\&CK



\---



\## Skills Practiced



\- SIEM deployment and administration

\- Endpoint agent deployment

\- Linux and Windows log analysis

\- Sysmon telemetry analysis

\- Alert triage

\- Raw event investigation

\- Detection engineering

\- Windows process analysis

\- PowerShell investigation

\- Authentication monitoring

\- Account creation monitoring

\- False-positive and benign-activity analysis

\- MITRE ATT\&CK mapping

\- Incident documentation

\- Virtual networking

\- Linux service management

\- Security troubleshooting



\---



\# SOC Investigations



\## SOC-001 — Linux Sudo Authentication Investigation



A controlled sudo authentication test was generated on the Ubuntu endpoint.



The activity included:



\- Failed sudo authentication

\- PAM login failure

\- Successful sudo authentication

\- Privileged command execution

\- PAM session creation and closure



Wazuh detected the activity using built-in Linux authentication rules.



\### Key Detection



\- Wazuh Rule ID: `5401`

\- Severity: Level 5

\- Description: `Failed attempt to run sudo`

\- Source user: `nikil`

\- Destination user: `root`

\- Command: `/usr/bin/id`

\- MITRE ATT\&CK: `T1548.003`

\- Technique: Sudo and Sudo Caching



The alert was classified as \*\*Benign / Expected Lab Activity\*\* because the authentication failures were intentionally generated as part of the controlled test.



In a production environment, repeated failures, unusual users, unexpected source systems, suspicious privileged commands, or correlated activity would require further investigation.



\### Report



`Incident-Reports/SOC-001-Linux-Sudo-Authentication.md`



\---



\## SOC-002 — Windows Command Shell Custom Detection



A custom Wazuh detection rule was created to identify Windows Command Prompt process creation using Sysmon telemetry.



The purpose of this exercise was to move beyond built-in SIEM detections and create detection logic manually.



\### Detection Details



\- Custom Wazuh Rule ID: `100100`

\- Severity: Level 6

\- Data source: Sysmon

\- Sysmon Event ID: `1`

\- Event type: Process Create

\- Process monitored: `cmd.exe`



The activity was intentionally generated in the Windows lab endpoint.



The resulting event was investigated to review process creation data and demonstrate how a custom rule moves telemetry from:



```text

Endpoint Activity

&#x20;     |

&#x20;     v

Sysmon

&#x20;     |

&#x20;     v

Wazuh Agent

&#x20;     |

&#x20;     v

Custom Rule

&#x20;     |

&#x20;     v

Alert

&#x20;     |

&#x20;     v

Analyst Investigation

```



The detection was classified as \*\*Benign / Expected Lab Activity\*\* because Command Prompt was deliberately launched for testing.



`cmd.exe` is a legitimate Windows utility, so its execution alone should not be treated as proof of malicious activity.



\### Detection Rule



`Detection-Rules/100100-Windows-CMD-Detection.xml`



\### Report



`Incident-Reports/SOC-002-Windows-Command-Shell-Detection.md`



\---



\## SOC-003 — Encoded PowerShell Investigation



A controlled encoded PowerShell command was executed to validate Sysmon telemetry and Wazuh detection of potentially suspicious PowerShell behaviour.



The test command used PowerShell's `-EncodedCommand` parameter.



The encoded content represented the harmless command:



```powershell

Write-Output 'SOC-003 test'

```



Sysmon recorded the new PowerShell process and its command line.



\### Detection Details



\- Wazuh Rule ID: `92057`

\- Severity: Level 12

\- Description: PowerShell spawned a PowerShell process which executed a Base64 encoded command

\- Sysmon Event ID: `1`

\- Event type: Process Create

\- User: `DESKTOP-K47D631\\nikil`

\- Integrity Level: High

\- MITRE ATT\&CK: `T1059.001`

\- Technique: PowerShell

\- Tactic: Execution



The process image was:



```text

C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

```



The command line contained:



```text

\-NoProfile -EncodedCommand <Base64 data>

```



\### Analyst Assessment



The activity was classified as \*\*Benign / Expected Lab Activity\*\*.



Although encoded PowerShell can be used legitimately, it is also commonly associated with attempts to obscure command contents and therefore deserves investigation.



In this case, the Base64 content was known and intentionally generated for the lab.



A production investigation would also review:



\- Parent and child processes

\- User context

\- Network connections

\- File creation

\- Registry activity

\- Additional PowerShell activity

\- Related endpoint alerts



\### Detection Engineering Lesson



During this investigation, an experimental custom PowerShell rule was tested.



It was discovered that Wazuh already provided a stronger built-in detection through Rule `92057`.



The duplicate experimental rule was therefore removed.



This demonstrated an important detection-engineering principle:



> Existing detection coverage should be reviewed before adding new rules that may create unnecessary duplication or alert noise.



\### Report



`Incident-Reports/SOC-003-Encoded-PowerShell-Investigation.md`



\---



\## SOC-004 — Windows Account Creation Investigation



A temporary Windows local account was created to test Windows account-management monitoring.



The temporary account was:



```text

soc-test

```



Windows generated Security Event ID `4720`, indicating that a user account was created.



\### Detection Details



\- Windows Event ID: `4720`

\- Event Provider: Microsoft-Windows-Security-Auditing

\- Wazuh Rule ID: `60109`

\- Severity: Level 8

\- Description: `User account enabled or created`

\- Account performing the action: `nikil`

\- Created account: `soc-test`

\- MITRE ATT\&CK: `T1098`

\- Technique: Account Manipulation

\- Tactic: Persistence



\### Analyst Assessment



The event clearly identified the account responsible for the activity and the newly created account.



Unexpected local account creation can represent persistence if an attacker creates or modifies accounts to maintain access to a compromised endpoint.



In a production environment, an analyst would investigate:



\- Who created the account

\- Whether the action was authorized

\- Administrative privilege assignment

\- Group membership changes

\- Subsequent logons

\- Related PowerShell or command-shell activity

\- Additional endpoint alerts around the same timestamp



The activity was classified as \*\*Benign / Expected Lab Activity\*\* because the account was intentionally created for the SOC exercise.



The temporary account was removed after the investigation.



\### Report



`Incident-Reports/SOC-004-Windows-Account-Creation.md`



\---



\# Detection Engineering



\## Custom Windows Command Prompt Detection



A custom Wazuh rule was created to detect Windows Command Prompt process creation through Sysmon.



```xml

<group name="windows,sysmon,custom\_detection,">



&#x20; <rule id="100100" level="6">

&#x20;   <if\_group>sysmon\_event1</if\_group>

&#x20;   <field name="win.eventdata.image">\\\\cmd\\.exe$</field>

&#x20;   <description>Custom detection: Windows Command Prompt launched</description>

&#x20; </rule>



</group>

```



\### Rule Logic



The rule checks:



```text

Sysmon Process Create Event

&#x20;         |

&#x20;         v

Is the executable cmd.exe?

&#x20;         |

&#x20;         v

&#x20;       Yes

&#x20;         |

&#x20;         v

Generate Wazuh Level 6 Alert

```



The purpose of the rule was detection-engineering practice.



Command Prompt is a legitimate Windows utility, so execution alone should not be considered malicious.



In a production environment, the rule would require additional context or tuning to reduce false positives.



The detection could potentially be extended with conditions involving:



\- Suspicious command-line arguments

\- Unusual parent processes

\- Privileged users

\- Network activity

\- Child process execution

\- Known attack patterns



\---



\# Example Detection Pipeline



The lab demonstrated the following security monitoring workflow:



```text

User or System Activity

&#x20;         |

&#x20;         v

Operating System / Sysmon

&#x20;         |

&#x20;         v

Security Event Generated

&#x20;         |

&#x20;         v

Wazuh Agent

&#x20;         |

&#x20;         v

Wazuh Manager

&#x20;         |

&#x20;         v

Decoder

&#x20;         |

&#x20;         v

Detection Rule

&#x20;         |

&#x20;         v

Security Alert

&#x20;         |

&#x20;         v

SOC Analyst Investigation

&#x20;         |

&#x20;         +------------+

&#x20;         |            |

&#x20;         v            v

&#x20;      Benign       Suspicious

&#x20;                      |

&#x20;                      v

&#x20;                  Incident

```



\---



\# Event vs Alert vs Incident



One of the main lessons from the lab was understanding the difference between an event, an alert, and an incident.



\## Event



An event is simply something that occurred on a system.



Examples include:



\- A process starts

\- A user logs in

\- A password fails

\- A file is modified

\- A user account is created



Sysmon and operating system logs can generate large numbers of events.



\## Alert



An alert occurs when detection logic identifies an event or sequence of events that matches a security rule.



Not every event becomes an alert.



\## Incident



An incident is activity that has been investigated and determined to require security response.



Not every alert becomes an incident.



This relationship can be represented as:



```text

Event

&#x20; |

&#x20; v

Detection Rule

&#x20; |

&#x20; v

Alert

&#x20; |

&#x20; v

Analyst Investigation

&#x20; |

&#x20; +--------> Benign

&#x20; |

&#x20; +--------> Suspicious

&#x20; |

&#x20; +--------> Confirmed Incident

```



\---



\# Key Lessons Learned



\## High Severity Does Not Automatically Mean Malicious



SOC-003 generated a Level 12 alert for encoded PowerShell.



Despite the high severity, investigation showed that the command was deliberately generated as part of the lab.



Severity helps analysts prioritize alerts, but context is still required.



\---



\## MITRE ATT\&CK Describes Behaviour



Several events were mapped to MITRE ATT\&CK techniques.



Examples included:



\- `T1548.003` — Sudo and Sudo Caching

\- `T1059.001` — PowerShell

\- `T1098` — Account Manipulation



A MITRE ATT\&CK mapping does not automatically prove malicious activity.



Legitimate administrative activity and attacker behaviour can sometimes use the same operating system features.



\---



\## Raw Logs Matter



Dashboards provide useful summaries, but detailed investigation requires reviewing underlying event fields.



Examples reviewed during the project included:



\- User

\- Command line

\- Parent process

\- Process image

\- Integrity level

\- Source and destination users

\- Event ID

\- Rule ID

\- Rule severity

\- Endpoint

\- Timestamp

\- MITRE ATT\&CK mapping



\---



\## Detection Engineering Requires Testing



A detection rule should not simply be written and assumed to work.



The project followed a workflow of:



```text

Create Rule

&#x20;   |

&#x20;   v

Validate Syntax

&#x20;   |

&#x20;   v

Restart Detection Engine

&#x20;   |

&#x20;   v

Generate Controlled Activity

&#x20;   |

&#x20;   v

Check Telemetry

&#x20;   |

&#x20;   v

Confirm Alert

&#x20;   |

&#x20;   v

Investigate

&#x20;   |

&#x20;   v

Tune or Remove Rule

```



The PowerShell exercise also demonstrated that duplicate detection logic should be avoided when stronger native coverage already exists.



\---



\## Troubleshooting Is Part of Security Engineering



The lab required troubleshooting several infrastructure issues including:



\- VirtualBox networking

\- Host-only connectivity

\- Wazuh agent registration

\- Wazuh agent connectivity

\- Virtual machine storage

\- Wazuh services

\- Windows virtualization conflicts

\- Sysmon telemetry

\- Custom rule syntax

\- Rule matching behaviour



The troubleshooting process followed:



```text

Observe Problem

&#x20;     |

&#x20;     v

Collect Evidence

&#x20;     |

&#x20;     v

Form Hypothesis

&#x20;     |

&#x20;     v

Test One Change

&#x20;     |

&#x20;     v

Observe Result

&#x20;     |

&#x20;     v

Confirm or Continue Investigation

```



\---



\# Evidence



Screenshots captured during the project include:



\- Initial Wazuh deployment

\- Ubuntu agent enrollment

\- Linux threat-hunting baseline

\- Failed sudo authentication investigation

\- Wazuh rule and MITRE details

\- Windows agent enrollment

\- Custom Windows command-shell detection

\- Custom detection event details

\- Encoded PowerShell detection

\- Windows account creation event details



Example evidence files include:



```text

Screenshots/

├── 01-wazuh-dashboard-initial.png

├── 02-ubuntu-agent-active.png

├── 03-threat-hunting-baseline.png

├── 04-sudo-authentication-investigation.png

├── 05-sudo-event-details.png

├── 06-sudo-rule-mitre-details.png

├── 07-windows-agent-active.png

├── 08-custom-cmd-detection.png

├── 09-custom-cmd-event-details.png

├── SOC-003-01-encoded-powershell-alert.png

└── SOC-004-02-user-account-event-details.png

```



\---



\# Repository Structure



```text

home-soc-lab/

|

|-- README.md

|

|-- Detection-Rules/

|   |

|   `-- 100100-Windows-CMD-Detection.xml

|

|-- Incident-Reports/

|   |

|   |-- SOC-001-Linux-Sudo-Authentication.md

|   |

|   |-- SOC-002-Windows-Command-Shell-Detection.md

|   |

|   |-- SOC-003-Encoded-PowerShell-Investigation.md

|   |

|   `-- SOC-004-Windows-Account-Creation.md

|

`-- Screenshots/

&#x20;   |

&#x20;   |-- Wazuh deployment evidence

&#x20;   |

&#x20;   |-- Endpoint enrollment evidence

&#x20;   |

&#x20;   |-- Linux authentication investigation evidence

&#x20;   |

&#x20;   |-- Custom detection evidence

&#x20;   |

&#x20;   |-- PowerShell investigation evidence

&#x20;   |

&#x20;   `-- Windows account creation evidence

```



Virtual machine disks and installation media are intentionally excluded from the repository.



\---



\# Security Notes



This project was performed in an isolated virtual lab environment.



All suspicious or security-relevant activity documented in the repository was intentionally generated for defensive security testing and detection validation.



No malware was deployed.



The repository does not contain:



\- Real passwords

\- Personal credentials

\- API keys

\- Access keys

\- Private keys

\- Authentication tokens

\- Virtual machine disks

\- Operating system installation images



Private laboratory IP addresses may appear in screenshots or reports.



These addresses belong only to the isolated VirtualBox environment.



\---



\# Future Improvements



Possible extensions to the project include:



\- Sigma rule testing

\- Additional Sysmon configuration tuning

\- File Integrity Monitoring investigations

\- Windows scheduled-task monitoring

\- PowerShell detection engineering

\- Network connection investigations

\- Vulnerability detection

\- Threat intelligence enrichment

\- Automated alert enrichment

\- Additional Windows Security Event monitoring

\- Brute-force authentication detection

\- File creation and persistence investigations



\---



\# Project Outcome



This project provided practical experience building and operating a small SOC environment rather than only studying SIEM concepts theoretically.



The completed lab demonstrated:



\- Centralized security monitoring

\- Linux and Windows endpoint telemetry

\- Sysmon deployment

\- Wazuh agent management

\- Threat hunting

\- Alert investigation

\- Raw event analysis

\- Custom detection engineering

\- MITRE ATT\&CK mapping

\- False-positive analysis

\- Incident documentation

\- Infrastructure troubleshooting



Four documented SOC investigations were completed:



```text

SOC-001  Linux sudo authentication

SOC-002  Windows custom command-shell detection

SOC-003  Encoded PowerShell execution

SOC-004  Windows local account creation

```



The project was designed as a practical foundation for entry-level SOC, security analyst, detection engineering, and blue-team roles.



\---



\## Disclaimer



This project was created for cybersecurity education, defensive monitoring, and detection-engineering practice in an isolated lab environment.



All testing was performed on systems owned and controlled within the lab.

