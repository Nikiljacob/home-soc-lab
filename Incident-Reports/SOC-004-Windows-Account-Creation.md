\# SOC-004 - Windows Local Account Creation Investigation



\## Summary



A controlled local user account creation test was performed on the Windows

endpoint `lab-windows-01` to validate Windows Security Event monitoring and

Wazuh account-management detections.



A temporary account named `soc-test` was created using an administrative

command.



\## Endpoint



\- Host: lab-windows-01

\- Agent ID: 002

\- IP Address: 192.168.56.104

\- Operating System: Windows 11 Enterprise Evaluation



\## Detection



\- Windows Event ID: 4720

\- Wazuh Rule ID: 60109

\- Rule Level: 8

\- Description: User account enabled or created

\- Event Provider: Microsoft-Windows-Security-Auditing



\## Account Activity



Account performing the action:



\- User: nikil

\- Domain: DESKTOP-K47D631



New account:



\- Username: soc-test

\- Domain: DESKTOP-K47D631

\- Primary Group ID: 513



\## MITRE ATT\&CK



Wazuh mapped the activity to:



\- Technique: T1098

\- Technique Name: Account Manipulation

\- Tactic: Persistence



\## Analysis



Windows generated Security Event ID 4720 indicating that a new local user

account was created.



The event identified `nikil` as the account responsible for creating the

new `soc-test` account.



Unexpected account creation can indicate persistence activity because an

attacker with sufficient privileges may create or modify accounts to maintain

access to a compromised system.



In a production investigation, the analyst would review:



\- Who created the account

\- Whether the creator was authorized

\- Group membership changes

\- Administrative privilege assignment

\- Subsequent logons using the account

\- Related PowerShell or command-shell activity

\- Other endpoint alerts around the same timestamp



\## Assessment



Benign / Expected Lab Activity.



The `soc-test` account was deliberately created as part of a controlled SOC

lab exercise. No unauthorized account creation or malicious persistence was

observed.



\## Outcome



No containment was required because the activity was intentionally generated.



The temporary lab account was removed after the investigation.



\## Lessons Learned



This investigation demonstrated:



\- Windows Security Event ID 4720 analysis

\- Local account creation monitoring

\- Wazuh account-management detection

\- User and target-account attribution

\- MITRE ATT\&CK mapping

\- Persistence-related investigation

\- Distinguishing authorized administrative activity from suspicious account creation

