\# SOC-003 - Encoded PowerShell Execution Investigation



\## Summary



A controlled PowerShell execution test was performed on the Windows endpoint

lab-windows-01 to validate Sysmon telemetry collection and Wazuh detection

capabilities.



A PowerShell process was used to launch another PowerShell process with a

Base64-encoded command.



\## Endpoint



\- Host: lab-windows-01

\- Agent ID: 002

\- IP Address: 192.168.56.104

\- User: DESKTOP-K47D631\\nikil

\- Operating System: Windows 11 Enterprise Evaluation



\## Detection



\- Wazuh Rule ID: 92057

\- Rule Level: 12

\- Description: Powershell.exe spawned a powershell process which executed a base64 encoded command

\- Sysmon Event ID: 1 - Process Create



\## Process Details



\- Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

\- Parent Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

\- Integrity Level: High

\- User: DESKTOP-K47D631\\nikil



The command line contained:



powershell.exe -NoProfile -EncodedCommand <Base64 data>



The Base64 data represented the intentionally generated lab command:



Write-Output 'SOC-003 test'



\## MITRE ATT\&CK



\- Technique: T1059.001

\- Technique Name: PowerShell

\- Tactic: Execution



\## Analysis



The alert was generated because PowerShell spawned another PowerShell process

using the EncodedCommand parameter.



Encoded PowerShell can be legitimate, but it can also be used to obscure

command contents and therefore warrants investigation.



The analyst reviewed the process image, command line, parent process, user,

integrity level, Sysmon Event ID and associated Wazuh detection.



\## Assessment



Benign / Expected Lab Activity.



The activity was intentionally generated as part of the SOC lab. The decoded

command only produced the text "SOC-003 test", and no additional evidence of

malicious activity was observed.



In a production environment, further investigation would include decoding the

command, reviewing surrounding process activity, network connections, file

activity, user context, parent/child processes and related endpoint alerts.



\## Outcome



No containment or remediation was required because the activity was a

controlled lab test.



\## Lessons Learned



This investigation demonstrated:



\- Sysmon process creation telemetry

\- PowerShell command-line visibility

\- Base64 encoded command detection

\- Wazuh alert triage

\- Parent-child process analysis

\- Severity interpretation

\- MITRE ATT\&CK mapping

\- Differentiating suspicious behaviour from confirmed malicious activity

