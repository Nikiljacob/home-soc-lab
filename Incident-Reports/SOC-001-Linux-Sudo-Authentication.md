\# SOC-001 - Linux Sudo Authentication Investigation



\## Incident Summary



A controlled authentication test was performed on the Ubuntu endpoint

`lab-ubuntu-01` to validate Wazuh log collection, detection, and alert

investigation capabilities.



Two incorrect sudo authentication attempts were intentionally generated,

followed by a successful sudo authentication.



\## Environment



\- Endpoint: lab-ubuntu-01

\- Operating System: Ubuntu 24.04.3 LTS

\- Endpoint IP: 192.168.56.101

\- Wazuh Agent ID: 001

\- Wazuh Server: 192.168.56.103



\## Activity Performed



The following test sequence was generated:



1\. Cleared cached sudo credentials.

2\. Attempted sudo authentication using an incorrect password.

3\. Attempted sudo authentication using an incorrect password again.

4\. Successfully authenticated using the correct password.

5\. Executed `/usr/bin/id` with elevated privileges.



\## Detected Events



Wazuh detected several related events:



\- Rule 5503 - PAM: User login failed

\- Rule 5401 - Failed attempt to run sudo

\- Rule 5402 - Successful sudo to ROOT executed

\- Rule 5501 - PAM: Login session opened

\- Rule 5502 - PAM: Login session closed



\## Primary Alert



\- Rule ID: 5401

\- Rule Level: 5

\- Description: Failed attempt to run sudo

\- Source User: nikil

\- Destination User: root

\- Command: /usr/bin/id

\- Working Directory: /home/nikil

\- Log Source: journald

\- Decoder: sudo



\## MITRE ATT\&CK Mapping



\- Technique: T1548.003

\- Technique Name: Sudo and Sudo Caching

\- Tactics:

&#x20; - Privilege Escalation

&#x20; - Defense Evasion



\## Evidence



The raw event indicated:



\- Two incorrect password attempts

\- User `nikil`

\- Destination user `root`

\- Terminal `pts/0`

\- Working directory `/home/nikil`

\- Command `/usr/bin/id`



\## Analyst Assessment



The activity was determined to be benign.



The failed authentication attempts were intentionally generated as part of

the SOC lab. A small number of failed sudo authentication attempts followed

by a successful authentication does not independently indicate compromise.



In a production environment, additional investigation would be warranted if

the activity involved repeated failures, unexpected users, unusual hosts,

unusual privileged commands, or correlated suspicious activity.



\## Outcome



No containment or remediation action was required because this was controlled

lab-generated activity.



\## Lessons Learned



This investigation demonstrated the complete monitoring workflow:



Endpoint activity -> Linux logs -> Wazuh agent -> decoder -> detection rule ->

alert -> MITRE ATT\&CK mapping -> analyst investigation -> assessment.

