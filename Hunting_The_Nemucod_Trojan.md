## The Nemucod Hunt

In this demonstration I will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.

As a Junior Security Administrator, my primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.
 
I will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling *Threat Intelligence* as part of my incident report.

### Setting Up the Lab

To complete this investigation I was provided with IOCs from Sguil that I will use to conduct my analysis:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

In order to complete my triage and analysis of the logs I will follow a simple framework answering a series of questions to complete my investigation.

#### 1. What was the indicator of an attack?
 
The indicator of an attack was the download of a .EXE file (payload) from an HTTP web server (port 80) by a JavaScript Trojan called “Nemucod”.


#### 2. What was the adversarial motivation?
 
Based on available information, “Nemucod” is a JavaScript trojan that is usually hidden in a `.zip` file. Once the victim opens the `.zip` folder and runs the JavaScript file, the trojan downloads a file to the %TEMP% folder and runs it. Nemucod is usually used by attackers to distribute other malware such as Gozi and Zeus, which are password and information-stealer. 
 
Nevertheless, in recent years attackers using Nemucod have been downloading ransomware such as TeslaCrypt and Locky (aka Locki).
 
If we take into consideration the payloads downloaded by Nemucod in recent attacks observed by most AV companies, we can assume that the attackers primary motivation was to install ransomware.


#### 3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.


|         TTP        |                 Example                   |
| ------------------ | ----------------------------------------- |
| **Reconnaissance** |  How did the attacker locate the victim?  | 
 

Based on the attacker(s) TTPs, it seems that the JavaScript Trojan Nemucod is distributed via email spam messages informing people about owed fines, failed payments, and held baggages. 
This particular way of targeting people requires whoever receives the message to give it immediate attention. The attacker uses “urgency” to have the victim open the attachment containing the malicious file. Major campaigns took place targeting Italy, U.S., Europe, Canada, India and Russia, where the trojan was hidden as an attachment in the email, masquerading as a `.zip` file. 


