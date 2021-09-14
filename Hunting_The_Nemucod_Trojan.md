## The Nemucod Hunt

In this demonstration I will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.

As a Junior Security Administrator, my primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.
 
I will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling *Threat Intelligence* as part of my incident report.

### Setting Up the Lab

To complete this investigation I was provided with IOCs from Sguil that I will use to conduct my analysis:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

In order to complete my triage and analysis of the logs I will follow a simple framework answering a series of questions to complete my investigation based on the stages of the Cyber Kill Chain.

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
 
 
#### Findings:
 
Based on the attacker(s) TTPs, it seems that the JavaScript Trojan Nemucod is distributed via email spam messages informing people about owed fines, failed payments, and held baggages. 
This particular way of targeting people requires whoever receives the message to give it immediate attention. The attacker uses “urgency” to have the victim open the attachment containing the malicious file. Major campaigns took place targeting Italy, U.S., Europe, Canada, India and Russia, where the trojan was hidden as an attachment in the email, masquerading as a `.zip` file. 


|         TTP        |                 Example                   |
| ------------------ | ----------------------------------------- |
| **Weaponization**  |  What was it that was downloaded?         |
 

#### Findings:

A fake file masquerading as an invoice or, in later campaigns, as documents such as contracts or informational documents in a `.zip` format. 
 
Inside the .zip file, a JavaScript malware was hidden (Nemucod) and once ran will either download an `.EXE` file that will then run to retrieve a Trojan Downloader called `Fareit` or `Pony Downloader` which in turn will download another set of `.exe` files containing password/info-stealer malware such as Gozi and Zeus (originally), and more recently, ransomware such as TeslaCrypt and Locky.


|         TTP        |                 Example                   |
| ------------------ | ----------------------------------------- |
| **Delivery**       |    How was it downloaded?                 |
 

#### Findings:

First, via email attachment in `.zip` format.
 
Then, once the victim unzips the file and runs the JavaScript malware masquerading as an invoice or other PDF document, it will download the rest of the payload from webservers over HTTP. 
 
##### Example of domains used in different campaigns targeting Italian users involving Nemucod:

dcmyx[.]com
ibmdatacap[.]com
www.landtourjapan[.]com
thevillageveterinaryhospital[.]com
majorcase[.]org
albirtchad[.]org 
czarplast[.]com 
www.yurtmobilyalari[.]net
jlinksms[.]com 
alberchad[.]org
bugrasilte[.]com
skbmw[.]com
wellnessherbal[.]com
istanbulklima[.]org
sieumaukimdung[.]com
skbmw[.]com
erikssonelectric[.]com
sieumaukimdung[.]com 
www.landtourjapan[.]com
albirtchad[.]org 
creativefoodstylist[.]com 
wellnessherbal[.]com 
belarusstudy[.]com 
adenyaoteleet[.]com 
tripsnepal[.]com

#### C&C servers for the Trojan Downloaders:

famoussuperstars[.]ru
torpedazil[.]ru
gofermertoop[.]ru
109.120.142[.]168
109.120.155[.]30
83.69.230[.]16


|         TTP        |                 Example                   |
| ------------------ | ----------------------------------------- |
| **Exploitation**   |  What does the exploit do?                |

 
#### Findings: 
 
When the victim unzip the `.zip` file and run the fake invoice/document, the trojan Nemucod will run an `.exe` file that will download a Trojan downloader malware (`Fareit` or `Pony`). Another way the malware Nemucod exploits the system to download the Trojan Downloader is to download a DLL library and then run it via `rundll32.exe`, leading to the download of the Trojan downloaders mentioned above.



|         TTP        |                 Example                   |
| ------------------ | ----------------------------------------- |
| **Installation**   | How is the exploit installed?             |


#### Findings:
 
The Trojan downloaders contact their C&C servers (listed above) and download additional malware in order to launch the final payloads. The malware include Gozi and Zeus (information-stealer), and more recently, ransomware such as TeslaCrypt and Locky.


|         TTP        |                         Example                          |
| ------------------ | ---------------------------------------------------------| 
| **C&C (C2))**      | How does the attacker gain control of the remote machine?|

 
#### Findings: 

Once the Trojan downloaders call back home (the C&Cs), they download malware to the victim’s machine (Gozi, Zeus, Locky etc.). The malware then establishes a connection with the C&C servers to received commands from the attacker(s) as well as to send back the stolen data from the victim’s system.


