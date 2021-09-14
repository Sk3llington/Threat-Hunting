## Snort Rules Analysis & Threat Hunting

Below, the Snort rules that I am going to analyze using a simple framework to answer a couple of questions about each Rule to quickly identify threats and their level of severity.

### Snort Rule #1
 
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
```

#### 1. Analyzing the rule header and making sense of the log.

First I start by isolating the header and interpreting the data:

Header: `alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820`

This alerts users of any inbound TCP traffic coming from any source ip address and ports, to any internal ip addresses with ports ranging from 5800 to 5820.

#### 2. What stage of the Cyber Kill Chain does this alert violate?

This alert violates the Stage 1, Reconnaissance. The ET threat highlighted a potential scan of ports ranging from 5800 to 5820.


#### 3. What kind of attack is this rule monitoring?

This rule is monitoring the network for a port scanning attack. The attackers are scanning the network looking for weaknesses. The alert highlighted a potential VNC scan of ports ranging from 5800 to 5820


### Snort Rule #2

```bash
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
```

#### 1. Analyzing the rule header and making sense of the log.

Header: `alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any`

This is an alert for inbound TCP traffic from any external web server ip addresses ($HTTP_PORTS) to any internal network ip addresses and ports.
 
In this case it indicates that someone has downloaded a Windows executable file or DLL over HTTP.

#### 2. What layer of the Cyber Kill Chain model does this alert violate?
 
The Delivery layer.


#### 3. What kind of attack is this rule monitoring?
 
The rule watches for downloads of potential Windows malicious files over HTTP.
