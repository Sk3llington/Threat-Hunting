### Setting up Firewalld


For this demonstration I will play a Jr. Security Administrator tasked with configuring Zones that will segment each network according to the type of service these networks are used for within the company's network.

#### Below, the list of Zones that I will create:


**Public Zone**

* Services: HTTP, HTTPS, POP3, SMTP
* Interface: ETH0



**Web Zone**

* Source IP: 201.45.34.126
* Services: HTTP
* Interface: ETH1



**Sales Zone**

* Source IP: 201.45.15.48
* Services: HTTPS
* Interface: ETH2



**Mail Zone**

* Source IP: 201.45.105.12
* Services: SMTP, POP3
* Interface: ETH3

I was also tasked to add the following IP addresses to the firewall's black list:

* 10.208.56.23
* 135.95.103.76
* 76.34.169.118


First, let's begin by running the commands that enable and start `firewalld` upon boots and reboots.

```bash
$ sudo /etc/init.d/firewalld start
```

```bash
$ sudo systemctl start firewalld
```

```bash
$ sudo systemctl enable firewalld
```

##### Note: 
This will ensure that `firewalld` remains active after each reboot.


#### Confirming that the service is running.


Command that checks whether or not the `firewalld` service is up and running:
 

```bash
$ sudo firewall-cmd --state
```
OR
```
$ sudo systemctl status firewalld
```


#### Listing all firewall rules currently configured.
 
Next, I listed all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.
 
Command that lists all currently configured firewall rules:
 
    ```bash
    $ sudo firewall-cmd --list-all
    ```
 
##### Tips: 

Take note of what Zones and settings are configured. You may need to remove unneeded services and settings.


#### Listing all supported service types that can be enabled.
 
Command that lists all currently supported services to see if the service you need is available:
 
```bash
$ sudo firewall-cmd --get-services
```
 
##### Note:

You can see that the `Home` and `Drop` Zones are created by default.


#### Zone Views
 
Command that lists all currently configured zones:
 
```bash
$ sudo firewall-cmd --list-all-zones
```

You can see that the `Public` and `Drop` Zones are created by default. 

To demonstrate how to create "Zones", I will create Zones for `Web`, `Sales`, and `Mail`.


#### Create Zones for `Web`, `Sales` and `Mail`.

 
##### Commands that create Web, Sales and Mail zones:
 
```bash
$ sudo firewall-cmd --permanent --new-zone=Web
```
```bash
$ sudo firewall-cmd --permanent --new-zone=Sales
```
```bash
$ sudo firewall-cmd --permanent --new-zone=Mail
```
 
##### Command to reload to apply changes:

```bash
Sudo firewall-cmd --reload
``` 

#### Set the zones to their designated interfaces.
 
##### Commands that set your `eth` interfaces to your zones:
 
```bash
$ sudo firewall-cmd --permanent --zone=Public --add-interface=eth0
```
```bash 
$ sudo firewall-cmd --permanent --zone=Web --add-interface=eth1
```
```bash
$ sudo firewall-cmd --permanent --zone=Sales --add-interface=eth2
```
```bash
$ sudo firewall-cmd --permanent --zone=Mail --add-interface=eth3
```
 
##### Again we need to reload the firewall to apply the changes:

```bash 
$ sudo firewall-cmd --reload
```

#### Add services to the active zones:
 
##### Commands that add services to the **public** zone, the **web** zone, the **sales** zone, and the **mail** zone:
 
- **Public:**
 
```bash
$ sudo firewall-cmd --permanent --zone=public --add-service=http
```
```bash
$ sudo firewall-cmd --permanent --zone=public --add-service=https
```
```bash
$ sudo firewall-cmd --permanent --zone=public --add-service=pop3
```
```bash
$ sudo firewall-cmd --permanent --zone=public --add-service=smtp
```

- **Web:**
 
```bash
$ sudo firewall-cmd --permanent --zone=Web --add-service=http
```

- **Sales:**
 
```bash
$ sudo firewall-cmd --permanent --zone=Sales --add-service=https
```

- **Mail:**
 
```bash
$ sudo firewall-cmd --permanent --zone=Mail --add-service=smtp
```
```bash
$ sudo firewall-cmd --permanent --zone=Mail --add-service=pop3
```

#### Add malicious actors to the Drop Zone.
 
##### Command that will add all current and any future blacklisted IPs to the Drop Zone.
 
```bash
$ sudo firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='10.208.56.23' reject"
```
```bash
$ sudo firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='135.95.103.76' reject"
```
```bash
$ sudo firewall-cmd --permanent --zone=drop --add-rich-rule="rule family='ipv4' source address='76.34.169.118' reject"
```
 
##### Command to reload and apply the changes to the zone:

```bash
$ sudo firewall-cmd --reload
```

#### Make rules permanent then reload them.
 
It's good practice to ensure that your `firewalld` installation remains nailed up and retains its services across reboots. This ensures that the network remains secured after unplanned outages such as power failures.
 
##### Command that reloads the `firewalld` configurations and writes it to memory:
 
```bash
$ sudo firewall-cmd --reload
```

#### View active Zones
 
Now, I want to provide truncated listings of all currently **active** zones. This is a good time to verify my zone settings.
 
##### Command to display all current “active” zones:

```bash
$ sudo firewall-cmd --get-active-zones
```

##### Command that displays all zone services.
 
```bash
$ sudo firewall-cmd --list-services
```


#### How to Block an IP address.
 
I used a rich-rule that blocks the IP address `138.138.0.3`.
 
```bash
$ sudo firewall-cmd --permanent --zone=public --add-rich-rule="rule family='ipv4' source address='138.138.0.3' reject"
```


##### Command to reload the firewall: 

```bash
$ sudo firewall-cmd --reload
```


#### Block Ping/ICMP Requests.
 
Now it's time to harden my network against `ping` scans by blocking `icmp echo` replies.
 
##### Command that blocks `pings` and `icmp` requests in your `public` zone:
 
```bash
$ sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request
```


#### Rule Check
 
Now that I've set up my brand new `firewalld` installation, it's time to verify that all of the settings have taken effect.
 
##### Commands that lists all of the rule settings. Do one command at a time for each zone:


```bash
$ sudo firewall-cmd --zone=public --list-all
```
```bash
$ sudo firewall-cmd --zone=Web --list-all
```
```bash
$ sudo firewall-cmd --zone=mail --list-all
```
```bash
$ sudo firewall-cmd --zone=sales --list-all
```
```bash
$ sudo firewall-cmd --zone=drop --list-all
```


I have successfully configured and deployed a fully comprehensive `firewalld` installation!
