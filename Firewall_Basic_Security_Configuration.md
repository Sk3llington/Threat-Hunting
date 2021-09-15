### Setting up Firewalld


For this demonstration I will play a Jr. Security Administrator tasked with configuring Zones that will segment each network according to the type of service these networks are used for within the company's network.

##### Below, the list of the Zones that I will create:


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
    $ sudo firewall-cmd --permanent --zone=public --add-service=https
    $ sudo firewall-cmd --permanent --zone=public --add-service=pop3
    $ sudo firewall-cmd --permanent --zone=public --add-service=smtp
    ```

