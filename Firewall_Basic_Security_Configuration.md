### Setting up Firewalld

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


