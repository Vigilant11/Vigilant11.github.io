






### NMAP
#### Quick TCP Scan
nmap -sC -sV -vv x.x.x.x

#### Quick UDP Scan
nmap -sU -sV -vv x.x.x.x

#### Full TCP Scan
nmap -sC -sV -p- -vv x.x.x.x

#### Verbose, syn, all ports, all scripts, no ping
nmap -vv -Pn -A -sC -sS -T4 -p- x.x.x.x

#### Verbose, SYN Stealth, Version info, and scripts against services.
nmap -v -sS -A -T4 x.x.x.x

###### netdiscover -r 192.168.1.0/24


### FTP Enumeration (21):
- ftp ip_addr port (Anonymous)
- nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 x.x.x.x

### SSH (22):
- ssh ip_addr 22
- hydra -l root -P passwords.txt x.x.x.x ssh
- ncrack -p 22 --user root -P passwords.txt x.x.x.x
- medusa -u root -P passwords.txt -h x.x.x. -M ssh

### Telnet(23)
- hydra -l root -P passwords.txt x.x.x.x telnet
- ncrack -p 23 --user root -P passwords.txt x.x.x.x
- medusa -u root -P 500-worst-passwords.txt -h x.x.x.x -M telnet

### SMTP Enumeration (25):
- nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 x.x.x.x
- nc -nv x.x.x.x 25
- telnet x.x.x.x 25

### Web Enumeration (80/443):
- dirb http://x.x.x.x/
- nikto –h 10.0.0.1
- curl -i ${IP}/robots.txt
- gobuster dir -u https://x.x.x.x/ -w ~/wordlists/shortlist.txt
- ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://x.x.x.x/FUZZ

### Pop3 (110):
- telnet x.x.x.x 110
- To login
USER [username]
PASS [password]
- To list messages
LIST
- Retrieve message
RETR [message number]
- quits
QUIT

### RPCBind (111):
- rpcinfo –p x.x.x.x

### SMB\RPC Enumeration (139/445):
- enum4linux –a x.x.x.x
- smbclient -L //x.x.x.x/
#####  List open shares
- smbclient //x.x.x.x/ipc$ -U john
- smbmap -H 192.168.24.24

##### SMB Vulnerability Scan
- nmap -A -vv --script=smb-vuln* -p445 x.x.x.x
- nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse x.x.x.x

##### SMB Users & Shares Scan
- nmap -p 445 -vv --script=smb-enum-shares.nse,smb-enum-users.nse x.x.x.x
- smbmap -H x.x.x.x

#### Null connect
- rpcclient -U "" x.x.x.x

### SNMP Enumeration (161):
- snmpwalk -c public -v1 x.x.x.x
- snmpcheck -t x.x.x.x -c public
- onesixtyone -c names -i hosts
- nmap -sT -p 161 x.x.x.x -oG results.txt
- snmpenum -t x.x.x.x

### Oracle (1521):
- tnscmd10g version/status -h x.x.x.x

### Mysql Enumeration (3306):
- nmap -sV -Pn -vv x.x.x.x -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122


### DNS Zone Transfers:
- nslookup -> set type=any -> ls -d abcd.com
- dig axfr blah.com @ns1.abcd.com
- dnsrecon -d abcd.com -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml


### Mounting File Share
- showmount -e x.x.x.x
- mount x.x.x.x:/vol/share /mnt/nfs  -nolock
- mounts the share to /mnt/nfs without locking it
- mount -t cifs -o username=user,password=pass,domain=blah //x.x.x.x/share-name /mnt/cifs
