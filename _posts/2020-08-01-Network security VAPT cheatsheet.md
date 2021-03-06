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

### FTP (21): (Vsftpd, ProFTPD)
File Transfer Protocol (FTP) is used for the transfer of computer files between a client and server in a network via port 21.
Attacks :

##### 1. Anonymous login
If anonymous login is allowed by admin to connect with FTP then anyone can login into server.
To check Anonymous login permissions.
-	ftp X.X.X.X port (Anonymous)
-	use auxiliary/scanner/ftp/anonymous

##### 2. Unauthenticated login
-	ftp X.X.X.X port

##### 3. FTP Sniffing
FTP users may authenticate themselves with a clear-text sign-in protocol for username and password.
Attacker can take help of sniffing tools which can sniff the data packet travelling between server and client in a network and retrieve credential, this is known as sniffing, after then use them for unauthorized access.
- wireshark tool

##### 4. FTP Bruteforce
Attacker can use bruteforce to get valid credentials.
-	auxiliary/scanner/ftp/ftp_login
- nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 X.X.X.X

### SSH (22): (OpenSSH)
SSH (Secure Shell) is used for secure and reliable remote login from one computer to another.
-	ssh X.X.X.X
-	nmap -sV -p22 X.X.X.X
-	nmap -Pn --script ssh-auth-methods,ssh2-enum-algos X.X.X.X
-	use scanner/ssh/ssh_enumusers
-	nmap X.X.X.X -p 22 --script ssh-brute --script-args    userdb=users.txt,passdb=passwords.txt

##### Bruteforce attack-
-	auxiliary/scanner/ssh/ssh_login
-	hydra -l root -P passwords.txt x.x.x.x ssh
-	nmap X.X.X.X -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt
- ncrack -p 22 --user root -P passwords.txt x.x.x.x
- medusa -u root -P passwords.txt -h x.x.x.x -M ssh

### TELNET(23): 
Telnet can be used to grab the banner from any port with below command:
-	telnet X.X.X.X port
-	nmap -p 23 telnet-brute.nse,telnet-encryption.nse,telnet-ntlm-info.nse X.X.X.X
-	auxiliary/server/capture/telnet
-	use auxiliary/scanner/telnet/telnet_login
##### Bruteforce attack-
-	hydra -l root -P passwords.txt x.x.x.x telnet
- ncrack -p 23 --user root -P passwords.txt x.x.x.x
- medusa -u root -P 500-worst-passwords.txt -h x.x.x.x -M telnet
### SMTP (25): 
SMTP (Simple Mail Transfer Protocol) is a TCP/IP protocol used in sending and receiving e-mail. Since it is limited in its ability to queue messages at the receiving end, it is usually used with one of two other protocols, POP3 or IMAP, that let the user save messages in a server mailbox and download them periodically from the server.

##### SMTP for sending e-mail.
##### POP3 or IMAP for receiving e-mail.
Several methods exist that can be used to abuse SMTP to enumerate valid usernames and addresses.
Commands : VRFY, EXPN, EMAIL FROM and RCPT TO.
-	nc -nv X.X.X.X 25.
-	nmap -P25 --script smtp-enum-users.nse X.X.X.X.
-	auxiliary/scanner/smtp/smtp_enum.
-	SMTPTester (https://github.com/xFreed0m/SMTPTester).

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

### Web Enumeration (80/443):
- dirb http://x.x.x.x/
- nikto –h x.x.x.x
- curl -i ${IP}/robots.txt
- gobuster dir -u https://x.x.x.x/ -w ~/wordlists/shortlist.txt
- ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://x.x.x.x/FUZZ

### SNMP(161):
SNMP protocol used to monitor and Manage network Devices: to obtain information on and even configure various network devices remotely. It runs on any network device from hubs to routers and network printers to servers.SNMP is also used in most of the network management packages for information gathering.
https://www.manageengine.com/network-monitoring/what-is-snmp.html
-	nmap -Pn -p 161 x.x.x.x
-	nmap -Pn -sU - p 161 --script=snmp-brute X.X.X.X
-	nmap -Pn -sU - p 161--script=snmp-interfaces X.X.X.X
-	snmp-check -t X.X.X.X -c public
-	snmpwalk -c public -v1 X.X.X.X
-	snmpenum -t X.X.X.X
-	onesixtyone X.X.X.X public
##### SNMP metasploit-
-	auxiliary/scanner/snmp/snmp_enum
-	auxiliary/scanner/snmp/snmp_enumshares
-	auxiliary/scanner/snmp/snmp_enumusers
-	auxiliary/scanner/snmp/snmp_login

### SMB (139,445) :
Server Message Block (SMB) is network protocol for file sharing that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols and an application can access files or other resources at a remote server.
-	nmap -p 445 -A X.X.X.X
-	nmap --script smb-vuln* -p 445 X.X.X.X
-	nmap -Pn --script smb-security-mode X.X.X.X
-	smbclient - L X.X.X.X
-	smbmap -H X.X.X.X
-	enum4linux https://highon.coffee/blog/enum4linux-cheat-sheet/ 
-	hydra -L user.txt -P pass.txt X.X.X.X smb
-	auxiliary/scanner/smb/smb_enumusers
-	post/windows/gather/enum_shares

### HTTP/HTTPS(80/443):
HTTPS stands for Hypertext Transfer Protocol Secure is a protocol over which data is sent between your browser and the website that you are connected to.
-	nmap -p 80 -A X.X.X.X
-	nikto - h X.X.X.X
-	dirb https://X.X.X.X 

#### Audit SSL:
Self-signed certificate
SSL version 2 and 3 detection
Weak hashing algorithm
Use of RC4 and CBC ciphers
Logjam issue
Sweet32 issue
Lucky13
Certificate expiry
Openssl ChangeCipherSec issue
POODLE vulnerability
Openssl heartbleed issue
######
[TLS/SSL certificate vulnerabilities \| docs.digicert.com](https://docs.digicert.com/certificate-tools/discovery-user-guide/tlsssl-certificate-vulnerabilities/)
######
[TLS/SSL Vulnerabilities \| GracefulSecurity](https://gracefulsecurity.com/tls-ssl-vulnerabilities/)

######
https://trelis24.github.io/2018/01/11/OpenSSL_manual_check/
###### https://www.yeahhub.com/testing-ssl-vulnerabilities-testssl-python-script/
###### https://www.manageengine.com/key-manager/help/ssl-vulnerability.html#SSLCertificateRevocation
###### https://kb.iweb.com/hc/en-us/articles/230268628-SSL-TLS-issues-POODLE-BEAST-SWEET32-attacks-and-the-End-of-SSLv3-OpenSSL-Security-Advisory
###### https://gist.github.com/MrMugiwara/6bb7e3f64b5890a18317e7a7f34ddbe0#poodle-vulnerability

-	nmap -p 80,443 -A X.X.X.X
-	nikto - h X.X.X.X
-	dirb https://X.X.X.X 
-	nmap --script ssl-enum-ciphers -p 443 X.X.X.X
-	nmap -Pn -sV --script ssl-enum-ciphers X.X.X.X
-	nmap -Pn -p(port) --script ssl-cert X.X.X.X
-	nmap -Pn -sV --script ssl-poodle X.X.X.X
-	nmap -Pn -sV --script ssl-dh-params X.X.X.X
### Oracle (1521):
Oracle database is a relational database management system (RDBMS).
https://github.com/tacticthreat/Oracle-Pentesting-Reference
##### Odat - ODAT It is an open source penetration test tool designed to attack and audit the security of Oracle Database servers.
https://github.com/quentinhardy/odat
-	Tnscmd10g version -h X.X.X.X
-	Tnscmd10g status -h X.X.X.X
-	auxiliary/scanner/oracle/oracle_login             
-	auxiliary/scanner/oracle/sid_brute                                   
-	auxiliary/scanner/oracle/sid_enum              
-	auxiliary/scanner/oracle/tnslsnr_version

### MYSQL(3306):
MySQL is a freely available open source Relational Database Management System (RDBMS) that uses Structured Query Language (SQL).
-	mysql -u root -p
-	nmap --script=mysql-info X.X.X.X
-	nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 X.X.X.X
https://www.yeahhub.com/mysql-pentesting-metasploit-framework/
https://www.hackingarticles.in/mysql-penetration-testing-nmap/
https://hakin9.org/how-to-use-sqlploit/

### RDP(3389)
- nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 X.X.X.X
- nmap -sV --script=rdp-vuln-ms12-020 -p 3389 X.X.X.X
- auxiliary/scanner/rdp/ms12_020_check

### NFS file share(111|2049):
-	Showmount -e X.X.X.X
-	mount -t nfs <ip>:<remote_folder> <local_folder> -o nolock
https://pentestacademy.wordpress.com/2017/09/20/nfs/

### NTP (123):

Network Time Protocol (NTP) is an application layer protocol used for clock synchronization between hosts on a TCP/IP network. The goal of NTP is to ensure that all computers on a network agree on the time, since even a small difference can create problems. For example, if there is more than 5 minutes difference on your host and the Active Directory domain controller, you will not be able to login into your AD domain.

### Postgresql (5432):
PostgreSQL is a powerful, Open-Source Object Relational Database Management System. It is used to store data securely as it comes with features like Client Authentication Control, Server Configuration, User and Role Management, Data Encryption etc.
-	Login: postgres:postgres
-	nmap -sV X.X.X.X -p 5432
-	auxiliary/scanner/postgres/postgres_login
https://medium.com/@netscylla/pentesters-guide-to-postgresql-hacking-59895f4f007

### rexec(512),rlogin(513),rshell(514)

Rexec or Remote execution service is a service which allows users to execute non-interactive commands on another remote system. This remote system should be running a remote exec daemon or server (rexecd).By default, this service requires a valid user name and password for the target system.
Rlogin or Remote Login service is a remote access service which allows an authorized user to login to UNIX machines (hosts). This service allows the logged user to operate the remote machine as if he is logged into the physical machine. This service is similar to other remote services like telnet and SSH.
Rsh or Remote shell is a remote access service that allows users a shell on the target system. Authentication is not required for this service. By default it runs on port 514.

Although Rsh doesn’t require a password, it requires the username belonging to the remote system.In case we don’t have the credentials, we have to crack them.

### Other Resources:
http://whitehatsindia.blogspot.com/2017/10/network-security-vapt.html
https://medium.com/oscp-cheatsheet/oscp-cheatsheet-6c80b9fa8d7e
https://security-prince.github.io/PWK-OSCP-Preparation-Roadmap/
https://kuwano.gitbook.io/infosec-notes/pentest-redteam-technical-guide/untitled/nfs-2049-tcp-udp
