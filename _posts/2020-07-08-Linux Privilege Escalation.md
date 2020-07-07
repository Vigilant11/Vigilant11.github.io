






### Automated  Tools
#### 1.	 LinEnum
https://github.com/rebootuser/LinEnum
#### 2.	linprivchecker.py 
https://github.com/reider-roque/linpostexp/blob/master/linprivchecker.py
#### 3.	Unix-privesc-check
http://pentestmonkey.net/tools/audit/unix-privesc-check
#### 4.	Gtfobins
https://gtfobins.github.io/



Finding installed software, running processes, bind ports, and OS version
##### OS and Kernel information (Kernel exploits)
- cat /etc/issue
- cat /proc/version
- uname -a
- lsb_release –a


##### Abusing sudo-rights
- Sudo -l
- cat /etc/sudoers

##### SUID & GUID  Misconfiguration
- find / -perm -1000 -type d 2>/dev/null
- find / -perm -g=s -type f 2>/dev/null
- find / -perm -u=s -type f 2>/dev/null 
- find / -perm -g=s -o -perm -u=s -type f 2>/dev/null 

##### Services and Programs running as root
- ps aux
- top
- cat /etc/services
##### #mysql running as root
- sys_exec('usermod -a -G admin username')
- https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/


##### Installed softwares and Applications
- ls -alh /usr/bin/
- ls -alh /sbin/
- dpkg -l
- rpm -qa
- ls -alh /var/cache/apt/archivesO
- ls -alh /var/cache/yum/


##### Misconfigured Path Variables
- cat /etc/profile
- cat /etc/bashrc
- cat ~/.bash_profile
- cat ~/.bashrc
- cat ~/.bash_logout
- env
- set

##### Misconfigured Services and Plugins
- cat /etc/syslog.conf
- cat /etc/inetd.conf
- cat /etc/apache2/apache2.conf
- cat /etc/httpd/conf/httpd.conf
- cat /opt/lampp/etc/httpd.conf

##### Scheduled Jobs
- crontab -l
- ls -al /etc/cron*
- cat /etc/cron*

##### Weak/reused/plaintext passwords
- cat /etc/passwd
- cat /etc/shadow
- /var/spool/mail
- cat ~/.*_history
- grep -ir user *
- grep -ir pass *

##### Writable configuration files
- find /etc/ -writable -type f 2>/dev/null

##### Private key search
- cat ~/.ssh/authorized_keys
- cat ~/.ssh/identity.pub
- cat ~/.ssh/identity
- cat ~/.ssh/id_rsa.pub
- cat ~/.ssh/id_rsa
- cat /etc/ssh/ssh_config
- cat /etc/ssh/ssh_host_key

##### Unmounted filesystems
- mount -l
- cat /etc/fstab
##### #NFS Share
- showmount -e ip
- mount ip:/ /tmp/

##### LXD 

https://www.hackingarticles.in/lxd-privilege-escalation/
	
##### Docker

https://www.hackingarticles.in/docker-privilege-escalation/

##### Bad path configuration

https://hackmag.com/security/reach-the-root/

##### Limited Shells
- python -c 'import pty; pty.spawn("/bin/sh")'
- echo os.system('/bin/bash')
- /bin/sh -i
