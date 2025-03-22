### dog.htb
#### https://app.hackthebox.com/machines/651
---
```
Hexada@hexada ~/docker_volume/web-security$ sudo nmap -sS -sC -sV -p- -T5 --max-rate 10000 -oN dog.txt 10.10.11.58                                                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-21 22:26 EET
Nmap scan report for dog.htb (10.10.11.58)
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-title: Home | Dog
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 355.62 seconds
```

```
Hexada@hexada ~/docker_volume/web-security$ curl http://10.10.11.58/robots.txt                                                                                                             
#
# robots.txt
#
# This file is to prevent the crawling and indexing of certain parts
# of your site by web crawlers and spiders run by sites like Yahoo!
# and Google. By telling these "robots" where not to go on your site,
# you save bandwidth and server resources.
#
# This file will be ignored unless it is at the root of your host:
# Used:    http://example.com/robots.txt
# Ignored: http://example.com/site/robots.txt
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/robotstxt.html
#
# For syntax checking, see:
# http://www.robotstxt.org/checker.html

User-agent: *
Crawl-delay: 10
# Directories
Disallow: /core/
Disallow: /profiles/
# Files
Disallow: /README.md
Disallow: /web.config
# Paths (clean URLs)
Disallow: /admin
Disallow: /comment/reply
Disallow: /filter/tips
Disallow: /node/add
Disallow: /search
Disallow: /user/register
Disallow: /user/password
Disallow: /user/login
Disallow: /user/logout
# Paths (no clean URLs)
Disallow: /?q=admin
Disallow: /?q=comment/reply
Disallow: /?q=filter/tips
Disallow: /?q=node/add
Disallow: /?q=search
Disallow: /?q=user/password
Disallow: /?q=user/register
Disallow: /?q=user/login
Disallow: /?q=user/logout
```

```
root@docker-desktop:~/home/local/dog# gobuster dir -u http://10.10.11.58/.git -w ~/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.58/.git
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /root/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2025/03/22 14:11:15 Starting gobuster in directory enumeration mode
===============================================================
/info                 (Status: 301) [Size: 314] [--> http://10.10.11.58/.git/info/]
/index                (Status: 200) [Size: 344667]                                 
/config               (Status: 200) [Size: 92]                                     
/logs                 (Status: 301) [Size: 314] [--> http://10.10.11.58/.git/logs/]
/objects              (Status: 301) [Size: 317] [--> http://10.10.11.58/.git/objects/]
/description          (Status: 200) [Size: 73]                                        
/branches             (Status: 301) [Size: 318] [--> http://10.10.11.58/.git/branches/]
/refs                 (Status: 301) [Size: 314] [--> http://10.10.11.58/.git/refs/]    
/HEAD                 (Status: 200) [Size: 23]                                         
                                                                                       
===============================================================
2025/03/22 14:15:28 Finished
===============================================================
root@docker-desktop:~/home/local/dog#  
```

![image](https://github.com/user-attachments/assets/daa82b0f-d8c8-4c5f-87e2-0926231beacf)
![image](https://github.com/user-attachments/assets/2d45c238-0d92-4a73-85ae-c8e1298ba2aa)

```
wget -r --no-parent http://dog.htb/.git/
```

```
root@docker-desktop:~/home/local/dog/dog.htb/.git# git log --oneline --graph --all
* 8204779 (HEAD -> master) todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases
root@docker-desktop:~/home/local/dog/dog.htb/.git# git show --name-only 8204779c764abd4c9d8d95038b6d22b6a7515afa
commit 8204779c764abd4c9d8d95038b6d22b6a7515afa (HEAD -> master)
Author: root <dog@dog.htb>
Date:   Fri Feb 7 21:22:11 2025 +0000

    todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases

LICENSE.txt
README.md
core/.jshintignore
core/.jshintrc
core/authorize.php
core/cron.php
core/includes/actions.inc
core/includes/ajax.inc
core/includes/anonymous.inc
core/includes/archiver.inc
core/includes/authorize.inc
core/includes/batch.inc
core/includes/batch.queue.inc
core/includes/bootstrap.classes.inc
core/includes/bootstrap.inc
core/includes/cache-install.inc
core/includes/cache.inc
core/includes/color.inc
core/includes/common.inc
core/includes/config.inc
core/includes/database/charset_converter.inc
core/includes/database/database.inc
core/includes/database/log.inc
core/includes/database/mysql/database.inc
core/includes/database/mysql/install.inc
core/includes/database/mysql/query.inc
core/includes/database/mysql/schema.inc
core/includes/database/prefetch.inc
core/includes/database/query.inc
core/includes/database/schema.inc
core/includes/database/select.inc
core/includes/date.class.inc
core/includes/date.inc
core/includes/diff.inc
core/includes/drupal.classes.inc
core/includes/drupal.inc
core/includes/errors.inc
core/includes/evalmath.inc
core/includes/file.inc
core/includes/file.mimetypes.inc
--More--
```

```
root@docker-desktop:~/home/local/dog/dog.htb/.git# git show 8204779c764abd4c9d8d95038b6d22b6a7515afa:core/scripts/password-hash.sh      
#!/usr/bin/env php
<?php

/**
 * Backdrop hash script - to generate a hash from a plaintext password
 *
 * Check for your PHP interpreter - on Windows you'll probably have to
 * replace line 1 with
 *   #!c:/program files/php/php.exe
 *
 * @param password1 [password2 [password3 ...]]
 *  Plain-text passwords in quotes (or with spaces backslash escaped).
 */

if (version_compare(PHP_VERSION, "5.2.0", "<")) {
  $version  = PHP_VERSION;
  echo <<<EOF

ERROR: This script requires at least PHP version 5.2.0. You invoked it with
       PHP version {$version}.
\n
EOF;
  exit;
}

$script = basename(array_shift($_SERVER['argv']));

if (in_array('--help', $_SERVER['argv']) || empty($_SERVER['argv'])) {
  echo <<<EOF

Generate Backdrop password hashes from the shell.

Usage:        {$script} [OPTIONS] "<plan-text password>"
Example:      {$script} "mynewpassword"

All arguments are long options.

  --help      Print this page.

  --root <path>

              Set the working directory for the script to the specified path.
              To execute this script this has to be the root directory of your
              Backdrop installation, e.g. /home/www/foo/backdrop (assuming
              Backdrop is running on Unix). Use surrounding quotation marks on
              Windows.
```


