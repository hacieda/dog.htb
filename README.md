### dog.htb
#### https://app.hackthebox.com/machines/651
---

Walkthrough: Dog HTB

As always, we start by scanning the machine with **Nmap**
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

We can see that the web server is managed via the **SSH protocol**, but I’m more interested in the `.git` directory. This directory contains the latest version of the back-end code that runs via **Apache**. If we find the hash of the last commit, we can use this unique hash to access the code version for analysis

I’m also interested in the robots.txt file because it might contain useful information. Let's check it out

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

The `robots.txt` file is used to manage access for search engines and other automated bots (called "spiders") that crawl websites. In this file, rules are defined that tell these bots which pages or directories they should not index or visit. This helps prevent unnecessary parts of the website from being indexed by search engines, which can save server resources or protect sensitive data from being indexed

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
Here’s the hash I was talking about earlier

Let's get access to the commit

```
wget -r --no-parent http://dog.htb/.git/
```

I recommend using dirsearch to download the `.git`; it's more comfortable

I found out about this tool later, after I had solved all the flags

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

We have successfully gained access to a commit, which represents a specific version of the web server. Now, our task is to analyze the files from this commit to find any useful information that may help us in the next steps

**CMS (Content Management System)** - It’s a program or web application that gives you the opportunity to create, edit, and manage website content without the need to write code manually

With a **CMS**, you can manage a website with a blog. For example, you can create, edit, and organize articles, upload images, and much more

Among the popular **CMS** options are **Backdrop**, **Backdrop**, **Joomla**, **Drupal** and many others

```
git show --name-only 8204779c764abd4c9d8d95038b6d22b6a7515afa:core/includes/bootstrap.inc

/**
 * The current system version.
 */
define('BACKDROP_VERSION', '1.27.1');
```

By analyzing the `bootstrap.inc` file inside the commit, we discovered that the installed **Backdrop** version is **1.27.1**

This particular version is known to be vulnerable to malicious code injection through the CMS itself, which allows us to execute arbitrary code or gain unauthorized access to the system, but for that, we need an account that has permissions to upload content to the website

```
git show --name-only 8204779c764abd4c9d8d95038b6d22b6a7515afa:settings.php

<?php
/
 * @file
 * Main Backdrop CMS configuration file.
 */

/
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```

```
git show --name-only 8204779c764abd4c9d8d95038b6d22b6a7515afa:files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json

{
    "_config_name": "update.settings",
    "_config_static": true,
    "update_cron": 1,
    "update_disabled_extensions": 0,
    "update_interval_days": 0,
    "update_url": "",
    "update_not_implemented_url": "https://github.com/backdrop-ops/backdropcms.org/issues/22",
    "update_max_attempts": 2,
    "update_timeout": 30,
    "update_emails": [
        "tiffany@dog.htb"
    ],
    "update_threshold": "all",
    "update_requirement_type": 0,
    "update_status": [],
    "update_projects": []
}
```

If we use this username and password, we can gain access to this account, which is suitable for our aim

![image](https://github.com/user-attachments/assets/c6d2fadf-5a33-4dd0-a77c-b22b8b65d3fd)
![image](https://github.com/user-attachments/assets/42832650-8cf6-4dd2-8782-d146c92bab1b)
![image](https://github.com/user-attachments/assets/94366bfa-6628-4daf-a2f7-17c91e2c0ef2)
![image](https://github.com/user-attachments/assets/93463e01-37c8-4b8c-9092-4fb14684ef59)




