# Vulnerable Server
**Vulnerable Server** - Its a server specially made for static analyzers testing. You can type there a comment, search for other users. 
Especially for SQL-injections and XSS vulnerabilities. So it has no practical use, but testing SAST.

> [!NOTE]
> **SQL injection (SQLi)** is a cyberattack where malicious SQL commands are inserted into input fields on a website or application.
> 
>  **Cross-Site Scripting (XSS)** is a cybersecurity vulnerability where an attacker injects malicious JavaScript into a legitimate website.

## how to use
Just upload it, then make directory *build* then type *cmake .. && make*
```
git clone https://github.com/Mager2112/Vulnerable_server.git && cd Vulnerable_server
mkdir build && cd build 
cmake ..
make
```
To start this app, type:
```
./vulnerable_server
```
