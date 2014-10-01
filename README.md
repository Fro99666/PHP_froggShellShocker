froggShellShocker
=================

Test Shell Shock Exploit on a linux server using php

i will add more description later

this script test the 4 exploit of Shell Shock on a Linux server with php 5+

all the configuration is actually in the main code in configuration part,
you can set:
- server server ip (+cgi page if needed)
- folder where exploit will write (or none but can be the mess, for better test need to add rights)
- and some more options (like the exploit file name and ext to be easily retrieved)

The code will try to write file in /tmp/exploit/ (default folder who need to be created) using the Shell Shock Exploit.
If the script create thoose file, that mean your server is Vulnerable to the exploit...

all is describe in detail in the source code...

if you got any question feel free to seend me message/mail
