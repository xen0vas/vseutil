

#######################################################

message = """
 _    _______ ______      __  _ __
| |  / / ___// ____/_  __/ /_(_) /
| | / /\__ \/ __/ / / / / __/ / /
| |/ /___/ / /___/ /_/ / /_/ / /
|___//____/_____/\__,_/\__/_/_/

VSEutil - a tool used to upgrade or downgrade signature dats on McAfee VSE 
""".format(__version__)


#######################################################

from _winreg import *
import optparse
import os
import threading
import zipfile
import sys
import platform as winos
import wmi
from netaddr import *
from colorama import *
import shutil
import win32wnet
import socket
import time
from types import *
import win32api
import win32con
import win32service
import win32serviceutil
from datetime import date, timedelta, datetime
import win32event

RUNNING = win32service.SERVICE_RUNNING
STARTING = win32service.SERVICE_START_PENDING
STOPPING = win32service.SERVICE_STOP_PENDING
STOPPED = win32service.SERVICE_STOPPED

init()

def main():
	
	print message
	parser = optparse.OptionParser('\n\nAuthor: Xenofon Vassilakopoulos (@xvass) \n\n\
	[-] Usage: \n\n\
		vseutil.exe  [options] \n\n\
	[!] Use vseutil.exe --hlp to see options and registry values to use\n\n')	
	
	parser.add_option('-r', dest = 'regname', type ='string',help = 'registry key')
	parser.add_option('--out', dest = 'output_file', type='string', help = 'output to file')
	parser.add_option('-u', dest = 'uname', type='string',help='user name with domain or workgroup')
	parser.add_option('-p', dest = 'upassword', type='string', help='user password')
	parser.add_option('-s', dest = 'fromhost', type='string',help = 'target machine')
	parser.add_option('-t', dest = 'tohost', type='string',help = 'target machine')
	parser.add_option('-c', dest = 'tocidrhost', type='string',help = 'cidr')
	parser.add_option('--sf', dest = 'sourcefile', type='string',help = 'sourcedir/sourcefile')
	parser.add_option('--df', dest = 'destinationfile', type='string',help = 'destdir/destfile')
	parser.add_option('--hlp', action='store_const', dest = 'hlp', const='help')
	parser.add_option('-l','--local', dest = 'localhost',action='store_const', const='local')
	parser.add_option('-d', "--down", action='store_const', const='down', dest='down')
		
	(options,args) = parser.parse_args()
	
	value = options.regname
	from_host = options.fromhost
	to_host = options.tohost
	tgtuser = options.uname
	tgtpass = options.upassword
	cidr_hosts = options.tocidrhost
	sourcefile = options.sourcefile
	destfile = options.destinationfile
	outfile = options.output_file
	hlp = options.hlp
	local = options.localhost
	down = options.down
	
	if hlp=="help":
		helpinfo()
		sys.exit()
	
	if (value == None and tgtuser == None and tgtpass == None and from_host == None and to_host == None):
		if (tgtuser == None or tgtpass == None or cidr_hosts == None or outfile == None):
			print parser.usage
			sys.exit()
	
	connectwmi(from_host,to_host,tgtuser,tgtpass,value,cidr_hosts,sourcefile,destfile,outfile,down)
		
def log_to_file(message,outfile): 
	fd=open(outfile,"ab" )
	fd.write("%s\r\n" % message)
	fd.close()
	return

def helpinfo():
	print '\n\n\
	[-] Usage: \n\n\
		vseutil.exe  [options] \n\n\
	[-] Options:\n\n\
		-c 		:- use this option to specify IP address as well as range of addresses using cidr\n\
		--sf 		:- use this option to specify the source file that will be copied to target machine\n\
		--df 		:- use this option to specify the destination that the file will be copied\n\
		-r 		:- use this option to specify the registry value you want to review\n\
		-u 		:- use this option to specify username\n\
		-p 		:- use this option to specify password\n\
		-s 		:- use this option to specify the first IP address to check\n\
		-t 		:- use this option to specify the last IP address to check\n\
		--out 		:- use this option to save the output into a log file --> e.g. "--out vse.log" or vse.csv\n\
		-d	 	:- use this option if you want to downgrade the DAT version\n\n\
	[-] Registry Values:\n\n\
		- DATVersion\n\
		- Version\n\
		- DatInstallDate\n\
		- HotFixVersions\n\
		- Uninstall Command\n\
		- EngineVersion\n\
		- DatDate\n\
		- EngineInstallDate\n\
		- Install Path\n\
		- Installs CMA\n\
		- Plugin Flag\n\
		- Plugin Path\n\
		- Software ID\n\
		- McTrayAboutBoxDisplay\n\
		- Enforce Flag\n\
		- CLSID\n\
		- Language\n\
		- Product Name\n'
		
def svcStatus( svc_name, machine=None):
		return win32serviceutil.QueryServiceStatus( svc_name, machine)[1]

def svcStop( svc_name, machine=None):
		status = win32serviceutil.StopServiceWithDeps( svc_name, machine,30)
		while status == STOPPING:
			time.sleep(1)
			status = svcStatus( svc_name, machine)
		return status

def svcStart(svc_name,svc_arg, machine=None):
		status = win32serviceutil.StartService(svc_name,None, machine)
		status = svcStatus( svc_name, machine)
		while status == STARTING:
			time.sleep(3)
			status = svcStatus( svc_name, machine)
		return status

def wnet_connect(host, username, password):
	unc = ''.join(['\\\\', str(host)])
	try:
		win32wnet.WNetAddConnection2(0, None, unc, None, username, password)
	except Exception, err:
		if isinstance(err, win32wnet.error):
			# Disconnect previous connections if detected, and reconnect.
			if err[0] == 1219:
				win32wnet.WNetCancelConnection2(unc, 0, 0)
				return wnet_connect(host, username, password)
			raise err
		
def lendian(daterelseq,datetimeinstseq):
	if daterelseq != None and datetimeinstseq == None:
		resid=1
		sequence="0x" + str(daterelseq) + "0x"
		sep="-"
	elif daterelseq == None and datetimeinstseq != None:
		resid=2
		sequence="0x" + str(datetimeinstseq) + "0x"
		sep="-"
	try:
		T,S = sequence.split('x')
	except:
		S=sequence
	count=0
	t=list();
	for _ in S:
		count=count+2
		I=S[:count:]
		Seq=I[::-count]
		t.append(Seq)
	count=1
	e=list();
	
	for _ in S:
		G=S[:count:]
		SG=G[::-count]
		count=count+2
		e.append(SG)
	
	no = len(S)/2
	TT = t[0:no]
	EE = e[0:no]			
	ftime = [ x+y for x,y in zip(EE,TT)]
	f = ftime[::-1]
	seperator = sep.join(f)			
	sepdate = ''.join(('"',sep,seperator,'"'))
	fdatetime = sepdate.split("-")
	devdate=len(fdatetime)/2
	if resid==1:
		day = fdatetime[2]
		month = fdatetime[3]
		year = fdatetime[devdate:][2] + fdatetime[devdate:][1]
		curdate =  year + "-" + month + "-" + day
		curd = datetime.strptime(curdate, '%Y-%m-%d').date()
		return curd
	else:
		return fdatetime[4] + fdatetime[3] + fdatetime[2]
		
	

#installation DAT date. This must be the same time the DAT is scheduled to be installed every day 
def installDatDate(dateseq,datetimeseq):
	datetime = lendian(None, datetimeseq)
	date = dateseq + datetime
	return date

# DAT release date. McAfee releases the DATs one day before
def DatReleaseDate(datver,current_value,date_release):
	current=str(current_value).split(".")[0]
	ver = int(current)-int(datver) 
	date_r = lendian(date_release,None)
	d = date_r - timedelta(days=ver)
	return str(d).replace("-","")

def copy_file(DAT2val,ip,user,password,sourcefile,destfile,outfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	wnet_connect(ip, user, password)
	try:
		shutil.copy2(sourcefile,'\\\\' + str(ip) + '\\' + str(destfile) + '\\')
		print Fore.WHITE +"[*] DAT "+ "latest version " + Fore.YELLOW + "%s.0000 " % DAT2val + Fore.WHITE + " uploded..."
		if (outfile != None):
			log_to_file("[*] DAT "+ "latest version %s.0000 " % DAT2val + " uploded...",outfile)
		print Fore.WHITE + '[*] file ' + Fore.YELLOW + sourcefile + Fore.WHITE + ' copied to C:\Program Files\Common Files\McAfee\%s' % destfile
		if (outfile != None):
			log_to_file('[*] file' + sourcefile + ' copied to C:\Program Files\Common Files\McAfee\%s' % destfile,outfile)
	except IOError, e:
		if e.errno == 22:   				
			print Fore.WHITE + '[x] file did not copied to C:\Program Files\Common Files\McAfee\%s.' % destfile
			if (outfile != None):
				log_to_file('[x] file did not copied to C:\Program Files\Common Files\McAfee\%s.' % destfile,outfile)
	finally:
		semaphore.release()	
		return
	semaphore.release()	
	return
	
def unzip(DAT,ip,destfile,outfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	zipp = zipfile.ZipFile('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + DAT)
	zipp.extractall('\\\\' + str(ip) + '\\' + str(destfile) + '\\')
	print Fore.WHITE + "[*] files have been extracted to C:\Program Files\Common Files\McAfee\%s" % destfile
	if (outfile != None):
		log_to_file("[*] files have been extracted to C:\Program Files\Common Files\McAfee\%s" % destfile,outfile)
	print Fore.WHITE + "[*] new DAT has been installed.."
	if (outfile != None):
		log_to_file("[*] new DAT has been installed..",outfile)
	semaphore.release()	
	
def deletefiles(ip,destfile,DAT,outfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	os.remove('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + DAT)
	os.remove('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + "legal.txt")
	print Fore.WHITE + "[*] cleaning unwanted files at C:\Program Files\Common Files\McAfee\%s" % destfile
	if (outfile != None):
		log_to_file("[*] cleaning unwanted files at C:\Program Files\Common Files\McAfee\%s" % destfile,outfile)
	semaphore.release()	

def wmiconnect(ip,username,upass,outfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	try:	
		c = wmi.WMI(computer=ip, user=username, password=upass, namespace="root/default").StdRegProv
		print "[*] Connected to host with IP: %s" % ip
		if (outfile != None):
			log_to_file("[*] Connected to host with IP: %s" % ip,outfile)
	except:
		c="not_connected"
		pass
	semaphore.release()
	return c

def registry_values(username,upass,value,sourcefile,destfile,c,outfile):

	if (value == 'DATVersion' and sourcefile != None and destfile != None and username != None and upass != None):
	
		n,arch = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
		if(arch == 'x86'):	
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
		else:
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
		DAT2val,valnum,DAT = string_convert(val,sourcefile)
		
	elif(value != None and sourcefile == None and destfile == None and username != None and upass != None):
		DAT2val = None
		valnum = None
		DAT = None
		n,arch = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
		if(arch == 'x86'):	
			res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
		else:
			res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
		
		print  "[*] The %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
		if (outfile != None):
			log_to_file('[*] The %s " % (value) + "is %s \n\n" % (val)',outfile)
	else:
		DAT2val = None
		valnum = None
		DAT = None
		val = None
		arch = None
		print '[!] check registry values, source and destination'
		if (outfile != None):
			log_to_file('[!] check registry values, source and destination',outfile)			
	return (val,arch,DAT2val,valnum,DAT)

# This function converts and modifies strings carrying DAT lexical format 
def string_convert(val,sourcefile):
	splitval = val 
	valsplit = splitval.split('.')
	sourcefilesplit = sourcefile.split('\\')
	DAT = sourcefilesplit[-1]
	DATval = DAT.split('.')
	valDAT = ''.join(DATval[0])
	val2DAT = valDAT.split('-')
	DAT2val = int(val2DAT[1])
	valnum = int(valsplit[0])
	return (DAT2val,valnum,DAT)

def checkServices(ip):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	status1 = svcStatus( "McShield", unicode(ip))
	status2 = svcStatus( "McAfeeFramework", unicode(ip))
	if status1 == STOPPED and status2 != STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"	
		svcStart( "McShield",arg, unicode(ip))
	elif status1 != STOPPED and status2 == STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"
		svcStart( "McAfeeFramework",arg, unicode(ip))
	elif status1 == STOPPED and status2 == STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"
		svcStart( "McAfeeFramework",arg, unicode(ip))
		svcStart( "McShield",arg, unicode(ip))
	semaphore.release()	
	
# This function updates DAT files inside the C:\Program Files\Common Files\McAfee\Engine file. It requires McShield and McAfeeFramework to stop. 
# After the files has been copied,start services again.
def update_vse(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	status1 = svcStatus( "McShield", unicode(ip))
	status2 = svcStatus( "McAfeeFramework", unicode(ip))
	state_value = "not_passed"					
	if status1 != STOPPED and status2 != STOPPED:
		svcStop( "McShield", unicode(ip))
		svcStop( "McAfeeFramework", unicode(ip))
		print Fore.WHITE +"[*] Found installed DAT version " + Fore.YELLOW + "%s.0000" % valnum 
		if (outfile != None):
			log_to_file("[*] Found installed DAT version %s.0000" % valnum,outfile)	
		copy_file(DAT2val,ip,username,upass,sourcefile,destfile,outfile)
		unzip(DAT,ip,destfile,outfile)
		deletefiles(ip,destfile,DAT,outfile)
		arg="win32service.SERVICE_ALL_ACCESS"
		svcStart( "McShield",arg, unicode(ip))
		svcStart( "McAfeeFramework",arg, unicode(ip))
		state_value="passed"
	
	elif status1 == STOPPED and status2 != STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"
		print Fore.WHITE +"[*] Found installed DAT version " + Fore.YELLOW + "%s.0000" % valnum 
		if (outfile != None):
			log_to_file("[*] Found installed DAT version %s.0000" % valnum,outfile)
		copy_file(DAT2val,ip,username,upass,sourcefile,destfile,outfile)
		unzip(DAT,ip,destfile,outfile)
		deletefiles(ip,destfile,DAT,outfile)		
		svcStart( "McShield",arg, unicode(ip))
		state_value="passed"
							
	elif status1 != STOPPED and status2 == STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"
		svcStop( "McShield", unicode(ip))
		print Fore.WHITE +"[*] Found installed DAT version " + Fore.YELLOW + "%s.0000" % valnum 
		if (outfile != None):
			log_to_file("[*] Found installed DAT version %s.0000" % valnum,outfile)
		copy_file(DAT2val,ip,username,upass,sourcefile,destfile,outfile)
		unzip(DAT,ip,destfile,outfile)
		deletefiles(ip,destfile,DAT,outfile)
		svcStart( "McShield",arg, unicode(ip))
		svcStart( "McAfeeFramework",arg, unicode(ip))
		state_value="passed"
		
	elif status1 == STOPPED and status2 == STOPPED:
		arg="win32service.SERVICE_ALL_ACCESS"
		print Fore.WHITE +"[*] Found installed DAT version " + Fore.YELLOW + "%s.0000" % valnum 
		if (outfile != None):
			log_to_file("[*] Found installed DAT version %s.0000" % valnum,outfile)
		copy_file(DAT2val,ip,username,upass,sourcefile,destfile,outfile)
		unzip(DAT,ip,destfile,outfile)
		deletefiles(ip,destfile,DAT,outfile)		
		svcStart( "McShield",arg, unicode(ip))	
		svcStart( "McAfeeFramework",arg, unicode(ip))
		state_value="passed"	
	status1 = svcStatus( "McShield", unicode(ip))
	status2 = svcStatus( "McAfeeFramework", unicode(ip))
	semaphore.release()	
	return (status1,status2,state_value)

#This function updates registry values only when Engine folder has been updated 
def update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val,current_val):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	if status1 != STOPPED and status2 != STOPPED and state_value == "passed":									
		if(arch == 'x86'):
			print "[*] updating registry.."
			if (outfile != None):
				log_to_file("[*] updating registry..",outfile)
			datRelease,date_release = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName="DatDate")
			datInst,date_install = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName="DatInstallDate")
			DATrelease = DatReleaseDate(DAT2val,current_val,date_release)
			DATinstall = installDatDate(DATrelease,date_install)
			result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
			dateres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatDate',sValue=DATrelease)
			dateinstalledres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatInstallDate',sValue=DATinstall)
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
			print "[*] registry updated successfully"
			if (outfile != None):
				log_to_file("[*] registry updated successfully",outfile)
		else:
			print "[*] updating registry.."
			if (outfile != None):
				log_to_file("[*] updating registry..",outfile)
			datRelease,date_release = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName="DatDate")
			datInst,date_install = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName="DatInstallDate")
			DATrelease = DatReleaseDate(DAT2val,current_val,date_release)
			DATinstall = installDatDate(DATrelease,date_install)
			result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
			dateres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatDate',sValue=DATrelease)
			dateinstalledres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatInstallDate',sValue=DATinstall)
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
			print "[*] registry updated successfully"
			if (outfile != None):
				log_to_file("[*] registry updated successfully",outfile)
		print  Fore.WHITE + "[*] new current %s is" % (value) + Fore.YELLOW + " %s " % (val)
		print Fore.WHITE + "[*] Exiting...\n"
		if (outfile != None):
			log_to_file("[*] new current %s " % (value) + "is %s \n\n" % (val),outfile)
	elif state_value == "not_passed":
		print "[x] Registry cannot be updated. Please try again..\n"
		if (outfile != None):
			log_to_file("[x] Registry cannot be updated. Please try again..\n",outfile)
	semaphore.release()
	return

def changeDATversion(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile,arch,c,value,val,level):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	try:
		if DAT2val != valnum and level=="down":
			status1,status2,state_value = update_vse(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile)
			update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val,val)
		elif DAT2val != valnum and level == None and DAT2val > valnum:
			status1,status2,state_value = update_vse(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile)
			update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val,val)
		elif DAT2val == valnum or (DAT2val < valnum and level==None):
			print Fore.WHITE + "[*] current %s " % (value) + "is " + Fore.YELLOW +  "%s " % (val)
			if (DAT2val < valnum):
				print Fore.WHITE + "[!] You are trying to install a lower DAT version..Use option '-d' to downgrade DAT version.."
			print Fore.WHITE + "[*] Exiting..."
			if (outfile != None):
				log_to_file("[*] current %s " % (value) + "is %s" % (val),outfile)
				log_to_file("[*] Exiting...",outfile)
	except:
		print Fore.RED + "[!] Check if DAT version you are trying to install exists.."
		print Fore.WHITE + "[*] Exiting..."
		if (outfile != None):
			log_to_file("[!] Check if DAT version you are trying to install exists..",outfile)
			log_to_file("[*] Exiting...",outfile)
		checkServices(ip)
	semaphore.release()
	return

def connectwmi(fromh,toh,username,upass,value,cidr_hosts,sourcefile,destfile,outfile,level):				
	if (cidr_hosts != None):
		iprange = IPNetwork(cidr_hosts)
	else:
		iprange = IPRange(fromh, toh)
	for ip in iprange:
		print Fore.WHITE + "\n" + "[-] IP: %s" % ip + "\n"
		if (outfile != None):
			log_to_file("--------------------------------------------------",outfile)
			log_to_file("\n" + "[-] IP: %s" % ip + "\n",outfile)
			log_to_file("--------------------------------------------------\n",outfile)
		try:					
			c = wmiconnect(ip,username,upass,outfile)
			if (c != "not_connected"):
				val,arch,DAT2val,valnum,DAT = registry_values(username,upass,value,sourcefile,destfile,c,outfile)
				if (sourcefile != None or destfile != None):				
					try:						
						changeDATversion(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile,arch,c,value,val,level)										
					except:
						print Fore.RED + "[*] Cannot access services..check permissions"
						print Fore.WHITE + "[*] Exiting..."
						checkServices(ip)
						continue
			else:
				print "[x] Not connected to host with IP address %s" % ip + " Probably the host is down or user is logged off"
				if (outfile != None):
					log_to_file("[x] Not connected to IP address %s" % ip + " Probably the host is down or user is logged off",outfile)
		except win32service.error, (msg):
			print "[x] Error starting service: %s" % msg
			if (outfile != None):
				log_to_file("[x] Error starting service: %s" % msg,outfile)
			continue
				
if __name__ == '__main__':
		main()

		
		
