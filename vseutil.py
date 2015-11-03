
#################################################
# Author: Xenofon Vassilakopoulos		#
# This tool has being developed in order 	#
# to help security engineers to automate VSE DAT#
# updates to endpoints without using ePO	#
#################################################
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
from datetime import date
import win32event

RUNNING = win32service.SERVICE_RUNNING
STARTING = win32service.SERVICE_START_PENDING
STOPPING = win32service.SERVICE_STOP_PENDING
STOPPED = win32service.SERVICE_STOPPED

init()

def main():
	
	parser = optparse.OptionParser('\n\nAuthor: Xenofon Vassilakopoulos (@xvass) \n\n\
	[-] Usage: \n\n 1) vse88x.exe  -s <from_target> -t <to_target> -u <domain\username> -p <password> -r "<value>"\n\n \
	2) vse88x.exe -c target_ip -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>" \n\n \
	3) vse88x.exe -s <from_target> -t <to_target> -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>"\n\n \
	4) vse88x.exe -c <ip/cidr> -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>" \n\n \
	5) vse88x.exe -c <ip/cidr> -u <domain\username> -p <password> -r "<value>"\n\n \
	6) vse88x.exe -c <ip> -u <domain\username> -p <password> -r <"value">\n\n- \
	Registry Values:\n\n- \
	DATVersion\n- \
	Version\n- \
	DatInstallDate\n- \
	HotFixVersions\n- \
	Uninstall Command\n- \
	EngineVersion\n- \
	DatDate\n- \
	EngineInstallDate\n- \
	Install Path\n- \
	Installs CMA\n- \
	Plugin Flag\n- \
	Plugin Path\n- \
	Software \
	ID\n- \
	McTrayAboutBoxDisplay\n- \
	Enforce Flag\n- \
	CLSID\n- \
	Language\n- \
	Product Name\n')
	
	
	parser.add_option('-r', dest = 'regname', type ='string',help = 'registry key')
	parser.add_option('--out', dest = 'output_file', type='string', help = 'output to file')
	parser.add_option('-u', dest = 'uname', type='string',help='user name with domain or workgroup')
	parser.add_option('-p', dest = 'upassword', type='string', help='user password')
	parser.add_option('-s', dest = 'fromhost', type='string',help = 'target machine')
	parser.add_option('-t', dest = 'tohost', type='string',help = 'target machine')
	parser.add_option('-c', dest = 'tocidrhost', type='string',help = 'cidr')
	parser.add_option('--sf', dest = 'sourcefile', type='string',help = 'sourcedir/sourcefile')
	parser.add_option('--df', dest = 'destinationfile', type='string',help = 'destdir/destfile')
	parser.add_option('--hlp', dest = 'help', type='string',help='show options and registry keys')
	parser.add_option('-l', dest = 'localhost', type='string',help='run into local host')
	parser.add_option('-d', dest = 'down', type='string',help='downgrade DAT')
	
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
	help = options.help
	local = options.localhost
	down = options.down
	
	
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
def DATdate():
	today = date.today()
	return str(today).replace("-","")

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
			print Fore.WHITE + '[*] file did not copied to C:\Program Files\Common Files\McAfee\%s.' % destfile
			if (outfile != None):
				log_to_file('[*] file did not copied to C:\Program Files\Common Files\McAfee\%s.' % destfile,outfile)
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
		print '[*] check registry values, source and destination'
		if (outfile != None):
			log_to_file('[*] check registry values, source and destination',outfile)
			
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

# This function updates DAT files inside the Engine file. It requires McShield and McAfeeFramework to stop and after the files copied then start.
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
def update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	today = DATdate()
	if status1 != STOPPED and status2 != STOPPED and state_value == "passed":									
		if(arch == 'x86'):
			print "[*] updating registry.."
			if (outfile != None):
				log_to_file("[*] updating registry..",outfile)
			result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
			dateres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatDate',sValue=today)
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
			print "[*] registry updated successfully"
			if (outfile != None):
				log_to_file("[*] registry updated successfully",outfile)
		else:
			print "[*] updating registry.."
			if (outfile != None):
				log_to_file("[*] updating registry..",outfile)
			result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
			dateres, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName='DatDate',sValue=today)
			res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
			print "[*] registry updated successfully"
			if (outfile != None):
				log_to_file("[*] registry updated successfully",outfile)
		print  Fore.WHITE + "[*] new current %s is" % (value) + Fore.YELLOW + " %s " % (val)
		print "[*] Exiting...\n"
		if (outfile != None):
			log_to_file("[*] new current %s " % (value) + "is %s \n\n" % (val),outfile)
	elif state_value == "not_passed":
		print "[*] Registry cannot be updated. Please try again..\n"
		if (outfile != None):
			log_to_file("[*] Registry cannot be updated. Please try again..\n",outfile)
	semaphore.release()

def changeDATversion(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile,arch,c,value,val,level):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	if DAT2val != valnum and level=="down":
		status1,status2,state_value = update_vse(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile)
		update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val)
	elif DAT2val != valnum and level == None and DAT2val > valnum:
		status1,status2,state_value = update_vse(DAT,ip,DAT2val,valnum,username,upass,sourcefile,destfile,outfile)
		update_registry(status1,status2,state_value,arch,outfile,c,value,DAT2val)
	elif DAT2val == valnum or (DAT2val < valnum and level==None):
		print Fore.WHITE + "[*] current %s " % (value) + "is " + Fore.YELLOW +  "%s " % (val)
		if (DAT2val < valnum):
			print "[*] You are trying to install a lower DAT version..Use option '-d down' to downgrade.."
		print "[*] Exiting..."
		if (outfile != None):
			log_to_file("[*] current %s " % (value) + "is %s" % (val),outfile)
			log_to_file("[*] Exiting...",outfile)
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
						print "[*] Cannot access services..check permissions"
						print "[*] Exiting..."
						continue
			else:
				print "[*] Not connected to host with IP address %s" % ip + " Probably the host is down or user is logged off"
				if (outfile != None):
					log_to_file("[*] Not connected to IP address %s" % ip + " Probably the host is down or user is logged off",outfile)
		except win32service.error, (msg):
			print "[*] Error starting service: %s" % msg
			if (outfile != None):
				log_to_file("[*] Error starting service: %s" % msg,outfile)
			continue
				
if __name__ == '__main__':
	main()
	