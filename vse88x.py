
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
import pprint
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
import win32event

RUNNING = win32service.SERVICE_RUNNING
STARTING = win32service.SERVICE_START_PENDING
STOPPING = win32service.SERVICE_STOP_PENDING
STOPPED = win32service.SERVICE_STOPPED

init()

def main():
	
	parser = optparse.OptionParser('\n\nAuthor: Xenofon Vassilakopoulos (@xvass) \n\n[-] Usage: \n\n 1) vse88x.exe  -s <from_target> -t <to_target> -u <domain\username> -p <password> -r "<value>"\n\n 2) vse88x.exe -c target_ip -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>" \n\n 3) vse88x.exe -s <from_target> -t <to_target> -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>"\n\n 4) vse88x.exe -c <ip/cidr> -u <domain\username> -p <password> --sf <src_file> --df <share_folder> -r "<value>" \n\n 5) vse88x.exe -c <ip/cidr> -u <domain\username> -p <password> -r "<value>"\n\n 6) vse88x.exe -c <ip> -u <domain\username> -p <password> -r <"value">\n\n- Registry Values:\n\n- DATVersion\n- Version\n- DatInstallDate\n- HotFixVersions\n- Uninstall Command\n- EngineVersion\n- DatDate\n- EngineInstallDate\n- Install Path\n- Installs CMA\n- Plugin Flag\n- Plugin Path\n- Software ID\n- McTrayAboutBoxDisplay\n- Enforce Flag\n- CLSID\n- Language\n- Product Name\n')
	parser.add_option('-r', dest = 'regname', type ='string',help = 'registry key')
	parser.add_option('-u', dest = 'uname', type='string',help='user name with domain or workgroup')
	parser.add_option('-p', dest = 'upassword', type='string', help='user password')
	parser.add_option('-s', dest = 'fromhost', type='string',help = 'target machine')
	parser.add_option('-t', dest = 'tohost', type='string',help = 'target machine')
	parser.add_option('-c', dest = 'tocidrhost', type='string',help = 'cidr')
	parser.add_option('--sf', dest = 'sourcefile', type='string',help = 'sourcedir/sourcefile')
	parser.add_option('--df', dest = 'destinationfile', type='string',help = 'destdir/destfile')
	
	(options,args) = parser.parse_args()
	
	value = options.regname
	from_host = options.fromhost
	to_host = options.tohost
	tgtuser = options.uname
	tgtpass = options.upassword
	cidr_hosts = options.tocidrhost
	sourcefile = options.sourcefile
	destfile = options.destinationfile
	
	if (value == None and tgtuser == None and tgtpass == None and from_host == None and to_host == None):
			if (tgtuser == None or tgtpass == None or cidr_hosts == None):
						print parser.usage
						sys.exit()
	
	connectwmi(from_host,to_host,tgtuser,tgtpass,value,cidr_hosts,sourcefile,destfile)
				
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

def copy_file(ip,user,password,sourcefile,destfile):
		semaphore = threading.BoundedSemaphore()
		semaphore.acquire()
		wnet_connect(ip, user, password)
		try:
			shutil.copy2(sourcefile,'\\\\' + str(ip) + '\\' + str(destfile) + '\\')
			print Fore.WHITE + '[*] file ' + Fore.YELLOW + sourcefile + Fore.WHITE + ' copied to C:\Program Files\Common Files\McAfee\%s' % destfile
		except:
			print Fore.WHITE + '[*] file did not copied to C:\Program Files\Common Files\McAfee\%s. Check Permissions' % destfile
		semaphore.release()	

def unzip(DAT,ip,destfile):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	zipp = zipfile.ZipFile('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + DAT)
	zipp.extractall('\\\\' + str(ip) + '\\' + str(destfile) + '\\')
	print Fore.WHITE + "[*] files have been extracted to C:\Program Files\Common Files\McAfee\%s" % destfile
	print Fore.WHITE + "[*] new DAT has been installed.."
	semaphore.release()	
	
def deletefiles(ip,destfile,DAT):
	semaphore = threading.BoundedSemaphore()
	semaphore.acquire()
	os.remove('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + DAT)
	os.remove('\\\\' + str(ip) + '\\' + str(destfile) + '\\' + "legal.txt")
	print Fore.WHITE + "[*] cleaning unwanted files at C:\Program Files\Common Files\McAfee\%s" % destfile
	semaphore.release()	
	
def connectwmi(fromh,toh,username,upass,value,cidr_hosts,sourcefile,destfile):
	if (cidr_hosts != None):
		iprange = IPNetwork(cidr_hosts)
	else:
		iprange = IPRange(fromh, toh)
	for ip in iprange:
		print Fore.WHITE + "\n" + "IP: %s" % ip + "\n\n"
		try:
			try:	
				c = wmi.WMI(computer=ip, user=username, password=upass, namespace="root/default").StdRegProv
				print "[*] Connected to host with IP: %s" % ip
			except:
				print "[*] Not connected to host with IP adreess %s" % ip
				exit(1)
			
			if (value == 'DATVersion' and sourcefile != None and destfile != None and username != None and upass != None):
			
				n,arch = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
				if(arch == 'x86'):	
					
					res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				else:
					
					res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				
				try:
					uname=username.split('\\')
					user=uname[-1]
					domain=uname[0]
				except:
					user=username
					domain=None
						
				splitval = val 
				valsplit = splitval.split('.')
				sourcefilesplit = sourcefile.split('\\')
				DAT = sourcefilesplit[-1]
				DATval = DAT.split('.')
				valDAT = ''.join(DATval[0])
				val2DAT = valDAT.split('-')
				DAT2val = int(val2DAT[1])
				valnum = int(valsplit[0])
				
				if DAT2val > valnum:				
						status1 = svcStatus( "McShield", unicode(ip))
						status2 = svcStatus( "McAfeeFramework", unicode(ip))
													
						if status1 != STOPPED and status2 != STOPPED:
							svcStop( "McShield", unicode(ip))
							svcStop( "McAfeeFramework", unicode(ip))
							print Fore.WHITE +"[*] Found installed DAT version " + Fore.YELLOW + "%s.0000" % valnum 
							print Fore.WHITE +"[*] DAT "+ "latest version " + Fore.YELLOW + "%s.0000 " % DAT2val + Fore.WHITE + " uploded..."
							copy_file(ip,username,upass,sourcefile,destfile)
							unzip(DAT,ip,destfile)
							deletefiles(ip,destfile,DAT)
						else:
							id_val=1
							
						if status1 == STOPPED and status2 != STOPPED:
							arg="win32service.SERVICE_ALL_ACCESS"
							svcStart( "McShield",arg, unicode(ip))
												
						if status1 != STOPPED and status2 == STOPPED:
							arg="win32service.SERVICE_ALL_ACCESS"
							svcStart( "McAfeeFramework",arg, unicode(ip))
							
							
						status1 = svcStatus( "McShield", unicode(ip))
						status2 = svcStatus( "McAfeeFramework", unicode(ip))
						
						if status1 == STOPPED and status2 == STOPPED:
							arg="win32service.SERVICE_ALL_ACCESS"
							svcStart( "McShield",arg, unicode(ip))	
							svcStart( "McAfeeFramework",arg, unicode(ip))
						
						
						status1 = svcStatus( "McShield", unicode(ip))
						status2 = svcStatus( "McAfeeFramework", unicode(ip))
						
						if status1 != STOPPED and status2 != STOPPED and id_val != 1:	
								
								if(arch == 'x86'):
									print "[*] updating registry.."
									result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
									res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
									print "[*] registry updated succesfully"
								else:
									print "[*] updating registry.."
									result, = c.SetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName=r"SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value,sValue=str(DAT2val) + '.0000')
									res,val = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
									print "[*] registry updated succesfully"
								print  Fore.WHITE + "[*] new current %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
						elif id_val == 1:
							print "[*] Registry cannot be updated. Please check McAfee services in case they are not both stopped.\n"
				elif DAT2val <= valnum:
					print Fore.WHITE + "[*] current %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
				
			elif(value == None and sourcefile != None and destfile != None):
				try:
					copy_file(ip,username,upass,sourcefile,destfile)
				except:
						print "[*] file didnt copied to destination %s" % destfile
						
			elif(value != None and sourcefile == None and destfile == None and username != None and upass != None):
				n,arch = c.GetStringValue(hDefKey=win32con.HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
				if(arch == 'x86'):	
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				else:
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				print  "[*] The %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
			
			else:
				print '[*] check registry values or source and destination file to copy'
				
		except win32service.error, (hr, fn, msg):
			print "[*] Error starting service: %s" % msg
					
					
if __name__ == '__main__':
	main()
	