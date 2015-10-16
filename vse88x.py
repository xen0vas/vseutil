
from _winreg import *
import optparse
import sys
import platform as winos
import wmi
from netaddr import *
import pprint
from colorama import  *
import shutil
import win32wnet
import psexec


init()

def main():
	
	parser = optparse.OptionParser('\n\n[-] Author Xenofon Vassilakopoulos , Systems Security Engineer - custom script for searching VSE registry information\n\n- Usage: vse8800.exe  -s <from_target> -t <to_target> -u <domain\username> -p <password> -r  "<value>"\n\nRegistry Values\n\n- DATVersion\n- Version\n- DatInstallDate\n- HotFixVersions\n- Uninstall Command\n- EngineVersion\n- DatDate\n- EngineInstallDate\n\nFor other values check registry keys\n\nfor 64bit OS --> SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800\n\nfor 32bit OS --> SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800\n\n')
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
		
	#if (value == "all"):
	#	enumerate(from_host,to_host,tgtuser,tgtpass,value,cidr_hosts)
	#else:		
	
	
	Xeno

def enumerate(fromh,toh,username,upass,value,cidr_hosts):
	if (cidr_hosts != None):
		iprange = IPNetwork(cidr_hosts)
	else:
		iprange = IPRange(fromh, toh)
	for ip in iprange:
		print Fore.WHITE + "\n" + "IP: %s" % ip + "\n\n"
		try:	
			c = wmi.WMI(computer=ip, user=username, password=upass, namespace="root/default").StdRegProv
			t = OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800", 0, KEY_ALL_ACCESS)
			count = 0
			while 1:
				name, value, type = c.EnumKey(t, count)
				print repr(name),
				count = count + 1
			CloseKey(t)
		except WindowsError:
			raise

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
	
		wnet_connect(ip, user, password)
		try:
			shutil.copy2(sourcefile,'\\\\' + str(ip) + '\\' + str(destfile) + '\\')
	
			print  'file ' + Fore.YELLOW + sourcefile + Fore.WHITE + ' copied to %s' % destfile
			
		except:
			print 'file didnt copied to %s' % destfile
			raise
		
#def fileexecute():
	

def connectwmi(fromh,toh,username,upass,value,cidr_hosts,sourcefile,destfile):
		
	if (cidr_hosts != None):
		iprange = IPNetwork(cidr_hosts)
	else:
		iprange = IPRange(fromh, toh)
	for ip in iprange:
		print Fore.WHITE + "\n" + "IP: %s" % ip + "\n\n"
		try:
			if (value == 'DATVersion' and sourcefile != None and destfile != None):
				
				copy_file(ip,username,upass,sourcefile,destfile)
				c = wmi.WMI(computer=ip, user=username, password=upass, namespace="root/default").StdRegProv
				n,arch = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
				if(arch == 'x86'):	
					results, vname = c.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800")
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				else:
					results, vname = c.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800")
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				
				splitval = val 
				valsplit = splitval.split('.')
				sourcefilesplit = sourcefile.split('\\')
				DAT = sourcefilesplit[-1]
				DATval = DAT.split('.')
				valDAT = ''.join(DATval[0])
				val2DAT = valDAT.split('x')
				DAT2val = int(val2DAT[0])
				valnum = int(valsplit[0])
				
				if DAT2val > valnum:
					try:
						print "DAT: %s.0000" % DAT2val + " is bigger version"
						psproject = psexec.PSEXEC(DAT,destfile,username,upass)
						print "executing new DAT %s" % sourcefile
						psproject.run(ip)
					except:
						raise
				
				if (value == "all"):
					regvalue(vname)
					
				else:
					print  "current %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
			elif(value == None and sourcefile != None and destfile != None):
				try:
					copy_file(ip,username,upass,sourcefile,destfile)
				except:
						print "file didnt copied to destination %s" % destfile
						
			elif(value != None and sourcefile == None and destfile == None):

				c = wmi.WMI(computer=ip, user=username, password=upass, namespace="root/default").StdRegProv
				n,arch = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SYSTEM\CurrentControlSet\Control\Session Manager\Environment",sValueName="PROCESSOR_ARCHITECTURE")
				if(arch == 'x86'):	
					results, vname = c.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800")
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				else:
					results, vname = c.EnumKey(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800")
					res,val = c.GetStringValue(hDefKey=HKEY_LOCAL_MACHINE,sSubKeyName="SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800",sValueName=value)
				if (value == "all"):
					regvalue(vname)
				else:
					print  "The %s " % (value) + "is " + Fore.YELLOW +  "%s \n\n" % (val)
			else:
				print 'check registry values or source and destination file to copy'
		except: 
			print "Probably host is down or no VSE 8.8.x installed \n\n"
	
def regvalue(val):
		try:
			for item in repr(val):
				print item
		except:
			print "no value"			
if __name__ == '__main__':
	main()
	