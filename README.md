# vseutil

vseutil tool performs the following

- Scan networks and single machines and reads as well as updates McAfee VSE 8.8.x windows registry values
- Copy latest DAT files to target machine in order to keep VSE 8.8.x antivirus updated
- Runs on 32bit as well as 64bit Windows OS
- Works only with VSE 8.8.x (future versions of vseutil will include every version of VSE)

The vseutil script developed based on the following article which describes the steps to update VSE 8.8.x DAT files on endpoints machines manually

https://kc.mcafee.com/corporate/index?page=content&id=KB51679

### Registry value that changes when update McAfee VSE 8.8.x

![reg](https://cloud.githubusercontent.com/assets/12726776/10712132/7ff04d56-7a99-11e5-8d5b-4effd8ace466.PNG)

### Who need this

everyone who want to keep VSE antivirus signatures updated on endpoints when McAfee agent does not communicating correctly with McAfee ePO.

### Prerequisites

- C:\Program Files\Common Files\McAfee\Engine must be shared
- Privileged domain users must have read/write permissions to C:\Program Files\Common Files\McAfee\Engine
- McAfee services McShield and McAfeeFramework must be allowed to be modified on target machines
- Endpoints must alow WMI connections from privileged domain users to manipulate registry values
- Privilleged domain users must be able to connect through SMB connections to endpoints that have VSE 8.8.x installed
- Disable UAC on endpoints 

### Security Concerns 

As shown at the previous image this tool can run only when no service protection is enabled from VSE console. Because we dont want non-privileged users to stop McAfee services from functioning, but instead we only want privileged users to be able to modify the services, we must add privileged domain users at local security policy by selecting administrative tools located at control panel,then local security policy,then user rights assignment and then select "act as part of the operating system". The following images show the process. 

- Administrative tools --> Local security policy 

![local](https://cloud.githubusercontent.com/assets/12726776/10758540/9ed76f56-7cba-11e5-8fa9-041a6eb055d6.PNG)

- Local Security Policy --> User Rights Assignment

![rights](https://cloud.githubusercontent.com/assets/12726776/10758547/a2e8c996-7cba-11e5-9f09-b3aac02b63f8.PNG)

- User Rights Assignment --> act as part of the operating system 

![act](https://cloud.githubusercontent.com/assets/12726776/10758544/a1a23392-7cba-11e5-9bda-9a856d37af76.PNG)

- act as part of the operating system --> add domain user

![user](https://cloud.githubusercontent.com/assets/12726776/10758664/8768a1ea-7cbb-11e5-82c6-6944c26e9f81.PNG)

### Running script without any arguments

 - Running the script without arguments gives the following
 
![vse_help](https://cloud.githubusercontent.com/assets/12726776/10962257/8be8e69a-839f-11e5-8cd0-700d7c924219.PNG)

### Running the script using --hlp help as argument gives the following output

![help](https://cloud.githubusercontent.com/assets/12726776/10962291/cad613a0-839f-11e5-8fe0-c88851063396.PNG)

#####Registry Values:

- DATVersion
- Version
- DatInstallDate
- HotFixVersions
- Uninstall Command
- EngineVersion
- DatDate
- EngineInstallDate
- Install Path
- Installs CMA
- Plugin Flag
- Plugin Path
- Software ID
- McTrayAboutBoxDisplay
- Enforce Flag
- CLSID
- Language
- Product Name

### Script Options 

- ```-c```    	use this option to specify IP address as well as range of addresses using cidr
- ```--sf```    	use this option to specify the source file that will be copied to target machine
- ```--df```    	use this option to specify the destination that the file will be copied
- ```-r```     	use this option to specify the registry value you want to review 
- ```-u```     	use this option to specify username 
- ```-p```     	use this option to specify password
- ```-s```     	use this option to specify the first IP address to check
- ```-t```    	use this option to specify the last IP address to check
- ```--out```		use this option to save the output into a log file --> e.g. '--out vse.log' or vse.csv
- ```-d```		use this option if you want to downgrade the DAT version 

### How to allow mcafee services modifications

![prevent](https://cloud.githubusercontent.com/assets/12726776/10712086/dad7c462-7a97-11e5-97df-1f56e8e09fe8.PNG)

### Create windows executable

```python pyinstaller.py --onefile vseutil.py```

### How to run it 

1) Update VSE on a range of machines in subnet

```vseutil.exe -s from_ip -t to_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

2) Update VSE on a single machine

```vseutil.exe -c target_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

3) Update VSE on a range of machines in a subnet using cidr

```vseutil.exe -c ip/cidr -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

4) Show registry values on a range of machines in a subnet

```vseutil.exe -s from_ip -t to_ip -u DOMAIN\user -p password -r "value"```

5) Show registry value on a range of machines in a subnet using cidr 

```vseutil.exe -c ip/cidr -u DOMAIN\user -p password -r "value"```

6) Show registry value on a single machine

```vseutil.exe -c ip -u DOMAIN\user -p password -r "value"```

7) Execute vseutil.exe and save the output into a file 

```vseutil.exe -c ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value" --out vse.log```

8) Execute vseutil.exe and downgrade the DAT version on endpoints as well as save the output into a log file

```vseutil.exe -c ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value" --out vse.log -d```

### Execution example

![execution](https://cloud.githubusercontent.com/assets/12726776/10912348/bd72d760-8251-11e5-937b-d6c66e5b5652.PNG)

