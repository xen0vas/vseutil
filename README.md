# vse88x

vse88x tool performs the following

- Scan networks and single machines and reads McAfee VSE 8.8.x windows registry values
- Copy latest DAT file to target machine and executes the DAT in order to keep VSE 8.8.x antivirus updated
- Runs on 32bit as well as 64bit Windows OS

The vse88x script developed based on the following article which describes the steps to update VSE 8.8.x DAT files on endpoints machines manually

https://kc.mcafee.com/corporate/index?page=content&id=KB51679

### Registry value that changes when update McAfee VSE 8.8.x

![reg](https://cloud.githubusercontent.com/assets/12726776/10712132/7ff04d56-7a99-11e5-8d5b-4effd8ace466.PNG)

### Who need this

Security engineers who want to keep VSE updated on endpoints when ePO is not functioning correctly.

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

![vse88](https://cloud.githubusercontent.com/assets/12726776/10715882/a0cc5ab6-7b2e-11e5-9ef0-d098d66b2553.PNG)
 
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

- ```-c```    use this option to specify IP address as well as range of addresses using cidr
- ```--sf```    use this option to specify the source file that will be copied to target machine
- ```--df```    use this option to specify the destination that the file will be copied
- ```-r```     use this option to specify the registry value you want to review 
- ```-u```     use this option to specify username 
- ```-p```     use this option to specify password
- ```-s```     use this option to specify the first IP address to check
- ```-t```    use this option to specify the last IP address to check
- ```--out``` use this option to save the output into a log file

### How to allow mcafee services modifications

![prevent](https://cloud.githubusercontent.com/assets/12726776/10712086/dad7c462-7a97-11e5-97df-1f56e8e09fe8.PNG)

### Create windows executable

```python pyinstaller.py --onefile vse88x.py```

### How to run it 

1) Update VSE on a range of machines in subnet

```vse88x.exe -s from_ip -t to_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

2) Update VSE on a single machine

```vse88x.exe -c target_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

3) Update VSE on a range of machines in a subnet using cidr

```vse88x.exe -c ip/cidr -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r "value"```

4) Show registry values on a range of machines in a subnet

```vse88x.exe -s from_ip -t to_ip -u DOMAIN\user -p password -r "value"```

5) Show registry value on a range of machines in a subnet using cidr 

```vse88x.exe -c ip/cidr -u DOMAIN\user -p password -r "value"```

6) Show registry value on a single machine

```vse88x.exe -c ip -u DOMAIN\user -p password -r "value"```

### Execution example

![capture](https://cloud.githubusercontent.com/assets/12726776/10736731/355f15d6-7c17-11e5-88cb-8b32b1e930c4.PNG)


