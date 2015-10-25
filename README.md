# vse88x

vse88x tool performs the following

- scan networks and single machines and reads McAfee VSE 8.8.x windows registry values
- copy latest DAT file to target machine and executes the DAT in order to keep VSE 8.8.x antivirus updated
- runs on 32bit as well as 64bit Windows OS

the following article describes the steps updating VSE manually

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

### Running script without any arguments

 - Running the script without arguments gives the following

![vse88](https://cloud.githubusercontent.com/assets/12726776/10715687/f30fe588-7b27-11e5-8d53-246ca046d028.PNG)
 
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

### Example of execution

![execution_2](https://cloud.githubusercontent.com/assets/12726776/10712004/78cc29cc-7a95-11e5-9dbc-0089dcc282b1.PNG)


