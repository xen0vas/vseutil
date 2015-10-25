# vse88x

This executable performs the following

- scan networks and single machines and reads McAfee VSE windows registry values
- copy latest DAT file to target machine and executes the DAT in order to keep VSE antivirus updated

the following article describes the steps updating VSE manually

https://kc.mcafee.com/corporate/index?page=content&id=KB51679

### Registry value that changes when update McAfee VSE 8.8.x

![reg](https://cloud.githubusercontent.com/assets/12726776/10712132/7ff04d56-7a99-11e5-8d5b-4effd8ace466.PNG)

### Who need this

Security engineers who want to keep VSE updated on target machines when ePO is screwed up.

### Prerequisites

- C:\Program Files\Common Files\McAfee\Engine must be shared to domain privilege user with read/write permissions
- McAfee services McShield and McAfeeFramework must be allowed to be modified on target machines
- Target machines must alow wmi connections to manipulate registry values remotely using a domain privilege user
- Allow SMB connections from domain privilege user 

### Registry Values


### Script Options 

- \-c     use this option to specify IP address as well as range of addresses using cidr
- \-\-sf    use this option to specify the source file that will be copied to target machine
- \-\-df    use this option to specify the destination that the file will be copied
- \-r     use this option to specify the registry value you want to review 
- \-u     use this option to specify username 
- \-p     use this option to specify password
- \-s     use this option to specify the first IP address to check
- \-t     use this option to specify the last IP address to check

### How to allow mcafee services modifications

![prevent](https://cloud.githubusercontent.com/assets/12726776/10712086/dad7c462-7a97-11e5-97df-1f56e8e09fe8.PNG)

### Create windows executable

python pyinstaller.py --onefile vse88x.py

### How to run it 

1) Update VSE on a range of machines

vse88x.exe -s from_ip -t to_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r DATVersion

2) Update VSE on a single machine

vse88x.exe -c target_ip -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r DATVersion

3) Show Registry values on a range of machines

vse88x.exe -s from_ip -t to_ip -u DOMAIN\user -p password -r DATVersion

4) Show Registry Values on a range of machine in a subnet using cidr 

vse88x.exe -c ip/cidr -u DOMAIN\user -p password --sf src_file --df Share_folder_name -r DATVersion

### Example of execution

![execution_2](https://cloud.githubusercontent.com/assets/12726776/10712004/78cc29cc-7a95-11e5-9dbc-0089dcc282b1.PNG)


