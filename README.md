# vse88x


This executable performs the following 

- scan networks and single machines reads windows registry and show values 
- copy DAT file to target machine and executes the newest DAT on that machine to upgrade VSE antivirus signatures 


### Create windows executable 

python pyinstaller.py --onefile vse88x.py

### How to run it 

###### *** the following execution command will search for the hosts with IP from 192.168.162.10 to 192.168.162.11 and will copy the DAT to the share folder named share 

vse88x.exe -s 192.168.162.10 -t  192.168.162.11  -u DOMAIN\User -p !12345! --sf c:\share\7949xdat.exe --df share


