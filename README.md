# nessusParser
This script has been developed by Behruz Cebiyev.



[ What is this script for? ]

If you have a nessus export or multiple nessus exports in csv format, you may need to parse them based on vulnerability IDs.
To speak more specifically, if you want to get all IPs and corresponding ports affected by a specific vulnerability,
you can get it by providing the ID of that vulnerability and the name of the nessus export (or multiple nessus exports merged into one) which should be in .csv format, to that script. 



[ How to use it? ]

Put your csv file (nessus export in .csv format), nessus.sh and nessus.py under some directory in your Linux machine.
Then, give just the .csv file name to the script so that to get some files ready for further parse operations based on vulnerability ID.
Then, by providing the .csv file name and an vulnerability ID, you will get a file created in which there are IPs with their domain names and corresponding ports affected from that vulnerability.



[Python version]

This script works properly with Python2.7. 



[ Help Page ]

![alt tag](https://github.com/BiznetLab/nessusParser/blob/master/help.PNG)
  
  

[ Example Usage ]

root@linux:~/nessus# python nessus.py -f test.csv
			
  [Output has been removed for the sake of neatness]
   
root@linux:~/nessus# python nessus.py -i 83298 -f test.csv
	
  [Output has been removed the sake of neatness]	        
   
