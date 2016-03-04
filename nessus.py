import sys
import optparse
import subprocess
import os

parser = optparse.OptionParser()
parser.add_option('-f',help = 'give the .csv file name',action="store",dest = "csv_file")
parser.add_option('-i',help = 'give the ID of the vulnerability',action="store",dest = "ID")
parser.add_option('--no-fqdn', action="store_true", help='don\'t write domain names to the file',default=False, dest = 'no_fqdn_flag')
(opts,args) = parser.parse_args()

if not os.path.exists(os.getcwd()+"/"+opts.csv_file):
	print "\n\n\tThere is no such a file in this directory: %s\n" %(opts.csv_file)
	exit()

if opts.csv_file is not None:
		result_flag = os.path.exists(os.getcwd()+"/"+opts.csv_file+"_result.txt")
		order_flag = os.path.exists(os.getcwd()+"/"+opts.csv_file+"_order.txt")
		fqdn_flag = os.path.exists(os.getcwd()+"/"+opts.csv_file+"_fqdn.txt")
		vulnNames_flag = os.path.exists(os.getcwd()+"/"+opts.csv_file+"_vulnNames.txt")
		if not (result_flag and fqdn_flag and vulnNames_flag and order_flag):
			if opts.ID is not None and (result_flag or order_flag or fqdn_flag or vulnNames_flag):
				print "\n"
				if not result_flag:
					print "\t'%s' could not be found." % (opts.csv_file+"_result.txt")	
				if not order_flag:
					print "\t'%s' could not be found." % (opts.csv_file+"_order.txt")		
				if not fqdn_flag:
					print "\t'%s' could not be found." % (opts.csv_file+"_fqdn.txt")		
				if not vulnNames_flag:
					print "\t'%s' could not be found." % (opts.csv_file+"_vulnNames.txt")
				print "\n\n\tSo again, we are parsing our .csv file."
		
			print "\n"
			if not os.path.exists("nessus.sh"):
                                print "\n\t\'nessus.sh\' is missing. We should have it for the script to work properly.\n"
                                exit()
			subprocess.call(["chmod","755","nessus.sh"])
			subprocess.call(["bash","nessus.sh",opts.csv_file])
else:
	print "\n\n\t.csv file name is missing.\n"
	if opts.ID is None:
		print "\tUsage: python nessus.py -f <csv_file>\n"
	else:
		print "\tUsage: python nessus.py -i <vulnID> -f <csv_file>\n"
	exit()

result = open(opts.csv_file+"_result.txt","r")
result_array = result.readlines()
fqdn_file = open(opts.csv_file+"_fqdn.txt","r")
fqdn_array = fqdn_file.readlines()


fqdnDict = {}
for line in fqdn_array:
	fqdnDict[line[:-1].split()[0]] = line[:-1].split()[1]

#print fqdnDict

dict = {}
for i,elem in enumerate(result_array):
	if i == 0:
		dict[elem[:5]] = [elem[:-1].split(',')[1] + ":" + elem[:-1].split(',')[2]]
	else:
		if elem[:5] == result_array[i-1][:5]:
			dict[elem[:5]] = dict[elem[:5]] + [elem[:-1].split(',')[1] + ":" + elem[:-1].split(',')[2]]
		else:
			dict[elem[:5]] = [elem[:-1].split(',')[1] + ":" + elem[:-1].split(',')[2]]	

def listToDict(lst):
	dic = {}
	for each in lst:
		ip_addr = ipToFQDN(each.split(':')[0]) 
		if ip_addr not in dic.keys():
			dic[ip_addr] = each.split(':')[1]
		else:
			if each.split(':')[1] not in dic[ip_addr].split(','):
				dic[ip_addr] = dic[ip_addr] + "," + each.split(':')[1]  	

	return dic

def ipToFQDN(str):
	if str in fqdnDict.keys() and (not opts.no_fqdn_flag):
		return fqdnDict[str][:-1] + ' - ' + str
	else:
		return str

if opts.ID is not None and opts.csv_file is not None:	
	vulnID = opts.ID
	try:
		fileDict = listToDict(dict[vulnID])
	except:
		print "\n\n\tThere is no such an ID in \'%s\': %s\n" %(opts.csv_file,opts.ID)		
		exit()
		
	fileName = opts.csv_file + "_" + vulnID + ".txt"
	fo = open(fileName,'w')
	for elem in fileDict.keys():
		fo.write(elem + ":" + fileDict[elem] + "\n")
	print "\n\n\t%s created.\n" % (fileName)

else:
	print "\n\n\tYou can parse .csv file based on vulnerability ID by providing BOTH .csv file name and vulnerability ID.\n"
	print "\tUsage: python nessus.py -i <vulnID> -f <csv_file>\n"
