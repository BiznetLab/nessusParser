echo -e "[ Critical ],5\n[ High ],4\n[ Low ],2\n[ Medium ],3\n[ None ],1" > $1_order.txt;

printf "\t";echo \"$1_order.txt\" created.

grep -r '^\"[0-9][0-9][0-9][0-9].*' $1 | awk -F"," '{ print $1,$5,$7 }' > $1_res.txt;

grep "^\"11936\|Remote operating system :" tmp.csv | cut -d"," -f5 | sed 's/^.*: //g' | tr -d "\""  > os_identified.txt 

sed 's/" "/,/g' $1_res.txt | sed 's/"//g' | uniq | sort -g > $1_result.txt;

rm $1_res.txt;

printf "\t";echo \"$1_result.txt\" created.

cat $1 | grep "resolves as" | awk -F" " '{ print $1,$4 }' > $1_fqdn.txt;

printf "\t";echo \"$1_fqdn.txt\" created.

grep -r '^\"[0-9][0-9][0-9][0-9].*' $1 | awk -F"," '{ print $1,$8,",[",$4,"]" }' > $1_res.txt;

sed 's/ /  ,  /' $1_res.txt | sed 's/"//g' | sed 's/^/  /' | sort -n | uniq > $1_vulnName.txt;

cat $1_vulnName.txt | sort -t, -k3 | join -t, -1 1 -2 3 $1_order.txt - | sort -t, -k2 | awk -F"," '{print $3,$4,"\t",$1}' > $1_vulnNames.txt;

rm $1_res.txt;

rm $1_vulnName.txt;

printf "\t";echo \"$1_vulnNames.txt\" created.;

echo;echo;

printf "\t";
echo Dumping \"$1_vulnNames.txt\" ...  \(Vulnerability names and IDs in this file.\) ;
echo ;
echo;
sleep 3 ;

cat $1_vulnNames.txt
