wordlist=$2
threads=$3
output_dir=$4
extensions=$5
if [ $1 == 'ffuf' ]
	then
	for x in $(cat $wordlist)
	do
		tempname=$(echo $x | awk -F"/" '{print $3}')
		if [ -z "$extensions"]
		then
			ffuf -u $x/FUZZ -t $threads -w $wordlist -e $extensions -of csv -ac -o $output_dir"/"$tempname".txt"  
		else
			echo "nope"
		fi
	done
elif [ $1 == 'gobuster' ]
	then
	echo 'gobuster'
fi
