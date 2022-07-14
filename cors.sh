#!/bin/bash

# cors_testing_script is a simple script written with bash scripting language,
# the perpos of this script, is to try to test if a specifec page are probably
# vulnerabil to CORS Misconfiguration by Comparing the ACAO "Access-Control-Allow-Origin"
# header value with Origin header value, and make sure that the ACAC
# "Access-Control-Allow-Credentials" header value is "true".

# Author : Mahmoud Mahfouz
# Twitter : @MahmoudZ0x1
# Github : https://github.com/MahmoudMahfouz21295/
# Facebook : https://www.facebook.com/profile.php?id=100073159347097
# Youtube : https://www.youtube.com/channel/UC7udOW9wUNkCDCgD7tu5dvA
# Usage : https://youtu.be/4pvbsa2Q90A

echo "{*} Start CORS Tester Script"
echo ""

read -p "{?} Enter Target URL {https://website.com/page} : " TARGET
read -p "{?} Enter Your Cookie {cookie=value; cookie=value} : " COOKIE
echo ""

ORIGIN_BASIC_VALUES=('test' 'null' 'localhost' '*' 'evil.com' 'sub.evil.com' 'http://evil.com' 'https://evil.com' 'http://sub.evil.com' 'https://sub.evil.com')

CORS_BASIC_TEST(){

	# len=${#ORIGIN_BASIC_VALUES[@]}
	# for (( i=0 ; i<${len}; i++ ));
	for value in "${ORIGIN_BASIC_VALUES[@]}"
	do
		echo "{*} Sending Request With {$value}"
		echo ""
		
		curl_var=$(curl "$1" --cookie "$2" -H "Origin: $value" -v 2>&1 1> /dev/null)
		ACAO_VALUE=$(echo "$curl_var" | grep "<" | grep "Access-Control-Allow-Origin" | cut -d ' ' -f 3)
		ACAC_VALUE=$(echo "$curl_var" | grep "<" | grep "Access-Control-Allow-Credentials" | cut -d ' ' -f 3)
		
		
		if [[ "$ACAC_VALUE" == *"true"* ]]
		then
		
			if [[ "$ACAO_VALUE" == *"$value"* ]]
			then
			
				echo "{*} $1 Probably Vulnerable To CORS Misconfiguration"
				echo "{+} Access-Control-Allow-Credentials: $ACAC_VALUE"
				echo "{+} Access-Control-Allow-Origin: $ACAO_VALUE"
				echo "{+} Origin: $value"
				echo ""
				echo "{*} Done !"

				exit 0
				
			fi
		fi

	done

}


CORS_ADV_TEST(){

	
	hostname=$(echo "$1" | cut -d '/' -f 3)
	x="${hostname//[^.]}"
	d="${#x}"
	t=`expr $d + 1`
	dom=$(echo $hostname | cut -d '.' -f $d)
	tld=$(echo $hostname | cut -d '.' -f $t)
	domain="$dom.$tld"

	ORIGIN_ADV_VALUES+=("thissitenot""$domain")
	ORIGIN_ADV_VALUES+=("http://thissitenot""$domain")
	ORIGIN_ADV_VALUES+=("https://thissitenot""$domain")
	ORIGIN_ADV_VALUES+=("ifvulntoxss.""$hostname")
	ORIGIN_ADV_VALUES+=("http://ifvulntoxss.""$hostname")
	ORIGIN_ADV_VALUES+=("https://ifvulntoxss.""$hostname")
	ORIGIN_ADV_VALUES+=("ifvulntoxss.""$domain")
	ORIGIN_ADV_VALUES+=("http://ifvulntoxss.""$domain")
	ORIGIN_ADV_VALUES+=("https://ifvulntoxss.""$domain")
	ORIGIN_ADV_VALUES+=("$hostname""tld")
	ORIGIN_ADV_VALUES+=("http://""$hostname""tld")
	ORIGIN_ADV_VALUES+=("https://""$hostname""tld")
	ORIGIN_ADV_VALUES+=("$hostname"".tld")
	ORIGIN_ADV_VALUES+=("http://""$hostname"".tld")
	ORIGIN_ADV_VALUES+=("https://""$hostname"".tld")
	ORIGIN_ADV_VALUES+=("$domain""tld")
	ORIGIN_ADV_VALUES+=("http://""$domain""tld")
	ORIGIN_ADV_VALUES+=("https://""$domain""tld")
	ORIGIN_ADV_VALUES+=("$domain"".tld")
	ORIGIN_ADV_VALUES+=("http://""$domain"".tld")
	ORIGIN_ADV_VALUES+=("https://""$domain"".tld")
	ORIGIN_ADV_VALUES+=("$domain"".evil.com")
	ORIGIN_ADV_VALUES+=("http://""$domain"".evil.com")
	ORIGIN_ADV_VALUES+=("https://""$domain"".evil.com")
	ORIGIN_ADV_VALUES+=("$hostname"".evil.com")
	ORIGIN_ADV_VALUES+=("http://""$hostname"".evil.com")
	ORIGIN_ADV_VALUES+=("https://""$hostname"".evil.com")
	ORIGIN_ADV_VALUES+=("evil.com/$hostname")
	ORIGIN_ADV_VALUES+=("http://evil.com/""$hostname")
	ORIGIN_ADV_VALUES+=("https://evil.com/""$hostname")
	ORIGIN_ADV_VALUES+=("evil.com/$domain")
	ORIGIN_ADV_VALUES+=("http://evil.com/""$domain")
	ORIGIN_ADV_VALUES+=("https://evil.com/""$domain")
	ORIGIN_ADV_VALUES+=("evil.com:""$hostname")
	ORIGIN_ADV_VALUES+=("http://evil.com:""$hostname")
	ORIGIN_ADV_VALUES+=("https://evil.com:""$hostname")
	ORIGIN_ADV_VALUES+=("evil.com:""$domain")
	ORIGIN_ADV_VALUES+=("http://evil.com:""$domain")
	ORIGIN_ADV_VALUES+=("https://evil.com:""$domain")
	ORIGIN_ADV_VALUES+=("evil.com/?query=$hostname")
	ORIGIN_ADV_VALUES+=("http://evil.com/?query=""$hostname")
	ORIGIN_ADV_VALUES+=("https://evil.com/?query=""$hostname")
	ORIGIN_ADV_VALUES+=("evil.com/?query=$domain")
	ORIGIN_ADV_VALUES+=("http://evil.com/?query=""$domain")
	ORIGIN_ADV_VALUES+=("https://evil.com/?query=""$domain")
	
	# len=${#ORIGIN_ADV_VALUES[$i]}
	# for (( i=0 ; i<${len}; i++ ));
	for value in "${ORIGIN_ADV_VALUES[@]}"
	do
	
		echo "{*} Sending Request With {Origin: $value}"
		echo ""
		
		curl_var=$(curl "$1" --cookie "$2" -H "Origin: $value" -v 2>&1 1> /dev/null)

		ACAO_VALUE=$(echo "$curl_var" | grep "<" | grep "Access-Control-Allow-Origin" | cut -d ' ' -f 3)
		ACAC_VALUE=$(echo "$curl_var" | grep "<" | grep "Access-Control-Allow-Credentials" | cut -d ' ' -f 3)
		
		if [[ "$ACAC_VALUE" == *"true"* ]]
		then
		
			if [[ "$ACAO_VALUE" == *"$value"* ]]
			then
			
				echo "{*} $1 Probably Vulnerable To CORS Misconfiguration"
				echo "{+} Access-Control-Allow-Credentials: $ACAC_VALUE"
				echo "{+} Access-Control-Allow-Origin: $ACAO_VALUE"
				echo "{+} Origin: $value"
				echo ""
				echo "{*} Done !"

				exit 0

			fi
		fi
	done

}



# Check if TARGET and COOKIE variables exists
if [ TARGET ] && [ COOKIE ]
then
	# Check if TARGET is real URL
	regex='(https?|ftp|file)://[-[:alnum:]\+&@#/%?=~_|!:,.;]*[-[:alnum:]\+&@#/%=~_|]'
	if [[ $TARGET =~ $regex ]]
	then
		# Call CORS_BASIC_TEST function to start the CORS basic tesing
		echo "{*} #### Start Basic CORS Testing #### "
		echo ""
		CORS_BASIC_TEST $TARGET $COOKIE
		echo "{*} #### Basic CORS Testing Has Been Finished ####"
		echo ""
		# Call CORS_ADV_TEST function to start the CORS advanced tesing
		echo "{*} #### Start Advanced CORS Testing #### "
		echo ""
		CORS_ADV_TEST $TARGET $COOKIE
		echo "{*} #### Advanced CORS Testing Has Been Finished ####"
		echo ""
		echo "{*} $TARGET Probably Not Vulnerable To CORS Misconfiguration"
		echo ""
		echo "{*} Script Finised .... "


	else
	    echo "{-} ERROR : Link not valid"
	    exit 0
	fi

fi
