# soc_checker
SOC analyst project for automated cyber attacks 

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/a018e4ef-682b-4026-9df1-ac60136e9652)

An automation development of various cyber-attacks such as brute-forcing, DDoS attack, LLMNR poisoning and ARP-spoofing to test the strength of local firewall network. 
Implemented customised alerts with SIEM (ELK) to detect these attack  and Snort IPS/IDS rules in pfsense firewall to prevent these attacks.

a) Creation of logs in /var/log for later referencing the cyber-attacks.

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/9d50cd3f-ddc5-4104-a7f9-384e71dc5e0d)

b) Automated scanning of local network for target hosts and information gathering. Assigned the attacks as a manual input or random selection of target IP addresses.

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/ff5661e3-e77d-4b57-bca8-598facc81cd6)

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/cf45436b-f03b-48c1-a6d3-3cc06273e348)

c) Automated checker for any software dependancies to run the scripts

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/d776af89-0969-456d-b4b7-a58ff3b4431a)

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/fd15ce3e-5cac-45a9-a4dd-cb90693760cd)

d) Automating a cyber-attack and check if it is successfully running. (An example is Brute-forcing with Hydra)


![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/916a35c1-7cc9-4521-a838-3109948095c1)

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/dbd4ccac-4c46-4ecf-9ecf-ffd98cc26d0b)

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/49c1dfb3-885a-423b-8631-5cec361fb7cd)

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/f31aec17-c7aa-4159-872e-2af04b184fea)

e) Usage of case statements in bash to running selection of attacker by user input or random selection of attacks

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/0f20c286-5d29-4c1e-a3e6-7177d4fe4a95)

f) SIEM implementation with ELK alerts to test within virtualised local network of machines

Wireshark Scanning of the attacks

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/5e05f2cb-ef06-4cd1-b4b7-27b4cb50dc13)

ELK results on logs

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/f6c596ba-a087-477b-95dc-2c77580f59ab)

Customised alerts for any brute-forcing by Remote Desktop service (RDP) in Windows-based machines.

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/89144f2b-e134-4852-b0e8-0bac3327a5ec)

g) Snort IDS/IPS rules for attacks

Set rules to detect or prevent these cyber attacks in pfSense firewall settings.

An example is bruteforcing with credentials.

Snort Rule

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/f8d9322c-e34e-44a2-a040-22ec3933507a)

Snort Rule Results

![image](https://github.com/AlexKongFY/soc_checker/assets/93807661/9e77a410-8812-4565-a6cf-7671a4c38ba6)

