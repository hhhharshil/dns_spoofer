# dns_spoofer
DNS Spoofer developed in Python3 

Perform the following commands before utilizing the DNS Spoofer:

Spoofing DNS for an external machine:
iptables -I FORWARD -j NFQUEUE --queue-num 0 

Spoof DNS on local host:
iptables -I OUTPUT -j NFQUEUE --queue-num 0 
iptables -I INPUT -j NFQUEUE --queue-num 0 

After DNS Spoofer is exited flush IP tables:
iptables --flush

Possible Future Updates:
Flush IP tables when exiting with Ctrl + C (import subprocess?)
Give the program more logic i.e:
  Choose the type of spoofing you want with arguments I for internal E for External...
