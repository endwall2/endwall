
#! /bin/sh
####################################################################################
#                        HEADER AND INSTRUCTIONS
####################################################################################
# Program: endwall.sh
# Type: Bourne shell script
# Current Version: 1.21  Feb 28 2016
# Stable Version:  1.16, Feb 14 2016
# Author: Endwall Development Team
#
# Changes:  - Fixed line 1 for Bourne shell (lcd)
#           - Added rules to BASIC FIRST LINE SECURITY/BAD FLAGS section
#           - Changed style issues (gawk to awk etc), added double quotes to variables
#           - Minor changes to first line security section
#           - Minimized instructions in header
#           - Fixed gateway mac pulling bug
#           - Added ipv6 host ip address pull
#           - Removed dependancies on lists or sets
#
#
# Instructions: make directory,copy the file and change name to endwall.sh
#               make whitelists,blacklist text files, edit the endwall.sh file
#               change permisions to make endwall.sh executable, run the file.    
#
# Notes:    - uncomment the macchanger lines if you want random mac address.
#           - requires macchanger (optional)
#           - comment out lines starting at 1335 for alternate distributions you don't use
#
# $ mkdir ~/endwall
# $ cp endwall_v1xx.sh endwall.sh
# $ nano endwall.sh   # go to the section below labeled GLOBAL VARIABLES
#                       edit the variables client1_ip,client1_mac,client1_ip,client2_mac 
#                       so that they match your needs and save. ^X  
#                     # uncomment the macchanger lines to use machanger
#                     # comment out save rules on line 1335 for distributions not used
# $ chmod u+rwx endwall.sh          # changer permisions to allow script execution
# $ su                              # become root
# # ./endwall.sh                    # execute/run the file
# OPTIONAL
# # ./endlists.sh                   # Loads traditional blacklists and whitelists into iptables rules
# # ./endsets.sh                    # Requires ipset, loads advanced kernel packet filtering blacklists
#
#####################################################################################################
# Note that ip6tables is not enabled by default on some distributions
# for systemd enable and start iptables/ip6tables as follows:
# # systemctl enable iptables
# # systemctl enable ip6tables 
# # systemctl enable iptables.service
# # systemctl enable ip6tables.service
# # systemctl start iptables
# # systemctl start ip6tables
# # systemctl restart iptables
# # systemctl restart ip6tables
#
################################################################################################
#                           GLOBAL VARIABLES
################################################################################################
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables

# Grab interface name from ip link and parse 
int_if=$(ip link | grep -a "state " | awk -F: '{ if (FNR==2) print $2}')
int_if2=$(ip link | grep -a "state " | awk -F: '{ if (FNR==3) print $2}')

# Grab Gateway Information
gateway_ip=$(ip route | awk '/via/ {print $3}')
#gateway_mac=$( arp | awk '/gateway/ {print $3}')
gateway_mac=$( nmap -sS "$gateway_ip" -p 53| grep -a "MAC Address:" | awk '{print $3}')

# RUN MAC CHANGER on INTERFACES
#macchanger -A $int_if
#macchanger -A "$int_if2"

# grab host mac addresses from ip link  
host_mac=$(ip link | grep -a "ether" | awk ' {if (FNR==1) print $2}')
host_mac2=$(ip link | grep -a "ether" | awk ' {if (FNR==2) print $2}')

# grab the ip addresses from the interfaces
host_ip=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| awk '{print $2}')
host_ip2=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')
# grab the ipv6 addresses frrom the interfaces
host_ip1v6=$(ip addr | grep -a "inet6"| awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')
host_ip2v6=$(ip addr | grep -a "inet6"| awk 'BEGIN  {FS="/"} {if (FNR==3) print $1}'| awk '{print $2}')

############################  CLIENTS  ################################################
# change these values but dont leave them blank
# add more clients as you need them use $ arp or $ nmap -sS client_ip to determine values 

#client1_mac=00:00:00:00:00:00  # change to be the mac address of client 1
#client2_mac=00:00:00:00:00:00  # change to be the mac address of client 2

#client1_ip=192.168.0.161   # change to be the static ip of your first internal client
#client2_ip=192.168.0.162   # change to be the static ip of your second internal client

########################### INTERNAL VARIABLES ################################## 
int_mac="$host_mac"         # internal mac address of interface 1
int_mac2="$host_mac2"       # internal mac address of interface 2 
int_ip1="$host_ip"          # internal ip address of interface 1  
int_ip2="$host_ip2"         # internal ip address of interface 2
int_ip1v6="$host_ip1v6"     # internal ipv6 address of interface 1
int_ip2v6="$host_ip2v6"     # internal ipv6 address of interface 2

#######################################################################################
######################      FLUSH OLD RULES     #######################################
iptables -F                   # Flush Rules
iptables -F -t mangle         # Flush table mangle
iptables -X -t mangle         # Delete table mangle from chains
iptables -F -t nat            # Flush table nat 
iptables -X -t nat            # Delete chain table raw 
iptables -F -t raw            # Flush table raw
iptables -X -t raw            # Delete chain table nat 
iptables -F -t security       # Flush table security 
iptables -X -t security       # Delete chain table security 
iptables -X                   # Delete chains 
iptables -Z                   # Reset counter

ip6tables -F                  # Flush Rules
ip6tables -F -t mangle        # Flush table mangle
ip6tables -X -t mangle        # Delete table mangle from chains
ip6tables -F -t raw           # Flush table raw
ip6tables -X -t raw           # Delete table raw from chains
ip6tables -F -t security      # Flush table security
ip6tables -X -t security      # Delete table security from chains
ip6tables -X                  # Delete Chains
ip6tables -Z                  # Reset Counter

###########################     DEFUALT POLICY      ##########################################
iptables -P INPUT   DROP 
iptables -P FORWARD DROP
iptables -P OUTPUT  DROP

ip6tables -P INPUT   DROP 
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT  DROP
############################   DEFINE CUSTOM CHAINS    ###############################################
iptables -N LnD			# Define custom DROP chain

iptables -A LnD -p tcp -m limit --limit 1/s -j LOG --log-prefix "[TCP drop] " 
iptables -A LnD -p udp -m limit --limit 1/s -j LOG --log-prefix "[UDP drop] " 
iptables -A LnD -p icmp -m limit --limit 1/s -j LOG --log-prefix "[ICMP drop] " 
iptables -A LnD -f -m limit --limit 1/s -j LOG --log-prefix "[FRAG drop] " 
iptables -A LnD -j DROP

iptables -N LnR			# Define custom REJECT chain

iptables -A LnR -p tcp -m limit --limit 1/s -j LOG --log-prefix "[TCP reject] " 
iptables -A LnR -p udp -m limit --limit 1/s -j LOG --log-prefix "[UDP reject] " 
iptables -A LnR -p icmp -m limit --limit 1/s -j LOG --log-prefix "[ICMP reject] " 
iptables -A LnR -f -m limit --limit 1/s -j LOG --log-prefix "[FRAG reject] " 
iptables -A LnR -j REJECT 

ip6tables -N LnD	        # Define custom DROP chain
ip6tables -A LnD -p tcp -m limit --limit 1/s -j LOG --log-prefix "[TCP drop] " 
ip6tables -A LnD -p udp -m limit --limit 1/s -j LOG --log-prefix "[UDP drop] " 
ip6tables -A LnD -p icmp -m limit --limit 1/s -j LOG --log-prefix "[ICMP drop] " 
ip6tables -A LnD -j DROP

ip6tables -N LnR		# Define custom REJECT chain
ip6tables -A LnR -p tcp -m limit --limit 1/s -j LOG --log-prefix "[TCP reject] " 
ip6tables -A LnR -p udp -m limit --limit 1/s -j LOG --log-prefix "[UDP reject] " 
ip6tables -A LnR -p icmp -m limit --limit 1/s -j LOG --log-prefix "[ICMP reject] " 
ip6tables -A LnR -j REJECT 

####################################################################################
#                   BASIC FIRST LINE SECURITY
####################################################################################
echo "LOADING FIRST LINE SECURITY"
################ DROP BAD FLAG COMBINATIONS #######################################

iptables -A INPUT -p tcp -m conntrack --ctstate INVALID -j LnD

iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN,RST,ACK,SYN -m state --state NEW -j REJECT --reject-with tcp-reset
iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK,SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset

ip6tables -A INPUT -p tcp -m conntrack --ctstate INVALID -j LnD

ip6tables -A INPUT -p tcp --tcp-flags ALL SYN,ACK,SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -p tcp --tcp-flags ALL FIN,SYN,RST,ACK,SYN -m state --state NEW -j REJECT --reject-with tcp-reset

######################       XMAS      ####################################

iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LnD
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LnD
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LnD
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LnD

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LnD
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LnD
iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j LnD
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j LnD
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LnD
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j LnD
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j LnD
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j LnD
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j LnD
###############
ip6tables -A INPUT -p tcp --tcp-flags ALL ALL -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ALL NONE -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LnD

ip6tables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LnD
ip6tables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LnD
ip6tables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j LnD
ip6tables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j LnD
ip6tables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LnD
ip6tables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j LnD
ip6tables -A INPUT -p tcp --tcp-flags ACK,URG URG -j LnD

######################   SYN FLOOD    ############################################
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -p tcp ! --syn -m state --state NEW -j REJECT --reject-with tcp-reset
###################### Prevent DoS attack ##########################################
#iptables -A INPUT -p tcp --dport 25 -m limit --limit 40/minute --limit-burst 80 -j ACCEPT
#ip6tables -A INPUT -p tcp --dport 25 -m limit --limit 40/minute --limit-burst 80 -j ACCEPT
#################     DROP BROADCAST   ###############################################
iptables -A INPUT  -i $int_if -d 255.255.255.255 -j DROP
iptables -A INPUT  -i $int_if -d 192.168.255.255 -j DROP
iptables -A INPUT  -i $int_if -d 192.168.0.255   -j DROP
iptables -A INPUT  -i $int_if -d 153.122.255.255 -j DROP
iptables -A INPUT  -i $int_if -d 153.122.1.255   -j DROP
iptables -A INPUT  -i $int_if -d 172.2.255.255 -j DROP
iptables -A INPUT  -i $int_if -d 172.2.1.255   -j DROP
# comment out if you want to accept broadcast from your router

#################### DROP MULTICAST/BROADCAST ###############################################
iptables -A INPUT  -s 224.0.0.0/4    -j LnD
iptables -A OUTPUT -d 224.0.0.0/4    -j LnD
iptables -A INPUT  -s 240.0.0.0/4    -j LnD
iptables -A OUTPUT -d 240.0.0.0/4    -j LnD

# comment out if you want to accept multicast or broadcast
#####################  DROP ASSUMED ATTACKERS   #####################################################
iptables -A INPUT -m recent --rcheck --seconds 60 -m limit --limit 10/second -j LOG --log-prefix "BG "
iptables -A INPUT -m recent --update --seconds 60 -j DROP
ip6tables -A INPUT -m recent --rcheck --seconds 60 -m limit --limit 10/second -j LOG --log-prefix "BG "
ip6tables -A INPUT -m recent --update --seconds 60 -j DROP

# this rule places any input source ip making over 10 connections/second into a watch list
# if this ip is still in the watch list after 60 seconds then it is dropped

#######################  DROP INTERNAL HOST IP INPUT SPOOFING    ####################################
#iptables -A INPUT    -i $int_if -s "$int_ip1" -m recent --set -j LnD
#iptables -A FORWARD  -i $int_if -s "$int_ip1" -m recent --set -j LnD
#iptables -A INPUT    -i $int_if -s "$int_ip2" -m recent --set -j LnD
#iptables -A FORWARD  -i $int_if -s "$int_ip2" -m recent --set -j LnD
### this rule may prevent you from seeing your own hosted website from the same computer
### comment these lines out if this affects your ability to see your own website from the host.

######################      DROP OTHER LAN SPOOFING         ############################################
# comment these lines out if they cause a problem

#######################################################################################################################
#                     DROP RESTRICTED SPECIAL USE IPv4 NETWORKS / IP SPOOFING
#######################################################################################################################
############################# DROP LINK-LOCAL ADDRESSES #############################################################
iptables -A INPUT  -s 169.254.0.0/16  -j LnD
iptables -A INPUT  -d 169.254.0.0/16  -j LnD
############################### DROP OUTBOUND BROADCAST ##########################################################
iptables -A OUTPUT -d 255.255.255.255 -j LnD

#####################  DROP PRIVATE LAN INPUT OF WRONG CLASS/TYPE      ########################################## 
#iptables -A INPUT  -s 10.0.0.0/8     -j LnD
#iptables -A INPUT  -s 172.16.0.0/12  -j LnD
#iptables -A INPUT  -s 192.168.0.0/16 -j LnD
# uncomment private lan network classss that are not not applicable to your network to drop them
# use an if statement to check gateway ip against 10,172,192 (not implemented currently)
#

echo "FIRST LINE SECURITY LOADED"
#####################################################################################################
#                               LOCAL HOST RULES  
#####################################################################################################
echo "LOADING LOCALHOST RULES"
#####################################   BOOTP    #############################################
iptables -A INPUT  -i lo  -p udp -m multiport --dports 67,68 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 67,68 -j ACCEPT
iptables -A OUTPUT  -o lo  -p udp -m multiport --dports 67,68 -j ACCEPT
iptables -A OUTPUT  -o lo  -p udp -m multiport --sports 67,68 -j ACCEPT

##################################  DNS   #################################################
iptables -A INPUT  -i lo  -p udp -m multiport --dports 53,953 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 53,953 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 53,953 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 53,953 -j ACCEPT

iptables -A INPUT  -i lo  -p tcp -m multiport --dports 53,953 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 53,953 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 53,953 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 53,953 -j ACCEPT

ip6tables -A INPUT  -i lo -p udp -m multiport --sports 53,953 -j ACCEPT
ip6tables -A INPUT  -i lo -p udp -m multiport --dports 53,953 -j ACCEPT
ip6tables -A OUTPUT -o lo -p udp -m multiport --sports 53,953 -j ACCEPT
ip6tables -A OUTPUT -o lo -p udp -m multiport --dports 53,953 -j ACCEPT

ip6tables -A INPUT  -i lo -p tcp -m multiport --sports 53,953 -j ACCEPT
ip6tables -A INPUT  -i lo -p tcp -m multiport --dports 53,953 -j ACCEPT
ip6tables -A OUTPUT -o lo -p tcp -m multiport --sports 53,953 -j ACCEPT
ip6tables -A OUTPUT -o lo -p tcp -m multiport --dports 53,953 -j ACCEPT

########################### TELNET SSH  ###########################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 22,23 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 22,23 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 22,23 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 22,23 -j ACCEPT
########################### SMTP ###################################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 25,587,465 -m limit --limit 10/second --limit-burst 12 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 25,587,465 -m limit --limit 10/second --limit-burst 12 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 25,587,465 -m limit --limit 10/second  --limit-burst 12 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 25,587,465 -m limit --limit 10/second --limit-burst 12 -j ACCEPT

ip6tables -A INPUT  -i lo  -p tcp -m multiport --dports 25,587,465 -m limit --limit 10/second  --limit-burst 12 -j ACCEPT
ip6tables -A INPUT  -i lo  -p tcp -m multiport --sports 25,587,465 -m limit --limit 10/second  --limit-burst 12 -j ACCEPT
ip6tables -A OUTPUT -o lo  -p tcp -m multiport --dports 25,587,465 -m limit --limit 10/second  --limit-burst 12 -j ACCEPT
ip6tables -A OUTPUT -o lo  -p tcp -m multiport --sports 25,587,465 -m limit --limit 10/second  --limit-burst 12 -j ACCEPT
############################ FTP ########################################################################################
iptables -A INPUT  -i lo -p tcp -m multiport --dports 20,21,989,990,2121 -j ACCEPT
iptables -A INPUT  -i lo -p tcp -m multiport --sports 20,21,989,990,2121 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m multiport --dports 20,21,989,990,2121 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m multiport --sports 20,21,989,990,2121 -j ACCEPT

iptables -A INPUT  -i lo  -p udp -m multiport --dports 20,21,989,990,2121 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 20,21,989,990,2121 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 20,21,989,990,2121 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 20,21,989,990,2121 -j ACCEPT

########################### HTTP,HTTPS ############################################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 80,443  -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 80,443  -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 80,443 -j ACCEPT

ip6tables -A INPUT  -i lo  -p tcp -m multiport --dports 80,443  -j ACCEPT
ip6tables -A INPUT  -i lo  -p tcp -m multiport --sports 80,443  -j ACCEPT
ip6tables -A OUTPUT -o lo  -p tcp -m multiport --dports 80,443  -j ACCEPT
ip6tables -A OUTPUT -o lo  -p tcp -m multiport --sports 80,443  -j ACCEPT
############################ IMAP,IMAPS #############################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 143,993  -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 143,993  -j  ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 143,993  -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 143,993  -j  ACCEPT

################################ POP3,POP3S  ################################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 110,995  -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 110,995  -j  ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 110,995  -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 110,995  -j  ACCEPT

############################# SPAM ASSASSIN #####################################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 783 -j ACCEPT 
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 783 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 783 -j ACCEPT 
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 783 -j ACCEPT

####################################     IRC         #####################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 6667,6668,6669,6697,9999 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 6667,6668,6669,6697,9999 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 6667,6668,6669,6697,9999 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 6667,6668,6669,6697,9999 -j ACCEPT

#################################### XMPP MSN ICQ AOL #####################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 1863,5190,5222,5223,5269,5280,5281,5298,5582,8010 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 1863,5190,5222,5223,5269,5280,5281,5298,5582,8010 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 1863,5190,5222,5223,5269,5280,5281,5298,5582,8010 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 1863,5190,5222,5223,5269,5280,5281,5298,5582,8010 -j ACCEPT

iptables -A INPUT  -i lo  -p udp -m multiport --dports 5298 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 5298 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 5298 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 5298 -j ACCEPT

############################### NNTP #####################################################
iptables -A INPUT  -i lo  -p udp -m multiport --dports 119,563 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 119,563 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 119,563 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 119,563 -j ACCEPT

iptables -A INPUT  -i lo  -p tcp -m multiport --dports 119,563 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 119,563 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 119,563 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 119,563 -j ACCEPT

###################################  HKP PGP ##########################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 11371 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 11371 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 11371 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 11371 -j ACCEPT

####################################  TOR #############################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 9040,9050,9051,9150,9151,9001 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 9040,9050,9051,9150,9151,9001 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 9040,9050,9051,9150,9151,9001 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 9040,9050,9051,9150,9151,9001 -j ACCEPT

###################################  LDAP  ############################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 389 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 389 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 389 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 389 -j ACCEPT

iptables -A INPUT  -i lo  -p udp -m multiport --dports 389 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 389 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 389 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 389 -j ACCEPT

###################################### BIT TORRENT #####################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 6886,6887,6888,6889,6890 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --dports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 6886,6887,6888,6889,6890 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 6880,6881,6882,6883,6884,6885,6969 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 6886,6887,6888,6889,6890 -j ACCEPT

#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 6897,6898,6899,6900,6901 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --dports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 6897,6898,6899,6900,6901 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 6891,6891,6892,6893,6894,6895,6896 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 6897,6898,6899,6900,6901 -j ACCEPT

################################### BIT TORRENT TRACKERS #####################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 58846,2710,7000 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 58846,2710,7000 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 58846,2710,7000 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 58846,2710,7000 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 3000,4444,6969,1337,2710,80 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 3000,4444,6969,1337,2710,80 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 3000,4444,6969,1337,2710,80 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 3000,4444,6969,1337,2710,80 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 30301,4444,80 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 30301,4444,80 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 30301,4444,80 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 30301,4444,80 -j ACCEPT

#################################### SQUID HTTP ALTERNATE ###########################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 3128,8000,8080,8082,8445,8123,8443 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 3128,8000,8080,8082,8445,8123,8443 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 3128,8000,8080,8082,8445,8123,8443 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 3128,8000,8080,8082,8445,8123,8443 -j ACCEPT
#################################### SOCKS 4/5  #########################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 1080,1085 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 1080,1085 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 1080,1085 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 1080,1085 -j ACCEPT
################################## NETBIOS  #########################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 135,137,138,139 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 135,137,138,139 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 135,137,138,139 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 135,137,138,139 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 135,137,138,139 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 135,137,138,139 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 135,137,138,139 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 135,137,138,139 -j ACCEPT

################################### SMB SAMBA #######################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 445 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 445 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 445 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 445 -j ACCEPT
##############################  PULSE AUDIO SERVER
#iptables -A INPUT   -i lo  -p tcp -m multiport --dports 4713 -j ACCEPT
#iptables -A INPUT   -i lo  -p tcp -m multiport --sports 4713 -j ACCEPT
#iptables -A OUTPUT  -o lo  -p tcp -m multiport --dports 4713 -j ACCEPT
#iptables -A OUTPUT  -o lo  -p tcp -m multiport --sports 4713 -j ACCEPT
###############################  CUPS ################################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 631 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 631 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 631 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 631 -j ACCEPT

iptables -A INPUT  -i lo  -p udp -m multiport --dports 631 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 631 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 631 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 631 -j ACCEPT
################################### GIT HUB ##########################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 9418 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 9418 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 9418 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 9418 -j ACCEPT
######################## ICMP ########################################################################
iptables -A INPUT  -i lo  -p icmp --icmp-type ping -m limit --limit 1/second -j ACCEPT
iptables -A OUTPUT -o lo  -p icmp --icmp-type ping -m limit --limit 2/second -j ACCEPT

iptables -A INPUT  -i lo  -p icmp --icmp-type 0 -m limit --limit 1/second -j ACCEPT
iptables -A OUTPUT -o lo  -p icmp --icmp-type 0 -m limit --limit 2/second -j ACCEPT
iptables -A INPUT  -i lo  -p icmp --icmp-type 3 -m limit --limit 1/second -j ACCEPT
iptables -A OUTPUT -o lo  -p icmp --icmp-type 3 -m limit --limit 2/second -j ACCEPT
iptables -A INPUT  -i lo  -p icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT
iptables -A OUTPUT -o lo  -p icmp --icmp-type 8 -m limit --limit 2/second -j ACCEPT
iptables -A INPUT  -i lo  -p icmp --icmp-type 11 -m limit --limit 1/second -j ACCEPT
iptables -A OUTPUT -o lo  -p icmp --icmp-type 11 -m limit --limit 2/second -j ACCEPT

ip6tables -A INPUT  -i lo  -p icmp -m limit --limit 1/second -j ACCEPT
ip6tables -A OUTPUT -o lo  -p icmp -m limit --limit 2/second -j ACCEPT

############################## SYSLOG ###############################################
iptables -A INPUT  -i lo  -p udp -m multiport --dports 514 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 514 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 514 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 514 -j ACCEPT

iptables -A INPUT  -i lo -p tcp -m multiport --dports 514 -j ACCEPT
iptables -A INPUT  -i lo -p tcp -m multiport --sports 514 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m multiport --dports 514 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m multiport --sports 514 -j ACCEPT

############################## RELP LOG ###############################################
#iptables -A INPUT  -i lo  -p udp -m multiport --dports 2514 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 2514 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 2514 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 2514 -j ACCEPT

#iptables -A INPUT  -i lo -p tcp -m multiport --dports 2514 -j ACCEPT
#iptables -A INPUT  -i lo -p tcp -m multiport --sports 2514 -j ACCEPT
#iptables -A OUTPUT -o lo -p tcp -m multiport --dports 2514 -j ACCEPT
#iptables -A OUTPUT -o lo -p tcp -m multiport --sports 2514 -j ACCEPT

############################### NTP #####################################################
iptables -A INPUT  -i lo  -p udp -m multiport --dports 123 -j ACCEPT
iptables -A INPUT  -i lo  -p udp -m multiport --sports 123 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --dports 123 -j ACCEPT
iptables -A OUTPUT -o lo  -p udp -m multiport --sports 123 -j ACCEPT

iptables -A INPUT  -i lo  -p tcp -m multiport --dports 123 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 123 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 123 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 123 -j ACCEPT

################################ RCP   #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 111 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 111 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 111 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 111 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 111 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 111 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 111 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 111 -j ACCEPT

################################ RSYNC   #################################################
iptables -A INPUT  -i lo  -p tcp -m multiport --dports 873 -j ACCEPT
iptables -A INPUT  -i lo  -p tcp -m multiport --sports 873 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 873 -j ACCEPT
iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 873 -j ACCEPT

################################ OPEN VPN  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 1194 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 1194 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 1194 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 1194 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 1194 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 1194 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 1194 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 1194 -j ACCEPT

################################  NFS  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 2049 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 2049 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 2049 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 2049 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 2049 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 2049 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 2049 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 2049 -j ACCEPT

################################  FREENET  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 8888 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 8888 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 8888 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 8888 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 12701,29732 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 12701,29732 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 12701,29732 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 12701,29732 -j ACCEPT

################################  GNU NET  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 2086 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 2086 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 2086 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 2086 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 2086 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 2086 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 2086 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 2086 -j ACCEPT

################################  I2P  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 2827,4444,4445,7652,7653,7654,7656,7657,7658,7659,7660,19648 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 2827,4444,4445,7652,7653,7654,7656,7657,7658,7659,7660,19648 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 2827,4444,4445,7652,7653,7654,7656,7657,7658,7659,7660,19648 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 2827,4444,4445,7652,7653,7654,7656,7657,7658,7659,7660,19648 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 7655,19648 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 7655,19648 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 7655,19648 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 7655,19648 -j ACCEPT

############################### IPsec #################################################
#iptables -A INPUT  -i lo  -p udp -m multiport --dports 4500 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 4500 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 4500 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 4500 -j ACCEPT

################################  SIP  #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 5060,5061 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 5060,5061 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 5060,5061 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 5060,5061 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 5060 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 5060 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 5060 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 5060 -j ACCEPT

################################  BITMESSAGE #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 8444 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 8444 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 8444 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 8444 -j ACCEPT


################################  BITCOIN #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 8332,8333 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 8332,8333 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 8332,8333 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 8332,8333 -j ACCEPT

################################  LITECOIN #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 9332,9333 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 9332,9333 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 9332,9333 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 9332,9333 -j ACCEPT

################################  GOOGLE TALK #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 19294 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 19294 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 19294 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 19294 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 19295,19302 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 19295,19302 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 19295,19302 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 19295,19302 -j ACCEPT

################################  SKYPE #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 23399 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 23399 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 23399 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 23399 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 23399 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 23399 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 23339 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 23399 -j ACCEPT

################################  MYSQL #################################################
#iptables -A INPUT  -i lo  -p tcp -m multiport --dports 25565 -j ACCEPT
#iptables -A INPUT  -i lo  -p tcp -m multiport --sports 25565 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --dports 25565 -j ACCEPT
#iptables -A OUTPUT -o lo  -p tcp -m multiport --sports 25565 -j ACCEPT

#iptables -A INPUT  -i lo  -p udp -m multiport --dports 25565 -j ACCEPT
#iptables -A INPUT  -i lo  -p udp -m multiport --sports 25565 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --dports 25565 -j ACCEPT
#iptables -A OUTPUT -o lo  -p udp -m multiport --sports 25565 -j ACCEPT

############################ LOCAL HOST DROP ############################################## 
# NO FURTHER INPUT/OUTPUT FROM LOCALHOST / SOURCE HOSTS
iptables -A INPUT  -s 127.0.0.0/8    -j LnD
iptables -A OUTPUT -d 127.0.0.0/8    -j LnD
iptables -A INPUT  -s 0.0.0.0/8      -j LnD
iptables -A OUTPUT -d 0.0.0.0/8      -j LnD

iptables -A INPUT    -i lo  -j LnD
iptables -A OUTPUT   -o lo  -j LnD
iptables -A FORWARD  -i lo  -j LnD
iptables -A FORWARD  -o lo  -j LnD

ip6tables -A INPUT    -i lo  -j LnD
ip6tables -A OUTPUT   -o lo  -j LnD
ip6tables -A FORWARD  -i lo  -j LnD
ip6tables -A FORWARD  -o lo  -j LnD

## comment out if problematic (under review)
###########################################################################################

echo "LOCALHOST RULES LOADED"
###########################################################################################

################################################################################################
#                         Router and Internal Network Rules
###################################################################################################
#
#                    REMOVED /ADD YOUR OWN according to your needs  sshd etc
#
#
##############################################################################################################################
#                      Application and Port Specific Rules for INTERNET 
##############################################################################################################################
#                                       PUBLIC OUTPUT
#############################################################################################################################################
echo "LOADING PUBLIC OUTPUT CLIENTS"
##################################################   HTTP HTTPS Client    ###############################################################################  
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 80,443 -m state --state ESTABLISHED -j ACCEPT

ip6tables -A OUTPUT  -o $int_if -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT 
ip6tables -A INPUT   -i $int_if -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT  -o $int_if -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT   -i $int_if -p tcp -m multiport --dports 80,443 -m state --state ESTABLISHED -j ACCEPT
##################################################      HKP OPEN PGP SERVER CLIENT       ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 11371 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 11371 -m state --state ESTABLISHED -j ACCEPT
##################################################      RSYNC CLIENT  #######################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 873 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 873 -m state --state ESTABLISHED -j ACCEPT
##################################################      HTTPS PROXY       ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 8081,8000,8080,8090,8443,8445,9090 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 8081,8000,8080,8090,8443,8445,9090 -m state --state ESTABLISHED,RELATED -j ACCEPT
#################################################  SQUID HTTPS PROXY  ################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 3128,8321 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 3128,8321 -m state --state ESTABLISHED -j ACCEPT
##########################################        SOCK4,SOCK5 Client    ##################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 1080,1085 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 1080,1085 -m state --state ESTABLISHED -j ACCEPT
##########################################         IRC Client           ###################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 6667,6668,6669,6697,9999 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 6667,6668,6669,6697,9999 -m state --state ESTABLISHED -j ACCEPT
##########################################        XMPP Client           ###################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 5190,5222,5223,5269,5280,5281,5298,8010 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 5190,5222,5223,5269,5280,5281,5298,8010 -m state --state ESTABLISHED -j ACCEPT

iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 5298 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 5298 -m state --state ESTABLISHED -j ACCEPT
##########################################       MSN Client           ###################################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 1863 -m state  --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 1863 -m state --state ESTABLISHED -j ACCEPT

##########################################         FTP Client           ###################################################################################
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 20,21,989,990,2121 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 20,21,989,990,2121 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p udp -m multiport --dports 20,21,989,990,2121 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p udp -m multiport --sports 20,21,989,990,2121 -m state --state ESTABLISHED -j ACCEPT
##########################################         NNTP Client           ###################################################################################
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 119,563 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 119,563 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p udp -m multiport --dports 119,563 -m state  --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p udp -m multiport --sports 119,563 -m state --state ESTABLISHED -j ACCEPT
##########################################        TELNET  Client        ####################################################################################
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 23 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 23 -m state --state ESTABLISHED -j ACCEPT
###########################################        SSH  Client          ##################################################################################
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 22 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 22 -m state --state ESTABLISHED -j ACCEPT
#############################################       SMTP  Client        #####################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 25,465,587,2525  -m limit --limit 5/second --limit-burst 10 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 25,465,587,2525  -m limit --limit 5/second --limit-burst 10 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT

ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --dports 25,465,587,2525  -m limit --limit 5/second --limit-burst 10 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p tcp -m multiport --sports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --sports 25,465,587,2525  -m limit --limit 5/second --limit-burst 10 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p tcp -m multiport --dports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT

##########################################         POP3  Client          ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 110,995 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 110,995 -m state --state ESTABLISHED -j ACCEPT
##########################################         IMAP  Client        ###################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 143,993 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 143,993 -m state --state ESTABLISHED -j ACCEPT
########################################          DNS   Client        #######################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 53,953 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 53,953 -m state --state ESTABLISHED -j ACCEPT

iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 53,953 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 53,953 -m state --state ESTABLISHED -j ACCEPT

ip6tables -A OUTPUT -o $int_if -p udp -m multiport --dports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p udp -m multiport --sports 53,953 -m state --state ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -o $int_if -p udp -m multiport --sports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p udp -m multiport --dports 53,953 -m state --state ESTABLISHED -j ACCEPT

ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --dports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p tcp -m multiport --sports 53,953 -m state --state ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --sports 53,953 -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT  -i $int_if -p tcp -m multiport --dports 53,953 -m state --state ESTABLISHED -j ACCEPT

#######################################            BOOTP  Client       #######################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -d "$gateway_ip" -p udp -m multiport --dports 67,68 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -s "$gateway_ip" -p udp -m multiport --sports 67,68 -m state --state ESTABLISHED -j ACCEPT
##########################################         NTP   Client        ##########################################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 123 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 123 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 123 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 123 -m state --state ESTABLISHED -j ACCEPT

###########################################        ICMP Ping         ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p icmp --icmp-type ping  -m state --state NEW,ESTABLISHED -j ACCEPT 
iptables -A INPUT  -i $int_if -d "$int_ip1" -p icmp --icmp-type ping  -m state --state ESTABLISHED -j ACCEPT

# echo reply from ping
iptables -A INPUT  -i $int_if -d "$int_ip1" -p icmp --icmp-type 0  -m state --state ESTABLISHED -j ACCEPT
# rejection messages
iptables -A INPUT  -i $int_if -d "$int_ip1" -p icmp --icmp-type 3  -m state --state ESTABLISHED -j ACCEPT
# time out signal
iptables -A INPUT  -i $int_if -d "$int_ip1" -p icmp --icmp-type 11 -m state --state ESTABLISHED -j ACCEPT
# echo request from ping
iptables -A INPUT  -i $int_if -d "$int_ip1" -p icmp --icmp-type 8  -m limit --limit 1/second -m state --state ESTABLISHED -j ACCEPT

## comment out if you wish to block ipv6 icmp (ping etc)
ip6tables -A OUTPUT -o $int_if -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT 
ip6tables -A INPUT  -i $int_if -p icmp -m state --state ESTABLISHED -j ACCEPT

##########################################    SPECIALIZED OUTPUT   #########################################################################################
##########################################        GIT Client        ####################################################################################
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 9418 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 9418 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT  -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 9418 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT   -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 9418 -m state --state ESTABLISHED -j ACCEPT
##########################################       TOR  Client        ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 9001,9040,9050,9051,9150,9151 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 9001,9040,9050,9051,9150,9151 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 9001,9040,9050,9051,9150,9151 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 9001,9040,9050,9051,9150,9151 -m state --state ESTABLISHED -j ACCEPT
##########################################      BitTorrent  Client     #########################################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 2710,6881,6887,6888,6889,6890,6969 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 2710,6881,6887,6888,6889,6890,6969 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 2710,6881,6887,6888,6889,6890,6969 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 2710,6881,6887,6888,6889,6890,6969 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 6969,2710,4444,1337,80 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 6969,2710,4444,1337,80 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 6969,2710,4444,1337,80 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 6969,2710,4444,1337,80 -m state --state ESTABLISHED -j ACCEPT

##########################################       NETBIOS  Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 135,137,138,139 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 135,137,138,139 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 135,137,138,139 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 135,137,138,139 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 135,137,138,139 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 135,137,138,139 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 135,137,138,139 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 135,137,138,139 -m state --state ESTABLISHED -j ACCEPT
##########################################        SMB   Client      ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 445 -m state --state NEW,ESTABLISHED-j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 445 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 445 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 445 -m state --state ESTABLISHED -j ACCEPT

##########################################        CUPS   Client     ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 631 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 631 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 631 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 631 -m state --state ESTABLISHED -j ACCEPT
#
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 631 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 631 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 631 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 631 -m state --state ESTABLISHED -j ACCEPT

##########################################       PULSE AUDIO  Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 4713 -m state --state NEW,ESTABLISHED, -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 4713 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 4713 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 4713 -m state --state ESTABLISHED -j ACCEPT

##########################################       LDAP  Client   ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 389 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 389 -m state --state ESTABLISHED -j ACCEPT

iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 389 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 389 -m state --state ESTABLISHED -j ACCEPT

##########################################       OPEN VPN  Client   ###############################################################################
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 1194 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 1194 -m state --state ESTABLISHED -j ACCEPT

iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 1194 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 1194 -m state --state ESTABLISHED -j ACCEPT

##########################################       NFS Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 2049 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 2049 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 2049 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 2049 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 2049 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 2049 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 2049 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 2049 -m state --state ESTABLISHED -j ACCEPT

##########################################       MYSQL Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 25565 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 25565 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 25565 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 25565 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 25565 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 25565 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 25565 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 25565 -m state --state ESTABLISHED -j ACCEPT

##########################################         FREENET  Client     #########################################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 8888 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 8888 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 8888 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 8888 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 12701,29732 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 12701,29732 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 12701,29732 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 12701,29732 -m state --state ESTABLISHED -j ACCEPT

##########################################       GNU NET Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 2086 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 2086 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 2086 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 2086 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 2086 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 2086 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 2086 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 2086 -m state --state ESTABLISHED -j ACCEPT

##########################################       I2P Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 7655,19648 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 7655,19648 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 7655,19648 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 7655,19648 -m state --state ESTABLISHED -j ACCEPT

##########################################     IPsec Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 4500 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 4500 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 4500 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 4500 -m state --state ESTABLISHED -j ACCEPT

##########################################      SIP   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 5060,5061 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 5060,5061 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 5060,5061 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 5060,5061 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 5060 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 5060 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 5060 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 5060 -m state --state ESTABLISHED -j ACCEPT

##########################################      BITCOIN Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 8332,8333 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 8332,8333 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 8332,8333 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 8332,8333 -m state --state ESTABLISHED -j ACCEPT

##########################################      LITECOIN Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 9332,9333  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 9332,9333  -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 9332,9333  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 9332,9333  -m state --state ESTABLISHED -j ACCEPT

##########################################      BITMESSAGE Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 8444 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 8444 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 8444 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 8444 -m state --state ESTABLISHED -j ACCEPT

##########################################       GOOGLE TALK Client   ###############################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 19294 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 19294 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 19294 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 19294 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 19295,19302 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 19295,19302 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 19295,19302 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 19295,19302 -m state --state ESTABLISHED -j ACCEPT

##########################################     SKYPE Client        ###########################################################################
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --dports 23399 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --sports 23399 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 23399 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 23399 -m state --state ESTABLISHED -j ACCEPT

#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --dports 23399 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --sports 23399 -m state --state ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 23399 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 23399 -m state --state ESTABLISHED -j ACCEPT

###########################################################################################################################################################

echo "LOADING PUBLIC SERVER INPUTS"
#########################################################################################################################
#                                           PUBLIC  INPUTS
#########################################################################################################################
###################################            NTP SERVER        ############################################################### 
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp  -m multiport --dports 123 -m state --state NEW,ESTABLISHED  -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp  -m multiport --sports 123 -m state --state ESTABLISHED  -j ACCEPT 
###################################            NNTP SERVER        ############################################################### 
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp  -m multiport --dports 119,563 -m state --state NEW,ESTABLISHED  -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp  -m multiport --sports 119,563 -m state --state ESTABLISHED  -j ACCEPT 
###################################           SMTP SERVER             #####################################################################################################
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 25,465,587,2525 -m limit --limit 10/s --limit-burst 12 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 25,465,587,2525 -m limit --limit 10/s --limit-burst 12 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 25,465,587,2525 -m state --state ESTABLISHED -j ACCEPT
###################################         POP3 SERVER            ###################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 110,995 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 110,995 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 110,995 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 110,995 -m state --state ESTABLISHED -j ACCEPT
###################################         IMAP4 SERVER            ###################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 143,993 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 143,993 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 143,993 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 143,993 -m state --state ESTABLISHED -j ACCEPT
###################################         TELNET SERVER            ################################################################################################# 
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp  -m multiport --dports 23 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -s "$int_ip1" -m multiport --sports 23 -m state --state ESTABLISHED -j ACCEPT
##################################           SSH SERVER            #################################################################################################### 
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp  -m multiport --dports 22 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -s "$int_ip1" -m multiport --sports 22 -m state --state ESTABLISHED -j ACCEPT
###################################          FTP  SERVER             ##################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp  -m multiport --dports 20,21,2121 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --dports 20,21,2121 -m state --state ESTABLISHED -j ACCEPT
##################################          HTTP HTTPS SERVER        ####################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 80,443 -m state --state ESTABLISHED -j ACCEPT

#ip6tables -A INPUT  -i $int_if -p tcp -m multiport --dports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --sports 80,443 -m state --state ESTABLISHED -j ACCEPT
#ip6tables -A INPUT  -i $int_if -p tcp -m multiport --sports 80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#ip6tables -A OUTPUT -o $int_if -p tcp -m multiport --dports 80,443 -m state --state ESTABLISHED -j ACCEPT
###################################            FREENET  SERVER              ###############################################################################################
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 12701,29732 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 12701,29732 -m state --state ESTABLISHED -j ACCEPT
###################################           BitTorrent  SERVER              ###############################################################################################
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 6880,6881,6882,6883,6884,6885,6886 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 6880,6881,6882,6883,6884,6885,6886 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 6880,6881,6882,6883,6884,6885,6886 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 6880,6881,6882,6883,6884,6885,6886 -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 6891,6892,6893,6894,6895,6896 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 6891,6892,6893,6894,6895,6896 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 6891,6892,6893,6894,6895,6896 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 6891,6892,6893,6894,6895,6896 -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp  --sport 53 --dport 4444 -d "$int_ip1"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 53 --sport 4444 -s "$int_ip1"  -m state --state ESTABLISHED -j ACCEPT

####################################            I2P  SERVER               #####################################################################################################
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 2827,4444,4445,7652,7653,7655,7654,7656,7657,7658,7659,7660,19648 -m state --state ESTABLISHED -j ACCEPT

####################################            TOR SERVER               #####################################################################################################
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p tcp -m multiport --dports 9001,9040,9050,9051,9150,9151 -m state --state NEW,ESTABLISHED -j ACCEPT 
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p tcp -m multiport --sports 9001,9040,9050,9051,9150,9151 -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -d "$int_ip1" -p udp -m multiport --dports 9001,9040,9050,9051,9150,9151 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -s "$int_ip1" -p udp -m multiport --sports 9001,9040,9050,9051,9150,9151 -m state --state ESTABLISHED -j ACCEPT

echo "LOADING INTERNAL LAN SERVER INPUTS"
##############################################################################################################################################################################
#                                 	LOCAL / PRIVATE INPUTS  # mac address bind local clients to hosts
#
#######################################          BOOTP SERVER             ###################################################################################################### 
iptables -A INPUT -i $int_if -s "$gateway_ip" -d "$int_ip1" -p udp -m multiport --dports 67,68 -m mac --mac-source "$gateway_mac" -m state --state NEW,ESTABLISHED -j ACCEPT 
#######################################          SYSLOG SERVER           ########################################################################################################### 
iptables -A INPUT -i $int_if -s "$gateway_ip" -d "$int_ip1" -p udp --sport 514 --dport 514 -m mac --mac-source "$gateway_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#######################################          RELP LOG SERVER ########################################################################################################### 
#iptables -A INPUT -i $int_if -s "$gateway_ip" -d "$int_ip1" -p udp --sport 2514 --dport 2514 -m mac --mac-source "$gateway_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#######################################          DNS SERVER       ######################################################################################################## 
iptables -A INPUT  -i $int_if -p udp  --dport 53 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -p udp  --sport 53 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -p udp  --sport 53 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -p udp  --dport 53 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

iptables -A INPUT  -i $int_if -p tcp  --dport 53 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -p tcp  --sport 53 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT  -i $int_if -p tcp  --sport 53 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $int_if -p tcp  --dport 53 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp  --dport 53 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --sport 53 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  --sport 53 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 53 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  --dport 53 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 53 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --sport 53 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 53 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp  --dport 53 -d "$int_ip1"  -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --sport 53 -s "$int_ip1"  -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  --sport 53 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 53 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  --dport 53 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 53 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --sport 53 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 53 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

###################################         POP3 SERVER            ###################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 110,995 -d "$int_ip1"  -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 110,995 -s "$int_ip1"  -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 110,995 -s "$host_ip"  -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 110,995 -d "$host_ip"  -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 110,995 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 110,995 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 110,995 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 110,995 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 110,995 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 110,995 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 110,995 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 110,995 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

###################################         IMAP4 SERVER            ###################################################################################################### 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 143,993 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 143,993 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 143,993 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 143,993 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 143,993 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 143,993 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 143,993 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 143,993 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 143,993 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 143,993 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 143,993 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 143,993 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

####################################################        SMB SERVER         ##############################################################################################
#iptables -A INPUT  -i $int_if -p tcp  --sport 445 --dport 445 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 445 --sport 445 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 445 --sport 445 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 445 --dport 445 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  --sport 445 --dport 445 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 445 --sport 445 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 445 --sport 445 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 445 --sport 445 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  --sport 445 --dport 445 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source $clinet2_mac -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 445 --sport 445 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 445 --sport 445 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 445 --dport 445 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#######################################################        NETBIOS  SERVER       ##############################################################################################
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 135,137,138,139 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 135,137,138,139 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 135,137,138,139 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 135,137,138,139 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 135,137,138,139 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 135,137,138,139 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 135,137,138,139 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 135,137,138,139 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 135,137,138,139 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 135,137,138,139 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 135,137,138,139 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 135,137,138,139 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 135,137,138,139 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 135,137,138,139 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

####################################################        CUPS SERVER         ##############################################################################################
#iptables -A INPUT  -i $int_if -p udp  --dport 631 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --sport 631 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  --sport 631 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 631 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 631 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 631 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --sport 631 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 631 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp  --dport 631 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --sport 631 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  --sport 631 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 631 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 631 -d "$int_ip1"    -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 631 -s "$int_ip1"    -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --sport 631 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 631 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp  --dport 631 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --sport 631 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  --sport 631 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  --dport 631 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --dport 631 -d "$int_ip1"    -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --sport 631 -s "$int_ip1"    -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  --sport 631 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  --dport 631 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#######################################    LDAP SERVER OPENLDAP  ######################################################################################################## 
#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 389 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 389 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 389 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 389 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 389 -d "$int_ip1" -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 389 -s "$int_ip1" -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 389 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 389 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 389 -d "$int_ip1" -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 389 -s "$int_ip1" -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 389 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 389 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 389 -d "$int_ip1" -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 389 -s "$int_ip1" -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 389 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 389 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp -m multiport --dports 389 -d "$int_ip1" -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --sports 389 -s "$int_ip1" -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp -m multiport --sports 389 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp -m multiport --dports 389 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p udp -m multiport --dports 389 -d "$int_ip1" -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --sports 389 -s "$int_ip1" -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp -m multiport --sports 389 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp -m multiport --dports 389 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#######################################    XMPP SERVER   ######################################################################################################## 
#iptables -A INPUT  -i $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$host_ip" -m mac --mac-source "$host_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$host_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$host_ip" -d "$int_ip1" -m mac --mac-source "$host_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$host_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

####CLIENT 1
#iptables -A INPUT  -i $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$client1_ip" -m mac --mac-source "$client1_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$client1_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$client1_ip" -d "$int_ip1" -m mac --mac-source "$client1_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$client1_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#####CLIENT 2
#iptables -A INPUT  -i $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p udp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac"  -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p udp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#iptables -A INPUT  -i $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$int_ip1"  -s "$client2_ip" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$int_ip1"  -d "$client2_ip" -m state --state ESTABLISHED -j ACCEPT
#iptables -A INPUT  -i $int_if -p tcp  -m multiport --sports 5222,5190,5223,5269,5280,5281,5298,8010 -s "$client2_ip" -d "$int_ip1" -m mac --mac-source "$client2_mac" -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o $int_if -p tcp  -m multiport --dports 5222,5190,5223,5269,5280,5281,5298,8010 -d "$client2_ip" -s "$int_ip1" -m state --state ESTABLISHED -j ACCEPT

#######################################################################################################################
#                                          ICMP INPUT
#######################################################################################################################
# accept ICMP packets (ping et.al.)

iptables -A INPUT -p icmp -j LnD
ip6tables -A INPUT -p icmp -j LnD

########################################################################################################################
#                                          LAN INPUT DROP
#########################################################################################################################
# DROP ANY FURTHER PRIVATE LAN INPUT not specified in internal networking or inputs section
iptables -A INPUT  -s 10.0.0.0/8     -j LnD
iptables -A INPUT  -s 172.16.0.0/12  -j LnD
iptables -A INPUT  -s 192.168.0.0/16 -j LnD

# may be redundent because final log drop comes next

########################################################################################################################
#                                       FINAL LOG DROP  
#######################################################################################################################

# log all the rest before dropping
iptables -A INPUT   -j LOG --log-prefix "IPTables IN Dropped " --log-level=info;
iptables -A INPUT   -j REJECT --reject-with icmp-host-unreachable
iptables -A OUTPUT  -j LOG --log-prefix "IPTables OUT Dropped --log-level=info" ;
iptables -A OUTPUT  -j REJECT --reject-with icmp-host-unreachable
iptables -A FORWARD -j LOG --log-prefix "IPTables FW Dropped --log-level=info" ;
iptables -A FORWARD -j REJECT --reject-with icmp-host-unreachable

ip6tables -A INPUT   -j LOG --log-prefix "IPTables IN Dropped --log-level=info" ; 
ip6tables -A INPUT   -j REJECT 
ip6tables -A OUTPUT  -j LOG --log-prefix "IPTables OUT Dropped --log-level=info" ;
ip6tables -A OUTPUT  -j REJECT 
ip6tables -A FORWARD -j LOG --log-prefix "IPTables FW Dropped --log-level=info" ;
ip6tables -A FORWARD -j REJECT 

##########################################################################################################################
#                                 SAVE RULES
#####################################################################################################################
echo SAVING RULES
# comment out distribution rules that you are not using
#ARCH/PARABOLA
iptables-save  > /etc/iptables/iptables.rules
ip6tables-save > /etc/iptables/ip6tables.rules

#DEBIAN/UBUNTU
iptables-save  > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# RHEL/CENTOS/FEDORA
iptables-save  > /etc/iptables/iptables
ip6tables-save > /etc/iptables/ip6tables

echo "ENDWALL LOADED"
################################  PRINT RULES   ###############################################################
#list the rules
#iptables -L -v
#ip6tables -L -v

#############################   PRINT ADDRESSES  ############################################################
echo "GATEWAY    :          MAC:"$gateway_mac"  IPv4:"$gateway_ip" " 
echo "INTERFACE_1: "$int_if"  MAC:"$int_mac"  IPv4:"$int_ip1" IPv6:"$int_ip1v6" "
echo "INTERFACE_2: "$int_if2"  MAC:"$int_mac2"  IPv4:"$int_ip2"  IPv6:"$int_ip2v6" "
# print the time the script finishes
date
exit 0
