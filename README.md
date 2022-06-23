# Endwall
<h2>A novel Firewall script for iptables, nftables, and pf.</h2>

Every computer user that uses the internet should have a default firewall configureation that is safe <br>
Most distributions of GNU-Linux and Unix systems come with no firewall enabled at all! <br>
Begining users may not know what to do and many intro scripts are either too lax and liberal or too convoluted to understand.<br>
Running this script <b>endwall.sh</b> right after system installation gives a new user a strong firewall configuration.<br>
Easily customizable to the user's networking needs as they grow, with the minimal effort of simply editing a text file. <br>
There are several branches available including for <b>iptables</b>, <b>nftables</b> and even <b>OpenBSD PF</b>. <br>
Give it a try, we know you'll like it! <br>

These files, scripts and configurations were developed by <b>Endwall</b>, of the <b>Endware Development Team</b>

<b>endwall.sh</b> is the original iptables firewall, and works with endlists.sh, endsets.sh for a full featured firewall system.<br>
<b>endwall_wifi.sh</b> is a version of endwall.sh that allows for wifi interfaces and works well on laptops with wifi.<br>
<b>endwall_raspi.sh</b> is an iptables version of endwall_wifi.sh that is tuned for a Rapspberry pi 4 on raspbian 10.<br> 

<b>endwall_nft.sh</b> is a netfilter tables (nft) translation of endwall.sh and has been tested working on Debian 11<br>
<b>endwall_nft_wifi.sh</b> is a wifi branch based on endwall_nft.sh and the design of endwall_wifi.sh<br>
<b>endwall_nft_raspi.sh</b> is a wifi enabled version of endwall_nft_wifi.sh tuned for a Raspberry pi 4 on Raspbian 11.<br> 

<b>endwall_pf.sh</b> is a translation of endwall.sh for <b>pf</b> developed and tested on <b>OpenBSD 7.1 </b> , <br>

Read the headers for operational instruction, which is generally, change permisions to execute, then run the file.  Read the file before running it to make sure it is to your liking. 

$ ./endwall.sh --help

# ENDWALL
`$ chmod u+wrx endwall.sh` <br>
`$ ./endwall.sh --help` <br>
`$ ./endwawll.sh      # enable the firewall` <br>
`$ ./endwall.sh --open # disable the firewall`<br>

# ENDWALL PF
`$ chmod u+wrx endwall_pf.sh`<br>
`$./endwall_pf.sh --help` <br>
`$./endwall_pf.sh   # enable the firewall` <br>
`$./endwall_pf.sh -d # deactivate the firewall`<br>

# ENDWALL NFT 
`$ chmod u+wrx endwall_nft.sh` <br>
`$./endwall_nft.sh --help` <br>
`$./endwall_nft.sh   # enable the firewall` <br>
`$./endwall_nft.sh --open # deactivate the firewall` <br>
