# endwall
A novel Firewall script for iptables, nftables, and pf.


$ ./endwall --help

endwall.sh is the original iptables firewall, and works with endlists.sh, endsets.sh for a full featured firewall system.
endwall_wifi.sh is a version of endwall.sh that allows for wifi interfaces and works well on laptops with wifi
endwall_raspi.sh is an iptables version of endwall_wifi.sh that is tuned for a Rapspberry pi 4 on raspbian 10. 

endwall_nft.sh is a netfilter tables (nft) translation of endwall.sh and has been tested working on Debian 11
endwall_nft_wifi.sh is a wifi branch based on endwall_nft.sh and the design of endwall_wifi.sh
endwall_nft_raspi.sh is a wifi enabled version of endwall_nft_wifi.sh tuned for a Raspberry pi 4 on Raspbian 11. 

Read the headers for operational instruction, which is generally, change permisions to execute, then run the file.  Read the file before running it to make sure it is to your liking. 

# ENDWALL
`$ chmod u+wrx endwall.sh`
`$ ./endwall.sh --help`
`$ ./endwawll.sh      # enable the firewall`
`$ ./endwall.sh --open # disable the firewall`

# ENDWALL PF
`$ chmod u+wrx endwall_pf.sh`
`$./endwall_pf.sh --help`
`$./endwall_pf.sh   # enable the firewall`
`$./endwall_pf.sh -d # deactivate the firewall`

# ENDWALL NFT 
`$ chmod u+wrx endwall_nft.sh`
`$./endwall_nft.sh --help`
`$./endwall_nft.sh   # enable the firewall`
`$./endwall_nft.sh --open # deactivate the firewall`
