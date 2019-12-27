# CyberSecTK-Library
 Cyber Security feature extraction python library 
 
 ################### WLAN IOT ########################

 Library function name : wiot()
 
 ################### TCP IOT #########################

Library function name : iot()

A python dictionary ip_filter {} is used to filter device specific TCP PCAP files in filtered_pcap directory.

Available Dictionary ip_filter keys
TCP_Mobile

TCP_Outlet

TCP_Assistant

TCP_Camera

TCP_Miscellaneous

Dictionary key value pair example:

ip_filter['TCP_Miscellaneous'] = "'tcp && (ip.src==192.168.1.216) || (ip.src==192.168.1.46) || (ip.src==192.168.1.84) \
                     || (ip.src==192.168.1.91)'"

Please update dictionary key and value. 

Example: ip_filter {} 

ip_filter['TCP_Miscellaneous'] = "'tcp && (ip.src==IP_Address)'"
         
iot (**ip_filter)

##########################################################
