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

NOTE: We need to create two different directories original_pcap and filtered_pcap on a working directory. The source iot pcap file need to be available inside the original_pcap directory. 
The library uses tshark to extract the features from the given TCP pcap file. Make sure tshark is installed on your system.  

####################### MALEWARE ###########################

Library function name : malware()

Note: Please make sure to creat directory "log_files" on a same working directory and add the Good and infected CSV log files inside for feature extraction. Make sure to name Good1~0.CSV for the non malicious system log files. 

Plese download the sample dataset from the Link below. 

https://drive.google.com/drive/folders/1_mJUvA99cHsE09UxFb1Cpyik3fVaSy0N?usp=sharing

###################### Helpful Tips #########################

Download the library, unzip it and run the following command before you install. 


Navigate to CyberSecTK-Library-master>cybersectk

Execute the following command before installation to make sure you have all the required packages are installed on your current python distribution.

 python setup.py develop
 
 If you found some error make sure to install the missing packages. 
 
 Installing the library

 python setup.py install



