# CyberSecTK-Library
 Cyber Security feature extraction python library 
 
 ################### WLAN IOT ########################

 Library Module name : wiot()
 
 Example:
 
 from cybersectk.wiot import wiot
 
 wiot()
 
 OUTPUT File: IOTwireless.CSV
 
NOTE: Add the wireless PCAP file in working directory. Enter the PCAP file name when prompt during the exection time. Don't forget to specify the .pcap extension at the end of the file name.
 ################### TCP IOT #########################

Library Module name : iot()

Example:
 
 from cybersectk.iot import iot
 
 iot()
 
OUTPUT File: label_feature_IOT.CSV

NOTE: We need to create two different directories original_pcap and filtered_pcap in a working directory. The source iot pcap file need to be available inside the original_pcap directory. 
The library uses tshark to extract the features from the given TCP pcap file. Make sure tshark is installed on your system. 
A python dictionary ip_filter {} is used to filter device specific TCP PCAP files at the time of execution. The filtered pcap file will be save with its fileted name inside filtered_pcap directory.

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

####################### MALEWARE ###########################

Library function name : malware()

Example:
 
 from cybersectk.malware import malware
 
 malware()
 
 OUTPUT File : DynamicMalwareMatrix.CSV

Note: Please make sure to creat directory "log_files" in a same working directory and add the Good and infected CSV log files inside log_files directory for feature extraction. Make sure to name Good1.CSV, Good2.CSV and so on for the non malicious system log files. Please refer to the sample data set for better understanding. 

Plese download the sample dataset from the Link below. 

https://drive.google.com/drive/folders/1_mJUvA99cHsE09UxFb1Cpyik3fVaSy0N?usp=sharing

###################### Helpful Tips #########################

Download the library, unzip it and run the following command before you install. 


Navigate to CyberSecTK-Library-master>cybersectk

Execute the following command before installation to make sure you have all the required packages are installed on your current python distribution.

 <i> python setup.py develop </i>
 
 If you found some error make sure to install the missing packages. 
 
 Installing the library

 <i> python setup.py install </i>
 


