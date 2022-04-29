# CyberSecTK-Library
 Cyber Security feature extraction python library

 ####################### Installation ##########################

Download the library, unzip it and run the following command before you install. 


Navigate to CyberSecTK-Library-master>cybersectk

Execute the following command before installation to make sure you have all the required packages are installed on your current python distribution.

 <i> python setup.py develop </i>
 
 If you found some error make sure to install the missing packages. 
 
 Installing the library

 <i> python setup.py install </i>
 
 ######################## WLAN IOT #############################

 Library Module name : wiot()
 
 Example:
 
 from cybersectk.wiot import wiot
 
 wiot()
 
 OUTPUT File: IOTwireless.CSV
 
NOTE: Add the wireless PCAP file in working directory. Enter the PCAP file name when prompt during the exection time. Don't forget to specify the .pcap extension at the end of the file name.

**Wireless IOT Features**
> Feature selection is based on wireless DataLink layer header information.

|Features	| Description|
|---|---|
|Version |	Radiotap Frame control field indicates the current WLAN protocol version.|
|Pad |	Radiotap Frame control field aligns onto natural word boundaries, that means all 8, 16, 32, and 64-bit fields must begin respectively to avoid unaligned accesses to radiotap capture fields.|
|Len |	Specifies entire length of radiotap data including radiotap header.|
|Rate |	Data transfer rate of a device i.e. 2.0 Mb/s etc.| 
|ChannelFrequency |	Device operating channel frequency i.e. radio wave spectrum type a,b,g,n |
|ChannelFlags |	Specifies device supported spectrum coding method designed to avoid collision.|
|DBM_AntSignal |	Transmitting wireless device radio antenna strength in dBm.|
|Antenna |	Number of available transceiving radio antennas.|
|Subtype |	Specified the frame sub type i.e. association request (0000), association response (0001), beacon (1000), probe request (0100) etc.|
|Type |	Determine the function of frame type i.e. management (00), control (01) or data (10).|  
|Proto	| WLAN Protocol version.|
|FCfield	| Specifies wireless frame flag i.e. to-DS, from-DS, retry, power, protected, etc.| 
|ID	| Connection ID assigned between source and destination over a period within maximum datagram lifetime (MDL).|
|Addr1 |	Wireless device MAC address (destination/recipient).|
|Addr2 |	Wireless device MAC address (relay/source).|
|Addr3 |	Wireless device MAC address (BSSID/source/destination).|
|SC |	Wireless packets Sequence control.|
|Addr4 |	Wireless device Mac Address (BSSID/source).|
|Dot11Elt.ID	| Dot11 beacon type specific e.g. 0 for management i.e. SSID.|  
|Dot11Elt.len |	Length of specific Dot11Elt packet sequence payload.|
|Dot11Elt.info	| Information of the Dot11Elt packet sequence.|

 ######################## TCP IOT ##############################

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

ip_filter['TCP_Miscellaneous'] = '"tcp && (ip.src==192.168.1.216) || (ip.src==192.168.1.46) || (ip.src==192.168.1.84) \
                     || (ip.src==192.168.1.91)"'

Please update dictionary key and value. 

Example: ip_filter = {} 

ip_filter['TCP_Miscellaneous'] = '"tcp && (ip.src==IP_Address)"'
         
iot (**ip_filter)

**IOT Features**
> Feature selection is based on TCP/IP packet.

| Features | Description |
|--- | --- |
|Label | Specifies the device type eg. Mobile, Camera, outlet, etc.|
|IPLength |	Total length of the IP packets.|
|IPHeaderLength |	Packets IP header length. |
|TTL |	Time to live filed, helps to maintain packets from looping endlessly.|
|Protocol |	Packet protocol field indicates packets upper-layer protocols.| 
|DestPort |	Destination Port fields helps to identify the end points of the connection.|
|SequenceNumber |	Initialize the sequence number assigned to PDU at the time of data transmission. |
|AckNumber |	Acknowledge the value specific to the sequence of data expecting to receive in the next sequence number.| 
|WindowSize	| Specified the packet buffer space available for incoming data.|
|TCPHeaderLength |	TCP packet header length.|
|TCPLength |	Total TCP packet length.|
|TCPStream |	Specifies the segments of the TCP PDU (Protocol Data Units).|
|TCPUrgentPointer | Data bytes set as urgent flag in the TCP header for immediate process.|
|IPFlags |	3 bits field value set to control or identify the fragments of the IP packets eg. Reserved (R) , Don’t fragment (DF) and More fragments (MF).|
|IPID |	Unique identification field value assigned for every PDU, between a source and destination of a given protocol over a period within maximum datagram lifetime (MDL).|
|IPchecksum |	Detect corruption in IPv4 packets header.|
|TCPflags |	Specifies the particular state of TCP connection, fields use like SYN, ACK, FIN, RST, etc. |
|TCPChecksum	| Detect corruption in TCP packed payload and the header.|

######################### MALEWARE #############################

Library function name : malware()

Example:
 
 from cybersectk.malware import malware
 
 malware()
 
 OUTPUT File : DynamicMalwareMatrix.CSV

Note: Please make sure to creat directory "log_files" in a same working directory and add the Good and infected CSV log files inside log_files directory for feature extraction. Make sure to name Good1.CSV, Good2.CSV and so on for the non malicious system log files. Please refer to the sample data set for better understanding. 

Plese download the sample dataset from the Link below. 

https://drive.google.com/drive/folders/1_mJUvA99cHsE09UxFb1Cpyik3fVaSy0N?usp=sharing

**Dynamic Malware Matrix Features** 
> TOP 20 Selected features out of 1000.

|Features |	Description |
|---|---|
|events_31bf3856ad364e35_6	| Windows system update service packages corrupt.|
|onent |	OneNote email association to send contents to notebooks by emailing.|
|directx	| DirectX error leading to tech support scams paying for unnecessary technical support service.| 
|resources_31bf3856ad364e35_8	| Error code 37 leading to tech support scams paying for unnecessary technical supports service.| 
|oem	| Original Equipment Manufacturer version use to build windows system.|
|adm_31bf3856ad364e35_6 |	Operating System misconfigured, missing or damaged important system files leading system crash with errors.| 
|resources_b03f5f7f11d50a3a_en |	.NET framework vulnerability could allow security feature bypass.|
|client_31bf3856ad364e35_6 |	Service stop error trying to connect to a printer server in windows (error 0x00000006).|
|rds |	Relational Database Service error.| 
|pcat |	Windows update patch error leading system crash, boot loader manager error.| 
|core_31bf3856ad364e35_6 |	Windows remote desktop service access error.|
|identity|	Services directory application or web service user authentication error due to account group policy.|  
|inf_31bf3856ad364e35_6 |	Windows OS network adaptor stop/disable error eg. Stop: 0x0000000A (parameter1, parameter2, parameter3, parameter4) IRQL_NOT_LESS_OR_EQUAL|
|resources_31bf3856ad364e35_6 |	Windows DNS service updates configuration rules.|
|anguagepack_31bf3856ad364e35_6|	Windows system32 components service configuration error.|
|resources_b03f5f7f11d50a3a_6 |	Windows security update for .NET framework.|
|mdac	|Microsoft Data Access Components core data access components eg. Microsoft SQL server.|
|dll_31bf3856ad364e35_6 |	Microsoft windows operating system, crypto API32.DLL file.|
|driverclass_31bf3856ad364e35_6 |	Windows security update installation problem.|
|msil_system	| Security update for .NET framework service.|

########################## PHISH ###############################

Library function name : phish(email=None, password=None, server=None, l=False, mailbox=None, process=1)

The phish function produces a personal corpus of phishing features 
extracted from an IMAP server of the user's choice.

Example:
 
    from cybersectk.phish import phish

To list IMAP directories. 
 
        phish('yuri@example.com', 'yourapppasswod', 'imap.gmail.com', True)

To process email messages.

        phish('yuri@example.com', 'yourapppasswod', 'imap.gmail.com', False, '[Gmail]/Spam', 25)
 
Parameters:

    email    (str):  Email login. Required.
    password (str):  Email password. Note, modern email services require app passwords. Required.
    server   (str):  IMAP server. This method connects via SSL port 993 only. Required.
    l        (bool): List IMAP mailboxes to console for use with next argument. Required.
    mailbox  (str):  Mailbox to use. Optional if l = True, else required.
    process  (int):  Number of emails to process. Default: 1, Max: 100.

Returns:

    None

Output:

    CSV. File will be placed in current working directory containing various phishing 
    feature extractions. The filename is dynamic to support multiple runs of this function. 
    Filename will be a combination of email address provided to function and current 
    date time stamp. Additionally, each message email processed will be placed in a "msg"
    folder at the root of the CyberSecTK folder hierarchy. 
 
NOTE1: Gmail, Hotmail/Outlook and Yahoo! Mail all require an "app password". See this link for
an example - https://support.google.com/accounts/answer/185833  

NOTE2: Be sure to review and update the phishing_terms file as required for your effort.

**Phish Features**
> Feature selection is based on preliminary evaluation.

|  Features	| Description | Data Type |
|---|---|---|
|Message ID | Unique identifier for a given an email.| String |
|From |	The 5322.From (also known as the From address or P2 sender) header value.| String |
|To | The email address in the To header field.| String |
|Subject | Subject field of the reviewed email.| String |
|DKIM |	DomainKeys Identified Mail value in Authenication_Header. | String |
|SPF |	Sender Policy Framework value in Authenication_Header.| String |
|Anchor_HREF | The URL defined in a given &lt;a&gt; tag.| String |
|Weight_Gain |	A sum of the value for a given term, or key, defined in the phishing_terms file. | Integer |


 


