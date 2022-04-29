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

ip_filter['TCP_Miscellaneous'] = '"tcp && (ip.src==192.168.1.216) || (ip.src==192.168.1.46) || (ip.src==192.168.1.84) \
                     || (ip.src==192.168.1.91)"'

Please update dictionary key and value. 

Example: ip_filter = {} 

ip_filter['TCP_Miscellaneous'] = '"tcp && (ip.src==IP_Address)"'
         
iot (**ip_filter)

 ###################### PHISH ############################

Library function name : phish(email=None, password=None, server=None, l=False, mailbox=None, process=1)

    The phish function produces a personal corpus of phishing features 
    extracted from an IMAP server of the user's choice.

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

##########################################################
