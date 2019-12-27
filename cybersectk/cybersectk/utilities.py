import os
import glob
from scapy.all import * 

###################################################
#################### WLAN IOT #####################
f = open ("IOTwireless.csv", "w")
f.writelines("version,Pad,Len,Rate,ChannelFrequency,ChannelFlags,dBm_AntSignal,Antenna,subtype,\
type,proto,FCfield,ID,addr1,addr2,addr3,SC,addr4,Dot11Elt1.ID,Dot11Elt1.len,Dot11Elt1.info\n")
def wiot(frame):
    if frame.haslayer(Dot11):
        for packets in frame:
            f.writelines('%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'%(frame.version,frame.pad,frame.len,\
                    frame.Rate,frame.ChannelFrequency,frame.ChannelFlags,frame.dBm_AntSignal,frame.Antenna,\
                    frame.subtype,frame.type,frame.proto,frame.FCfield,frame.ID,frame.addr1,frame.addr2,frame.addr3,frame.SC,frame.addr4))
            if packets.haslayer(Dot11Elt):
                packets=Dot11Elt()
                f.writelines('%s,%s,%s,'%(frame.payload.ID,frame.payload.len,frame.info.decode()))
            f.writelines('\n')
sniff(offline=input("Enter the Pcap file:"), prn=wiot)
#######################################################
#################### TCP IOT ##########################
ip_filter = {} # python dictionary
    
ip_filter['TCP_Mobile'] = "'tcp && (ip.src==192.168.1.45)'"
ip_filter['TCP_Outlet'] = "'tcp && (ip.src==192.168.1.222) || \
                                        (ip.src==192.168.1.67)'"
ip_filter['TCP_Assistant'] = "'tcp && (ip.src==192.168.1.111) || \
                    (ip.src==192.168.1.30) || (ip.src==192.168.1.42) \
                 || (ip.src==192.168.1.59) || (ip.src==192.168.1.70)'"
ip_filter['TCP_Camera'] = "'tcp && (ip.src==192.168.1.128) || \
                    (ip.src==192.168.1.145) || (ip.src==192.168.1.78)'"
ip_filter['TCP_Miscellaneous'] = "'tcp && (ip.src==192.168.1.216) \
                  || (ip.src==192.168.1.46) || (ip.src==192.168.1.84) \
                     || (ip.src==192.168.1.91)'"

#############################################################

labelFeature = open("label_feature_IOT.csv",'a') #vector space

labelFeature.writelines("Label,IPLength,IPHeaderLength,TTL,\
           Protocol,SourcePort,DestPort,SequenceNumber,AckNumber\
           ,WindowSize,TCPHeaderLength,TCPLength,TCPStream\
     ,TCPUrgentPointer,IPFlags,IPID,IPchecksum,TCPflags,TCPChecksum\n")

##############################################################
def iot (**ip_filter):
    for original in glob.glob('./*.pcap'):
        for k in ip_filter.keys():
            os.system("tshark -r " + original + " -w- -Y " + 
                      ip_filter[k] + ">> filtered_pcap/" + k + ".pcap")

#################################################################
for filteredFile in glob.glob('filtered_pcap/*.pcap'):
    #print(filteredFile)
    filename = filteredFile.split('/')[-1]
    label = filename.replace('.pcap', '')
    tsharkCommand = "tshark -r " + filteredFile + " -T fields \
                    -e ip.len -e ip.hdr_len -e ip.ttl \
                    -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.seq \
                    -e tcp.ack -e tcp.window_size_value -e tcp.hdr_len -e tcp.len \
                    -e tcp.stream -e tcp.urgent_pointer \
                    -e ip.flags -e ip.id -e ip.checksum -e tcp.flags -e tcp.checksum"

    allFeatures = str(  os.popen(tsharkCommand).read()  )
    allFeatures = allFeatures.replace('\t',',')
    allFeaturesList = allFeatures.splitlines()
    for features in allFeaturesList:
        labelFeature.writelines(label + "," + features + "\n")
##############################################################