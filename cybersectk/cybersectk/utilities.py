from scapy.all import * 
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
