"""
Create GTPv1 and GTPv2 packets
Author: aprabh@juniper.net

Create sample GTP-C and GTP-U packets with scaled teid, inner iP using scapy
use -ver v1 or -ver v2 to create packets accordinlgy 
use -write <file.pcap> to create a pcap file 
use -nteid <> to create that many TEID values with individual source Ip and dest IP
use -npkts < > to create < > many number of packets to be sent.

"""
from scapy.all import *
import argparse
import json
from scapy.contrib.gtp import *
from scapy.utils import wrpcap
import binascii
from netaddr import *

parser = argparse.ArgumentParser()
parser.add_argument('-ver', action='store',dest='VERSION',default="v1", help='v1 or v2')
parser.add_argument('-write', action='store',dest='WRITE',default="scapy_gtp.pcap", help='write to pcap')
parser.add_argument('-nteid', action='store',dest='NTEID',default="1", help='Number of TEID to simulate with range starting based on Input[teid] value ')
parser.add_argument('-npkts', action='store', dest='NPKTS', default="1", help='Number of packets to be sent per TEID')
parser.add_argument('-iptype', action='store', dest='IP_TYPE', default="v4inv4", help='Type of GTP packet. v4inv4/v6inv6/v4inv6/v6inv4')
args = parser.parse_args()

if args.IP_TYPE == 'v4inv4':
    # GTP V4 in V4
    Input = {
    	"srcmac":"00:10:94:00:00:02",
    	"dstmac":"20:d8:0b:c2:48:0f",
        "type":"IPV4",
    	"srcip":"100.1.1.1",
    	"dstip":"100.1.1.2",
        "teid": 1000,
        "innersrcip":"191.168.1.1/14",
        "innerdstip":"192.168.2.1/14",
        "innersrcport":1000,
        "innerdstport":2000,
        "iface": "GTP"
    }


elif args.IP_TYPE == 'v6inv4':
    # GTP V6 in V4
    Input = {
    	"srcmac":"00:10:94:00:00:02",
    	"dstmac":"20:d8:0b:c2:48:0f",
        "type":"IPV6",
    	"srcip":"100.1.1.1",
    	"dstip":"100.1.1.2",
        "teid": 1000,
        "innersrcip":"2001:fc80:1790:3721::4:1a/64",
        "innerdstip":"2001:fc90:1690:3721::5:1a/64",
        "innersrcport":1000,
        "innerdstport":2000,
        "iface": "GTP"
    }

elif args.IP_TYPE == 'v6inv6':
    # GTP V6 in V6
    Input = {
    	"srcmac":"00:10:94:00:00:02",
    	"dstmac":"20:d8:0b:c2:48:0f",
        "type":"IPV6",
    	"srcip":"2001:fc80:1890:3721::4:1a",
    	"dstip":"2001:fc80:1890:3721::4:1b",
        "teid": 1000,
        "innersrcip":"2001:fc80:1790:3721::4:1a/64",
        "innerdstip":"2001:fc90:1690:3721::5:1a/64",
        "innersrcport":1000,
        "innerdstport":2000,
        "iface": "GTP"
    }

elif args.IP_TYPE == 'v4inv6':
    # GTP V4 in V6
    Input = {
    	"srcmac":"00:10:94:00:00:02",
    	"dstmac":"20:d8:0b:c2:48:0f",
        "type":"IPV6",
    	"srcip":"2001:fc80:1890:3721::4:1a",
    	"dstip":"2001:fc80:1890:3721::4:1b",
        "teid": 1000,
        "innersrcip":"191.168.1.1/14",
        "innerdstip":"192.168.2.1/14",
        "innersrcport":1000,
        "innerdstport":2000,
        "iface": "GTP"
    }

# create a GTP-C packet. GTPv1. WIP. Need to fix similar to function "CreateGTPUPacket" 
def CreateGtpCPacket(ip_type, teid, innersrcip, innerdstip, innersrcport, innerdstport):
    if ip_type == 'v4inv4':
        pkt = Ether()/IP()/UDP()/GTPHeader()
        newpkt = IP()/UDP()
    elif ip_type == 'v6inv6':
        pkt = Ether()/IPv6()/UDP()/GTPHeader()
        newpkt = IPv6()/UDP()
    elif ip_type == 'v4inv6':
        pkt = Ether()/IPv6()/UDP()/GTPHeader()
        newpkt = IPv6()/UDP()
    #pkt[Ether].src = data["srcmac"]
    #pkt[Ether].dst = data["dstmac"]
    #pkt[IP].src = data["srcip"]
    #pkt[IP].dst = data["dstip"]
    pkt[GTPHeader].teid = teid
    newpkt[IP].src = innersrcip
    newpkt[IP].dst = innerdstip
    newpkt[UDP].sport = innersrcport
    newpkt[UDP].dport = innerdstport
    gtp = pkt/newpkt

    return gtp

# Create GTP-U packet. GTPv1
def CreateGtpUPacket(ip_type, teid, innersrcip, innerdstip, innersrcport, innerdstport):
    if ip_type == 'v4inv4':
        pkt = Ether()/IP()/UDP()/GTP_U_Header()
        newpkt = IP()/UDP()
        pkt[IP].src = Input["srcip"]
        pkt[IP].dst = Input["dstip"]
        newpkt[IP].src = innersrcip
        newpkt[IP].dst = innerdstip
    elif ip_type == 'v6inv6':
        pkt = Ether()/IPv6()/UDP()/GTP_U_Header()
        newpkt = IPv6()/UDP()
        pkt[IPv6].src = Input["srcip"]
        pkt[IPv6].dst = Input["dstip"]
        newpkt[IPv6].src = innersrcip
        newpkt[IPv6].dst = innerdstip
    elif ip_type == 'v4inv6':
        pkt = Ether()/IPv6()/UDP()/GTP_U_Header()
        newpkt = IP()/UDP()
        pkt[IPv6].src = Input["srcip"]
        pkt[IPv6].dst = Input["dstip"]
        newpkt[IP].src = innersrcip
        newpkt[IP].dst = innerdstip
    elif ip_type == 'v6inv4':
        pkt = Ether()/IP()/UDP()/GTP_U_Header()
        newpkt = IPv6()/UDP()
        pkt[IP].src = Input["srcip"]
        pkt[IP].dst = Input["dstip"]
        newpkt[IPv6].src = innersrcip
        newpkt[IPv6].dst = innerdstip
        
    #pkt = Ether()/IP()/UDP()/GTP_U_Header()
    #newpkt = IP()/UDP()
    pkt[Ether].src = Input["srcmac"]
    pkt[Ether].dst = Input["dstmac"]
    newpkt[UDP].sport = innersrcport
    newpkt[UDP].dport = innerdstport
    pkt[GTP_U_Header].teid = teid
    gtp = pkt/newpkt

    return gtp

# Create GTP-C v2 packet 
def CreateGtpV2packet():
    ie = IE_RecoveryRestart(ietype='Recovery Restart', length=1, restart_counter=17, CR_flag=0, instance=0)
    gtp = Ether()/IP()/UDP(sport=2123, dport=2123) / GTPHeader(seq=12345, length=9, P=0) / GTPV2EchoRequest(IE_list=[ie])
    gtp[Ether].src = data["srcmac"]
    gtp[Ether].dst = data["dstmac"]
    gtp[IP].src = data["srcip"]
    gtp[IP].dst = data["dstip"]

    return gtp

if args.VERSION == "v1":
    # Simulate a range of TEID for GTP-U packets
    n_isip = IPNetwork(Input["innersrcip"]).ip
    print(n_isip)
    n_idip = IPNetwork(Input["innerdstip"]).ip
    
    if args.NTEID:
        # increment inner IP by 1 for every TEID to emulate that many sessions. Each would be unique
        for i in range(int(args.NTEID)):
            teid = int(Input["teid"]) + i
            isip = n_isip + i
            idip = n_idip + i 
            print(' TEID: {0}, ISIP: {1}, IDIP: {2}'.format(str(teid), str(isip), str(idip)))
            upkt = CreateGtpUPacket(args.IP_TYPE, teid, isip, idip, Input["innersrcport"], Input["innerdstport"])
            if args.WRITE:
                wrpcap("{}".format(args.WRITE), upkt, append=True)
            sendp(upkt, iface=Input["iface"], inter=0.01, count=int(args.NPKTS)) 
            

if args.VERSION == "v2":
    print("Entering V2 block")

    from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader
    from scapy.contrib.gtp_v2 import GTPV2EchoRequest as GTPV2EchoRequest
    from scapy.contrib.gtp_v2 import IE_RecoveryRestart as IE_RecoveryRestart
    
    cpktv2 = CreateGtpV2packet()
    cpktv2.show2()
    sendp(cpktv2, iface="GTP", inter=0.01, count=10)

    if args.WRITE:
        wrpcap("{}".format(args.WRITE), cpktv2, append=True)
