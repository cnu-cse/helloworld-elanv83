import sys
from scapy.all import *

ARGS = None
#DEBUG = False
DEBUG = False 


"""
Ref(EAPOL): https://en.wikipedia.org/wiki/IEEE_802.1X
Ref: https://medium.com/@debookee/promiscuous-vs-monitoring-mode-d603601f5fa
"""
load_layer('tls')

def pkt_handler(pkts):
    for pkt in pkts:
        if DEBUG:
            print(pkt.summary())
        pkt_type = pkt['Ether'].type
        if pkt_type != 0x0800:
            continue
        proto = pkt['IP'].proto
        if proto == 0x06:
            src_port = pkt['TCP'].sport
            dst_port = pkt['TCP'].dport
            if src_port == 443 or dst_port == 443:
                tls_handler(pkt)
        elif proto == 0x11:
            src_port = pkt['UDP'].sport
            dst_port = pkt['UDP'].dport
            if src_port == 53 or dst_port == 53:
                dns_handler(pkt)

def tls_handler(pkt):
    """
    Ref: https://en.wikipedia.org/wiki/Transport_Layer_Security#Protocol_details
    """
    
    ip_src = pkt['IP'].src
    ip_dst = pkt['IP'].dst
    
    """
    print('Here is TLS handler')   
    """
    
    print('Source IP : '+ ip_src + ', Dest IP : ' + ip_dst)
    
    

def dns_handler(pkt):
    """
    Ref: https://en.wikipedia.org/wiki/Transport_Layer_Security#Protocol_details
    Ref: https://tools.ietf.org/html/rfc1035
    """
    """
    Ref: print('Here is DNS handler')
    """
    
    
    for p in pkt:
       if p.haslayer(DNS):
          if p.qdcount > 0 and isinstance(p.qd, DNSQR):            
	    print "DSQR :::::::: "
            name = p.qd.qname            
          elif p.ancount > 0 and isinstance(p.an, DNSRR):
            print "DNSRR ======= "
            name = p.an.r
          else:
            continue
       print name       
    
    
def main():
    try:
        sniff(prn=pkt_handler)
    except KeyboardInterrupt:
        print('Done')


if __name__ == '__main__':
    import argparse

    main()

