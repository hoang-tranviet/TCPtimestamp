#! /usr/bin/env python

# Use dpkt. 
# dpkt is primarily a packet creation/parsing library. 

import dpkt
import socket
import sys
import struct
import hashlib

TCP_OPT_MPTCP = 30

conn = {} # info of each connection

def parse_ip(ip, index):

    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    
    tcp = ip.data

    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    sport = tcp.sport
    dport = tcp.dport


    ts = False


    for opt in dpkt.tcp.parse_opts(tcp.opts):
        (o,l,buf) = opt                   # option type, length, data

        if o == dpkt.tcp.TCP_OPT_TIMESTAMP:       
            ts = True
            (ts_val, ts_ocr) = struct.unpack('>LL', buf[0:8])

        if o == TCP_OPT_MPTCP:
            print "MPTCP!"
            sleep(1)


    # if this is SYN
    if tcp.flags & dpkt.tcp.TH_SYN :

        if not (tcp.flags & dpkt.tcp.TH_ACK):
            if ts == False:                # no TS, skip
                return
            conn_info = {}
            conn_info['SYN-ACKed'] = False 
            conn_info['trace'] = [ (index,"SYN",ts_val,ts_ocr) ]        

            conn[(src_ip, dst_ip, sport, dport)] = conn_info          # add this connection to the DB
            return

        else:   #  this is a SYN/ACK
            conn_tuple = (dst_ip, src_ip, dport, sport) 
            if conn_tuple not in conn:          # if SYN not seen, skip.
                return
            if ts == False:                     # no TS, skip.
                return
            print ""
            print index
            print (src_ip, dst_ip, sport, dport)
            print " SYN/ACK, TS on"
            conn_info = conn[conn_tuple]
            conn_info['SYN-ACKed'] = True 
            conn_info['trace'].append( (index,"SYN/ACK",ts_val,ts_ocr) )
            print conn[conn_tuple]
            # print conn_info            # the same result as previous line, great!
            return


    elif ((src_ip, dst_ip, sport, dport) in conn):

        conn_tuple  =  (src_ip, dst_ip, sport, dport)
        info = conn[conn_tuple]


        if info['SYN-ACKed'] == False:
        # not seen SYN-ACK, skip
            return

        print ""
        print index
        print conn_tuple
        if ts == False:
            print "Manual analysis" 
            # May be RST flag, receiver rejects the connection
            return

        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( (index,"FIN", ts_val, ts_ocr) )

        info['trace'].append( (index, "regular", ts_val, ts_ocr) )

        print info['trace']

    elif ((dst_ip, src_ip,  dport, sport) in conn):

        conn_tuple  =  (dst_ip, src_ip,  dport, sport)
        info = conn[conn_tuple]


        if info['SYN-ACKed'] == False:
        # not seen SYN-ACK, skip
            return

        print index
        print conn_tuple

        if ts == False:
            print "Manual analysis" 
            # May be RST flag, receiver rejects the connection
            return

        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( ("FIN", ts_val, ts_ocr) )

        info['trace'].append( ("regular", ts_val, ts_ocr) )

        print info['trace']
    # skip if this connection doesn't have ts negotiation.


    
def main():

    pfile = "/Users/hoang/Downloads/201204010000.dump"
    pcapReader = dpkt.pcap.Reader(file(pfile, "rb"))

    print "Trace file is opened"
    print "parsing file... "
    index=0

    for time, data in pcapReader:
        index += 1
        ether = dpkt.ethernet.Ethernet(data)

        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = ether.data
            parse_ip(ip, index)


        if index > 10000:
            break



if __name__== "__main__":
    main()