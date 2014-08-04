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


    print (src_ip, dst_ip, sport, dport)


    ts = False


    for opt in dpkt.tcp.parse_opts(tcp.opts):
        (o,l,buf) = opt                   # option type, length, data

        if o == dpkt.tcp.TCP_OPT_TIMESTAMP:       
            ts = True
            (ts_val, ts_ocr) = struct.unpack('>LL', buf[0:8])
            print ts_val, ts_ocr
            
        if o == TCP_OPT_MPTCP:
            print "MPTCP!"
            sleep(1)



    if ts == False:
        print "no timestamp option"

    conn_info = {'ts_nego': ts }

    # if this is SYN
    if tcp.flags & dpkt.tcp.TH_SYN :
        conn_info['SYN_observed'] = True 
        conn[(src_ip, dst_ip, sport, dport)] = conn_info          # add this connection to the knowledge
        print "SYN"
        print conn_info
        return


    # skip if this connection doesn't have ts negotiation.
    elif ((src_ip, dst_ip, sport, dport) in conn):
        conn_tuple  =  (src_ip, dst_ip, sport, dport)
        info = conn[conn_tuple]
        if info[ts_nego] == False:
            print "skip"
            return

    elif ((dst_ip, src_ip,  dport, sport) in conn):
        conn_tuple  =  (dst_ip, src_ip,  dport, sport)
        info = conn[conn_tuple]
        if info[ts_nego] == False:
            print "skip"
            return



    
def main():

    pfile = "/Users/hoang/Downloads/201204010000.dump"
    pcapReader = dpkt.pcap.Reader(file(pfile, "rb"))

    print "Trace file is opened"
    print "parsing file... \n"
    index=0

    for time, data in pcapReader:
        index += 1
        ether = dpkt.ethernet.Ethernet(data)

        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = ether.data
            parse_ip(ip, index)
        else: 
            print "not an IP packet"


        if index > 100:
            break



if __name__== "__main__":
    main()