#! /usr/bin/env python

# Use dpkt. 
# dpkt is primarily a packet creation/parsing library. 

import dpkt
import socket
import sys
import struct
import hashlib
import time

dir = "/Users/hoang/trace/201408011400/"

TCP_OPT_MPTCP = 30

# Range of packets being processed
PackIdMin = 000000
PackIdMax = 1000000  

conn = {} # dict of no TS connections
mptcp = {} # dict of mptcp packets
# packets = []
packets = {}   
# Dict or List?
# Dict for storing conn_tuple, and it is more efficient than List

def summarize_result():

    outfile = open(dir + "connections.txt", 'w')

    outfile.write("Need manual analysis \n")

    for conn_tuple in conn:

        info = conn[conn_tuple]
        # if (info['SYN-ed'] == False) or (info['SYN-ACKed'] == False):
        #     outfile.write("One-way trace \n")

        if info['manual']:
            outfile.write('\n'+ str(conn_tuple) +'\n')
            for pkt in info['trace']:
                outfile.write(str(pkt)+'\n')
                # id of each pkt
                pId = pkt[0]    
                packets[pId] = conn_tuple


    outfile.close()


def connections_dump(tracefile):

    outfile    = dir + 'no_TS_connections.pcap'
    pcapReader = dpkt.pcap.Reader(file(tracefile, "rb"))
    pcapWriter = dpkt.pcap.Writer(open(outfile,'wb'))

    print "Trace file is opened again"
    print "parsing file... "
    index=0

    for time, data in pcapReader:
        index += 1

        if (index < PackIdMin):
            continue

        # with Dict, time complexity: O(1)
        if (index in packets) or (index in mptcp):
            print index
            ether = dpkt.ethernet.Ethernet(data)
            pcapWriter.writepkt(ether)


        if (index > PackIdMax):
            break

    # c = 0     # connection Id
    # for conn_tuple in conn:
    #     c+=1
    #     pcw = dpkt.pcap.Writer(open(c+'.pcap','wb'))



def parse_ip(ip, index):

    if not hasattr(ip, 'p'):    # some packets are sniffed brokenly
        return                  # faster if convert to try/except
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    
    tcp = ip.data

    try:
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        sport = tcp.sport
        dport = tcp.dport
    except AttributeError:
        return


    ts = False

    for opt in dpkt.tcp.parse_opts(tcp.opts):
        (o,l,buf) = opt                   # option type, length, data

        if o == dpkt.tcp.TCP_OPT_TIMESTAMP:       
            ts = True
            (ts_val, ts_ocr) = struct.unpack('>LL', buf[0:8])

        if o == TCP_OPT_MPTCP:
            print "MPTCP!"
            print index
            mptcp[index] = True

    # if this is SYN
    if tcp.flags & dpkt.tcp.TH_SYN :

        if not (tcp.flags & dpkt.tcp.TH_ACK):
            if ts == False:                # no TS, skip
                return
            conn_info = {}
            conn_info['SYN-ed']     = True 
            conn_info['SYN-ACKed']  = False 
            conn_info['manual']     = False
            conn_info['trace']      = [ (index,"SYN",ts_val,ts_ocr) ]        

            conn[(src_ip, dst_ip, sport, dport)] = conn_info          # add this connection to the DB
            return

        else:   #  this is a SYN/ACK
            conn_tuple = (dst_ip, src_ip, dport, sport) 

            if ts == False:                     # no TS in SYN/ACK, skip.
                if conn_tuple in conn:
                    del conn[conn_tuple]
                return

            if conn_tuple in conn:          
                conn_info = conn[conn_tuple]
                conn_info['SYN-ACKed']  = True             
                conn_info['trace'].append( (index,"SYN/ACK",ts_val,ts_ocr) )

            else:                   # if SYN not seen, add new connection.
                conn_info = {}
                conn_info['SYN-ed']     = False 
                conn_info['SYN-ACKed']  = True 
                conn_info['manual']     = False 
                conn_info['trace']      = [ (index, "SYN-ACK", ts_val, ts_ocr) ]
                conn[conn_tuple] = conn_info

             # print conn[conn_tuple]
 #           # print conn_info            # the same result as previous line, great!
            return


    elif ((src_ip, dst_ip, sport, dport) in conn):

        conn_tuple  =  (src_ip, dst_ip, sport, dport)
        info = conn[conn_tuple]


        if (ts == False) and (info['SYN-ACKed'] == False) :
        # no TS and not handshaked, skip
            # May be RST flag, receiver rejects the connection
            del conn[conn_tuple]
            return

        if (ts == False) and info['SYN-ACKed']:
            if tcp.flags & dpkt.tcp.TH_RST:
                info['trace'].append( (index, "RST", -1, -1) )
            else:
            # flag for manual analysis
                info['manual'] = True
                info['trace'].append( (index, "no TS", -1, -1) )
            return


        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( (index,"FIN", ts_val, ts_ocr) )
        else:
            info['trace'].append( (index, "regular", ts_val, ts_ocr) )


    elif ((dst_ip, src_ip,  dport, sport) in conn):

        conn_tuple  =  (dst_ip, src_ip,  dport, sport)
        info = conn[conn_tuple]


        if (ts == False) and (info['SYN-ACKed'] == False) :
        # no TS and not handshaked, skip
            # May be RST flag, receiver rejects the connection
            del conn[conn_tuple]
            return

        if (ts == False) and info['SYN-ACKed']:
            if tcp.flags & dpkt.tcp.TH_RST:
                info['trace'].append( (index, "RST", -1, -1) )
            else:
            # flag for manual analysis
                info['manual'] = True
                info['trace'].append( (index, "no TS", -1, -1) )
            return


        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( (index,"FIN", ts_val, ts_ocr) )
        else:
            info['trace'].append( (index, "regular", ts_val, ts_ocr) )

                # skip if this connection doesn't have ts negotiation.


    
def main():
    tracefile = dir + "201408011400.dump"
    pcapReader = dpkt.pcap.Reader(file(tracefile, "rb"))

    print "Trace file is opened"
    print "parsing file... "

    index=0

    for time, data in pcapReader:
        index += 1

        if (index < PackIdMin):
            continue

        ether = dpkt.ethernet.Ethernet(data)

        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = ether.data
            parse_ip(ip, index)

        if (index % 100000 == 0):
            print index

        if (index > PackIdMax):
            break

    print "Parsing finished"

    summarize_result()

    print "dump connections"

    connections_dump(tracefile)

if __name__== "__main__":
    main()