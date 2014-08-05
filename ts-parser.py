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

def save_result():

    outfile = open("/Users/hoang/Downloads/connections.txt", 'w')

    for conn_tuple in conn:
        outfile.write(str(conn_tuple)+'\n')
        conn_info = conn[conn_tuple]
        for pkt in conn_info['trace']:
            outfile.write(str(pkt)+'\n')
    outfile.close()

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
            sleep(1)


    # if this is SYN
    if tcp.flags & dpkt.tcp.TH_SYN :

        if not (tcp.flags & dpkt.tcp.TH_ACK):
            if ts == False:                # no TS, skip
                return
            conn_info = {}
            conn_info['SYN-ed']     = True 
            conn_info['SYN-ACKed']  = False 
            conn_info['trace']      = [ (index,"SYN",ts_val,ts_ocr) ]        

            conn[(src_ip, dst_ip, sport, dport)] = conn_info          # add this connection to the DB
            return

        else:   #  this is a SYN/ACK
            conn_tuple = (dst_ip, src_ip, dport, sport) 

            if ts == False:                     # no TS, skip.
                return
            # print ""
            # print index
            # print (src_ip, dst_ip, sport, dport)
            # print " SYN/ACK, TS on"
            if conn_tuple not in conn:          # if SYN not seen, add new connection.
                conn_info = {}
                
            else:
            conn_info = conn[conn_tuple]
            conn_info['SYN-ACKed'] = True 
            conn_info['trace'].append( (index,"SYN/ACK",ts_val,ts_ocr) )
            # print conn[conn_tuple]
 #           # print conn_info            # the same result as previous line, great!
            return


    elif ((src_ip, dst_ip, sport, dport) in conn):

        conn_tuple  =  (src_ip, dst_ip, sport, dport)
        info = conn[conn_tuple]


        if (info['SYN-ACKed'] == False) && ():
        # not seen SYN-ACK, skip
            # May be RST flag, receiver rejects the connection
            del conn[conn_tuple]
            return

        # print ""
        # print index
        # print conn_tuple
        if ts == False:
            print "Manual analysis" 
            return

        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( (index,"FIN", ts_val, ts_ocr) )
        else:
            info['trace'].append( (index, "regular", ts_val, ts_ocr) )

        # for line in info['trace']:
        #     print line

    elif ((dst_ip, src_ip,  dport, sport) in conn):

        conn_tuple  =  (dst_ip, src_ip,  dport, sport)
        info = conn[conn_tuple]


        if info['SYN-ACKed'] == False:
        # not seen SYN-ACK, skip
            # May be RST flag, receiver rejects the connection
            del conn[conn_tuple]
            return


        if ts == False:
            print index
            print conn_tuple
            print "Manual analysis" 
            return

        if tcp.flags & dpkt.tcp.TH_FIN:
            info['trace'].append( (index, "FIN", ts_val, ts_ocr) )
        else:
            info['trace'].append( (index, "regular", ts_val, ts_ocr) )

        # for line in info['trace']:
        #     print line


                # skip if this connection doesn't have ts negotiation.


    
def main():
    # pfile = "/Users/hoang/Downloads/201204010000.dump"
    pfile = "/Users/hoang/Downloads/200603030630.dump"
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


        if index > 200000:
            break

    print "Parsing finished"

    save_result()


if __name__== "__main__":
    main()