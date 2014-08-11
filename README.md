
4/8/14
Note 1: 
For many connections, trace file stores only 1 traffic direction: from A to B, but not B to A. The reason is likely because the reverse direction go through another route and not pass the capturing machine.
E.g. : in 201204010000.dump trace file, TCP stream started at Pkt No 613.
These traces should be analysed.

Note 2:
There are many RST signals from receivers to reject the incoming SYNs. 

5/8/14
Note 1: Timestamps' unit is millisecond (ms)

Note 2: In many connections, the packets without timestamp are RST.