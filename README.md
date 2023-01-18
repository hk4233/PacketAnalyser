# Packet Analyser

# Analyzing the Captured Packets

This application reads a set of packets and produces a detailed summary of those
packets.The packet analyzer should run as a shell command. The syntax of the command is the
following:

% java pktanalyzer datafile

The pktanalyzer program will extract and display the different headers of the captured packets in
the file datafile. First, it displays the ethernet header fields of the captured frames. Second, if the
ethernet frame contains an IP datagram, it prints the IP header. Third, it prints the packets
encapsulated in the IP datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP
packet.

# Sample captured packets

-TCP

-UDP

-ICMP

# Sample Output

Here are some examples of the output:

% java pktanalyzer pkt/new_icmp_packet2.bin

ETHER: ----- Ether Header -----

ETHER:

ETHER: Packet size = 60 bytes

ETHER: Destination = c0:14:3d:d5:72:8b,

ETHER: Source = 00:1d:a1:38:58:00,

ETHER: Ethertype = 0800 (IP)

ETHER:

IP: ----- IP Header -----

IP:

IP: Version = 4

IP: Header length = 20 bytes

IP: Type of service = 0x00

IP: xxx. .... = 0 (precedence)

IP: ...0 .... = normal delay

IP: .... 0... = normal throughput

IP: .... .0.. = normal reliability

IP: Total length = 40 bytes

IP: Identification = 54321

IP: Flags = 0x00

IP: .0.. .... = OK to fragment

IP: ..0. .... = last fragment

IP: Fragment offset = 0 bytes

IP: Time to live = 244 seconds/hops

IP: Protocol = 1 (ICMP)

IP: Header checksum = 0x05a2

IP: Source address = 198.20.99.130

IP: Destination address = 129.21.66.85

IP: No options

IP:

ICMP: ----- ICMP Header -----

ICMP:

ICMP: Type = 8 (Echo request)

ICMP: Code = 0

ICMP: Checksum = 0x60b1
