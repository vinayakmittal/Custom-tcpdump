CSE508: Network Security, Spring 2016

Homework 2: Programming with Libpcap
-------------------------------------------------------------------------------
Submitted By -  Vinayak Mittal
SBU ID - 110385943
-------------------------------------------------------------------------------

This project develops a passive network monitoring tool written in C which imitates the working of tcpdump.
The project allows both online and offline capturing of packets. Online capturing involves listening on particular interfaces as specified by user or on default ethernet. Offline capturing involves parsing packets
from a packet capture trace file (.pcap). 

Working of program:

The program takes the following specifications:

mydump [-i interface] [-r file] [-s string] [-h] expression

mydump is the name of binary file which is used to execute the program. 
-i option allows user to provide a custom interface to capture packets in case of online mode.
-r option allows user to specify trace file for offline capture.
-s option allows user to provide a string for showing only those packets which matches this pattern.
-h option displays a help message to user.
expression is used to provide any bpf filter.

The program takes the relevant arguments and then first vaildates the input. If any discrepancy is found, the program is terminated with a help message. However, in case of successful validation, the program parses the input and first determines whether to do online or offline packet capturing.

In case of online capture, it first finds the default interface to listen to or else take the interface name provided by the user. In case of offline capture, it tries to open the pcap file provided. After these steps, it checks if any bpf filter is provided by the user and then compiles and sets it to device. Finally, a callback function is invoked for every packet. I have used networking headers provided by linux and have parsed their headers according to the struct provided in respective headers.

The program strips ethernet header and checks if its type is IP, ARP or other. Further in case of IP, it strips ip header and then checks if its protocol is TCP, UDP, ICMP, other. Similarly, all these headers are extracted to find the actual payload. The payload is printed in the required format. In case a user has provided any string pattern to match, then only those packets are displayed whose payload matches that pattern.

Output of TCP Packet:

******************************************************************************
******************************************************************************
****************************Packet Information********************************

Time Stamp: Fri Mar 11 11:36:47 2016
Source MAC Address: 8:0:27:d5:7b:5
Destination MAC Address: b8:86:87:5b:b0:2d
Ether Type: IPv4
Packet Length: 198
Source: 172.24.20.200 Port: 22
Destination: 172.24.16.159 Port: 53908
Protocol: TCP

Payload (144 bytes):
00000   6e 69 af 13 d1 bc b5 ce  e7 4a 39 72 70 29 5e 33    ni.......J9rp)^3
00016   9c 5c 4c d7 6c 6c 34 cc  dc 6c ad 0f 49 d5 09 3e    .\L.ll4..l..I..>
00032   7a c6 6d 48 35 f5 ef 7b  f9 e9 09 71 9e 87 51 9f    z.mH5..{...q..Q.
00048   1b c4 73 44 6a 6d 0e 77  32 3e c5 f3 14 68 79 5f    ..sDjm.w2>...hy_
00064   c7 63 cc 01 19 86 24 1e  76 9e 20 7a b4 ae 5e ae    .c....$.v. z..^.
00080   c3 7c bd 76 b6 1e 6c 1a  7b 7d f9 57 b5 22 05 39    .|.v..l.{}.W.".9
00096   92 cc 17 57 fa fd c5 9d  80 c7 bf f8 91 09 d3 16    ...W............
00112   3c 81 e4 e6 72 e8 9b 54  33 62 67 8f 0d 0e 9d 73    <...r..T3bg....s
00128   5b d0 8f 5c b5 07 cd fc  55 5d 0a 05 e6 48 1c 66    [..\....U]...H.f

******************************************************************************

Output of ARP Packet:

******************************************************************************
******************************************************************************
****************************Packet Information********************************

Time Stamp: Sat Jan 12 11:40:26 2013
Ether Type: ARP
Packet Length: 60
Protocol Type: Unknown
Operation: ARP Request
Sender MAC: 3C:D0:F8:4E:4B:A1
Sender IP: 192.168.0.10
Target MAC: 00:00:00:00:00:00
Target IP: 169.254.255.255

******************************************************************************


The following fields are extracted from the packet to display :
1. Timestamp
2. Source and Destination MAC address.
3. Source and Destination IP.
4. Ether Type
5. Protocol
6. Source and Destination Port.
7. Packet Length
8. Payload


A makefile is also included for easy compilation. Output of live packet capturing and offline capturing using hw1.pcap is also included in the directory.

