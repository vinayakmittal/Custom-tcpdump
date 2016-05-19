#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include "arp_header.h"

void displayHelp()
{
	fprintf(stdout, "\nUsage : mydump [-i interface] [-r file] [-s string] [-h] expression\n");
	fprintf(stdout, "-i : Use this option to specify interface\n");
	fprintf(stdout, "-r : Use this option to specify tracefile\n");
	fprintf(stdout, "-s : Use this option to specify any string pattern\n");
	fprintf(stdout, "-h : Displays this help message\n");
	fprintf(stdout, "expression : Use this option to specify any BPF filter.\n");		
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
	int i;
	int gap;
	const u_char *ch;
		
	printf("%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		
		if (i == 7) {
			printf(" ");
		}
			
	}

	if (len < 8) {
		printf(" ");
	}
		

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}

	printf("   ");

	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch)) {
			printf("%c", *ch);
		}			
		else {
			printf(".");
		}			
		ch++;
	}

	printf("\n");

	return;
}

void display_payload(const u_char *payload, int len)
{
	int left_len = len;
	int line_width = 16;
	int line_len;
	int offset = 0;

	const u_char *ch = payload;

	if(len < 1)	{
		return;
	}

	if(len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	while(1)
	{
		line_len = line_width % left_len;
		print_hex_ascii_line(ch, line_len, offset);

		left_len = left_len - line_len;
		ch += line_len;
		offset += line_width;

		if(left_len <= line_width) {
			print_hex_ascii_line(ch, left_len, offset);
			break;
		}
	}

}

void display_info(char *timestamp, const u_int8_t *ether_dhost,const u_int8_t *ether_shost)
{
	int i=0;

	printf("******************************************************************************\n");
	printf("****************************Packet Information********************************\n\n");
	printf("Time Stamp: %s\n", timestamp);

	printf("Source MAC Address: ");
	for(i=0; i<6; i++) {
		printf("%x", ether_shost[i]);	
		(i == 5) ? printf("\n") : printf(":");
	}
	
	printf("Destination MAC Address: ");
	for(i=0; i<6; i++) {
		printf("%x", ether_dhost[i]);	
		(i == 5) ? printf("\n") : printf(":");
	}
}

void parse_packet(u_char *args, const struct pcap_pkthdr *pktHeader, const u_char *packet)
{
	const struct ether_header *etherHeader;
	const struct ip *ipHeader;
	const struct tcphdr *tcpHeader;
	const struct udphdr *udpHeader;
	const struct icmphdr *icmpHeader;
	const struct arphdr *arpHeader;
  	u_int size_ip, size_tcp;
  	u_int size_udp = 8, size_icmp = 8;
  	static char sender[INET_ADDRSTRLEN];
  	static char dest[INET_ADDRSTRLEN];
  	const char *payload;
  	char *pattern = NULL;
  	int size_payload, i=0;	

  	time_t orig_time = (time_t) pktHeader->ts.tv_sec;
	char *ptr = ctime(&orig_time);
	char timestamp[126];
	strcpy(timestamp, ptr);
	timestamp[strlen(timestamp)-1] = 0;

	if(args != NULL) {
		pattern = args;		
	}	

	etherHeader = (struct ether_header *) packet;
	
	if(ntohs(etherHeader->ether_type) == ETHERTYPE_IP) {		
		ipHeader = (struct ip *) (packet + sizeof(struct ether_header));
		size_ip = ipHeader->ip_hl * 4;		

		if(size_ip < 20) {
			printf("Invalid IP header length: %u bytes\n", size_ip);
			return;
		}		

	    switch(ipHeader->ip_p) {
	    	case IPPROTO_TCP:	    		
	    		tcpHeader = (struct tcphdr *) (packet + sizeof(struct ether_header) + size_ip);
	    		size_tcp = tcpHeader->th_off * 4;

	    		if(size_tcp < 20) {
	    			printf("Invalid TCP header length: %u bytes\n", size_tcp);
	    			return;
	    		}	    		

	    		payload = (u_char *) (packet + sizeof(struct ether_header) + size_ip + size_tcp);
	    		size_payload = ntohs(ipHeader->ip_len) - (size_ip + size_tcp);

	    		if(size_payload >= 0) {	    			
	    			char payload_data[size_payload];
	    			strncpy(payload_data, payload, size_payload);

	    			if(pattern && strstr(payload_data, pattern) == NULL) {
	    				return;
	    			}	    				

	    			display_info(timestamp, etherHeader->ether_dhost, etherHeader->ether_shost);
	    			printf("Ether Type: IPv4\n");		
	    			printf("Packet Length: %d\n", pktHeader->len);	    			
	    			printf("Source: %s Port: %d\n", inet_ntoa(ipHeader->ip_src), ntohs(tcpHeader->source));
	    			printf("Destination: %s Port: %d\n", inet_ntoa(ipHeader->ip_dst), ntohs(tcpHeader->dest));          		
	    			printf("Protocol: TCP\n\n");					
					printf("Payload (%d bytes):\n", size_payload);
	    			display_payload(payload, size_payload);
	    			printf("\n******************************************************************************\n");
	    		}

	    		break;

	    	case IPPROTO_UDP:	    		
	    		udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) + size_ip);
				
	    		payload = (u_char *) (packet + sizeof(struct ether_header) + size_ip + size_udp);
	    		size_payload = ntohs(ipHeader->ip_len) - (size_ip + size_udp);

	    		if(size_payload >= 0) {	    			
	    			char payload_data[size_payload];
	    			strncpy(payload_data, payload, size_payload);

	    			if(pattern && strstr(payload_data, pattern) == NULL) {
	    				return;
	    			}

	    			display_info(timestamp, etherHeader->ether_dhost, etherHeader->ether_shost);
	    			printf("Ether Type: IPv4\n");		
	    			printf("Packet Length: %d\n", pktHeader->len);	    			
	    			printf("Source: %s \tPort: %d\n", inet_ntoa(ipHeader->ip_src), ntohs(udpHeader->uh_sport));
	    			printf("Destination: %s \tPort: %d\n", inet_ntoa(ipHeader->ip_dst), ntohs(udpHeader->uh_dport));          			    		
	    			printf("Protocol: UDP\n\n");
					printf("Payload (%d bytes):\n", size_payload);
	    			display_payload(payload, size_payload);
	    			printf("\n******************************************************************************\n");
	    		}

	    		break;

	    	case IPPROTO_ICMP:	    		
	    		icmpHeader = (struct icmphdr *) (packet + sizeof(struct ether_header) + size_ip);				

	    		payload = (u_char *) (packet + sizeof(struct ether_header) + size_ip + size_icmp);
	    		size_payload = ntohs(ipHeader->ip_len) - (size_ip + size_icmp);

	    		if(size_payload >= 0) {	    			
	    			char payload_data[size_payload];
	    			strncpy(payload_data, payload, size_payload);

	    			if(pattern && strstr(payload_data, pattern) == NULL) {
	    				return;
	    			}

	    			display_info(timestamp, etherHeader->ether_dhost, etherHeader->ether_shost);
	    			printf("Ether Type: IPv4\n");		
	    			printf("Packet Length: %d\n", pktHeader->len);	    			
	    			printf("Source: %s \n", inet_ntoa(ipHeader->ip_src));
	    			printf("Destination: %s \n", inet_ntoa(ipHeader->ip_dst));          			    		
	    			printf("Protocol: ICMP\n\n");
					printf("Payload (%d bytes):\n", size_payload);
	    			display_payload(payload, size_payload);
	    			printf("\n******************************************************************************\n");
	    		}

	    		break;
	    
	    	default:	    		
	    		payload = (u_char *) (packet + sizeof(struct ether_header) + size_ip + size_icmp);
	    		size_payload = ntohs(ipHeader->ip_len) - size_ip;

	    		if(size_payload >= 0) {	    			
	    			char payload_data[size_payload];
	    			strncpy(payload_data, payload, size_payload);

	    			if(pattern && strstr(payload_data, pattern) == NULL) {
	    				return;
	    			}

	    			display_info(timestamp, etherHeader->ether_dhost, etherHeader->ether_shost);
	    			printf("Ether Type: IPv4\n");		
	    			printf("Packet Length: %d\n", pktHeader->len);	
	    			printf("Source: %s \n", inet_ntoa(ipHeader->ip_src));
	    			printf("Destination: %s \n", inet_ntoa(ipHeader->ip_dst));          			    		    				    			
	    			printf("Protocol: Other\n\n");
					printf("Payload (%d bytes):\n", size_payload);
	    			display_payload(payload, size_payload);
	    			printf("\n******************************************************************************\n");
	    		}

	    		break;
	    } 
	} else if(ntohs(etherHeader->ether_type) == ETHERTYPE_ARP) {
		printf("******************************************************************************\n");
		printf("****************************Packet Information********************************\n\n");
		printf("Time Stamp: %s\n", timestamp);
    	printf("Ether Type: ARP\n");
    	arpHeader = (struct arphdr *) (packet + sizeof(struct ether_header));
    	printf("Packet Length: %d\n", pktHeader->len);
    	printf("Protocol Type: %s\n", (ntohs(arpHeader->ptype == 0x0800) ? "IPv4" : "Unknown"));
    	printf("Operation: %s\n", (ntohs(arpHeader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

    	if(ntohs(arpHeader->htype) == 1 && ntohs(arpHeader->ptype) == 0x0800) {
    		printf("Sender MAC: "); 
		    for(i=0; i<6;i++) {
		    	printf("%02X", arpHeader->sha[i]); 
		    	(i == 5) ? printf("\n") : printf(":");
		    }
		        
		    printf("Sender IP: "); 
		    for(i=0; i<4;i++) {
		    	printf("%d", arpHeader->spa[i]); 
		    	(i == 3) ? printf("\n") : printf(".");
		    }
		        
		    printf("Target MAC: "); 
		    for(i=0; i<6;i++) {
		    	printf("%02X", arpHeader->tha[i]); 
		    	(i == 5) ? printf("\n") : printf(":");
		    }
		        
		    printf("Target IP: "); 
		    for(i=0; i<4; i++) {
		    	printf("%d", arpHeader->tpa[i]); 
		    	(i == 3) ? printf("\n") : printf(".");
		    }
		        		    		    
		    printf("\n******************************************************************************\n");
    	}
    } else {
    	printf("******************************************************************************\n");
		printf("****************************Packet Information********************************\n\n");
		printf("Time Stamp: %s\n", timestamp);
    	printf("Ether Type: Other\n");	   
    	printf("\n******************************************************************************\n"); 	
    }    
}

int main(int argc, char **argv)
{
	int i, c;
	pcap_t *descr;
	char *fName, *iName = NULL, *pattern = NULL, *expression;
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int isOffline = 0, isInterface = 0, isString = 0, isExpression = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	while((c = getopt(argc, argv, "i:r:s:h")) != -1) {

		switch(c) {
			case 'i':
				isInterface = 1;				
				iName = optarg;
				break;

			case 'r':
				isOffline = 1;
				fName = optarg;
				break;

			case 's':
				isString = 1;
				pattern = optarg;
				break;

			case 'h':
				displayHelp();
				goto exit_point;
				break;

			case '?':
				displayHelp();				
				goto exit_point;
				break;
		}
	}
	
	if(isInterface == 1 && isOffline == 1) {
		displayHelp();
		goto exit_point;
	}

	if(optind < argc) {
		expression = argv[optind];
		isExpression = 1;	
	}

	if(!isOffline)
	{
		if(iName == NULL) {
			iName = pcap_lookupdev(errbuf);

			if(iName == NULL) {
				printf("%s\n", errbuf);
				goto exit_point;
			}	
		}

		printf("Sniffing Device : %s\n", iName);

		if(pcap_lookupnet(iName, &net, &mask, errbuf) == -1) {
			printf("Error in getting netmask for device : %s\n", iName);
			net = 0;
			mask = 0;
		}

		descr = pcap_open_live(iName, BUFSIZ, 1, 1000, errbuf);

		if(descr == NULL) {
			printf("pcap_open_live(): %s\n", errbuf);
			goto exit_point;
		}

		if(pcap_datalink(descr) != DLT_EN10MB) {
			printf("%s is not ethernet!\n", iName);
			goto exit_point;
		}		
	} else {		
		descr = pcap_open_offline(fName, errbuf);
		if (descr == NULL) {
		  printf("pcap_open_live(): %s\n", errbuf);
		  goto exit_point;
		}		
	}

	if(isExpression){		
		if(pcap_compile(descr, &fp, expression, 0, net) == -1) {
			printf("Error in parsing filter: %s\n", expression);
			goto exit_point;
		}

		if(pcap_setfilter(descr, &fp) == -1) {
			printf("Error in installing filter: %s\n", expression);
			goto exit_point;
		}
	}

	pcap_loop(descr, 0, parse_packet, pattern);		  
	pcap_close(descr);
	printf("Finished capturing packets!\n");

exit_point:
	return 0;
}