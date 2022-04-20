#include <stdio.h>	//for printf
#include <stdlib.h>
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <sys/types.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/in.h>
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
// #include <unistd.h> // sleep()

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}


int main(){
    int client_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(client_socket == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

    char recv_packet[500], datagram[500], source_ip[32], *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 500);

	strcpy(source_ip, "10.0.0.1");

    //server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(25000);
    server_address.sin_addr.s_addr = inet_addr("10.0.0.2");

    //IP header
    struct iphdr *recv_iph = (struct iphdr *) recv_packet, *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *recv_tcph = (struct tcphdr *) (recv_packet + sizeof (struct iphdr)), *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct pseudo_header psh;

    //Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = server_address.sin_addr.s_addr;
    //Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    //TCP Header
	tcph->source = htons (25000);
	tcph->dest = server_address.sin_port;
	tcph->seq = htonl(0);
	tcph->ack_seq = htonl(0);
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

    //Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = server_address.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (client_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    //Send the packet
    if (sendto (client_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
    {
        perror("sendto failed");
    }
    //Data send successfully
    else
    {
        printf ("SYN packet Send. Length : %d \n" , iph->tot_len);
    }

while(1) {
        if(recvfrom(client_socket, recv_packet, 500, 0, NULL, NULL)>0 && (recv_tcph->syn == 1) && (recv_tcph->ack == 1)){

            printf("Packet received. Length: %d\n", recv_iph->tot_len);

            //Fill in the IP Header
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
            iph->id = htonl (43210);	//Id of this packet
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;		//Set to 0 before calculating checksum
            iph->saddr = recv_iph->daddr;	//Spoof the source ip address
            iph->daddr = recv_iph->saddr;

            //Ip checksum
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);

            //TCP Header
            tcph->source = recv_tcph->dest;
            tcph->dest = recv_tcph->source;
            tcph->seq = htonl(ntohl(recv_tcph->seq)+1);
            tcph->ack_seq = htonl(ntohl(recv_tcph->ack_seq)) ;
            tcph->doff = 5;	//tcp header size
            tcph->fin=0;
            tcph->syn=0;
            tcph->rst=0;
            tcph->psh=0;
            tcph->ack=1;
            tcph->urg=0;
            tcph->window = htons (5840);	/* maximum allowed window size */
            tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
            tcph->urg_ptr = 0;

            //Now the TCP checksum
            psh.source_address = recv_iph->daddr;
            psh.dest_address = recv_iph->saddr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));

            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
            pseudogram = malloc(psize);
            
            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
            
            tcph->check = csum( (unsigned short*) pseudogram , psize);

            //IP_HDRINCL to tell the kernel that headers are included in the packet
            int one = 1;
            const int *val = &one;
            
            if (setsockopt (client_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            {
                perror("Error setting IP_HDRINCL");
                exit(0);
            }

            //Send the packet
            if (sendto (client_socket, datagram, iph->tot_len ,	0, (struct sockaddr *) &server_address, sizeof (server_address)) < 0)
            {
                perror("sendto failed");
            }
            //Data send successfully
            else
            {
                printf ("ACK packet Sent. Length : %d \n" , iph->tot_len);
                break;
            }
        }
    }

    return 0;
}
