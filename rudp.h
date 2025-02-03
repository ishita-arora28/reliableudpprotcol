#ifndef RUDP_H
#define RUDP_H

#define DAT 0
#define SYN 1
#define ACK 2
#define SYNACK 3
#define FIN 4



typedef struct {
  char type;
  int seqnum;
  char payload[];
} rudp_packet_t;



int sans_send_pkt(int socket, const char* buf, int len);
int sans_recv_pkt(int socket, char* buf, int len);
int sans_disconnect(int socket);
int sans_connect(const char* addr, int port, int protocol);
int sans_accept(const char* addr, int port, int protocol);

#endif