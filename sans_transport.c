#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include "include/sans.h"
#include "include/rudp.h"

#define MAX_SOCKETS 10
#define TIMEOUT_SEC 2
#define MAX_RETRIES 5

typedef struct {
    int sock_id;
    struct sockaddr_in address;
    int seqnum;
} socket_entry_t;

extern socket_entry_t socket_map[MAX_SOCKETS];
void enqueue_packet(int sock, rudp_packet_t* pkt, int len);

// static int timeout_func(int socket, int seconds) {
//     struct timeval timeout;
//     timeout.tv_sec = seconds;
//     timeout.tv_usec = 0;
//     return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
// }
int sans_send_pkt(int socket, const char* buf, int len) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_map[i].sock_id == socket) {
            rudp_packet_t* pkt = malloc(sizeof(rudp_packet_t) + len);
            if (!pkt) {
                return -1;
            }
            
            pkt->type = DAT;
            pkt->seqnum = socket_map[i].seqnum;
            memcpy(pkt->payload, buf, len);
            
            // Enqueue packet to send window
            enqueue_packet(socket, pkt, len);
            socket_map[i].seqnum++;
            free(pkt);
            return len;
        }
    }
    return -1;
}

int sans_recv_pkt(int socket, char* buf, int len) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_map[i].sock_id == socket) {
            rudp_packet_t* pkt = malloc(sizeof(rudp_packet_t) + len);
            if (!pkt) {
                return -1;
            }

            while (1) {
                socklen_t addrlen = sizeof(socket_map[i].address);
                int bytes_received = recvfrom(socket, pkt, sizeof(rudp_packet_t) + len, 0,
                                           (struct sockaddr*)&socket_map[i].address, &addrlen);
                
                if (bytes_received > 0 && pkt->type == DAT) {
                    rudp_packet_t ack_pkt;
                    ack_pkt.type = ACK;
                    
                    if (pkt->seqnum == socket_map[i].seqnum) {
                        ack_pkt.seqnum = pkt->seqnum;
                        sendto(socket, &ack_pkt, sizeof(ack_pkt), 0,
                               (struct sockaddr*)&socket_map[i].address,
                               sizeof(socket_map[i].address));
                        
                        int payload_size = bytes_received - sizeof(rudp_packet_t);
                        memcpy(buf, pkt->payload, payload_size);
                        socket_map[i].seqnum++;
                        free(pkt);
                        return payload_size;
                    } else {
                        ack_pkt.seqnum = socket_map[i].seqnum - 1;
                        sendto(socket, &ack_pkt, sizeof(ack_pkt), 0,
                               (struct sockaddr*)&socket_map[i].address,
                               sizeof(socket_map[i].address));
                        continue;
                    }
                }
            }
            free(pkt);
        }
    }
    return -1;
}
