#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "include/rudp.h"

#define TIMEOUT_SEC 2
#define MAX_SOCKETS 10
#define SWND_SIZE 10

typedef struct {
    int socket; 
    int packetlen;
    rudp_packet_t* packet;
} swnd_entry_t;

extern swnd_entry_t send_window[SWND_SIZE];
// Send window ring buffer
swnd_entry_t send_window[SWND_SIZE];

static int sent = 0;
static int count = 0;
static int front = 0;
static int rear = 0;

typedef struct {
    int socket_id;
    struct sockaddr_in address;
    int seqnum;
} socket_entry_t;

extern socket_entry_t socket_map[MAX_SOCKETS];

void enqueue_packet(int sock, rudp_packet_t* pkt, int len) {
    rudp_packet_t *packet = malloc(sizeof(rudp_packet_t) + len);
   

    packet->type = pkt->type;
    packet->seqnum = pkt->seqnum;
    memcpy(packet->payload, pkt->payload, len);
    while(count - sent > SWND_SIZE){
        return;
     }
    swnd_entry_t packet_entry;
    packet_entry.socket = sock;
    packet_entry.packetlen = len;
    packet_entry.packet = packet;

    send_window[rear] = packet_entry;
    rear = (rear + 1) % SWND_SIZE;
    count++;
}

static void dequeue_packet(void) {
    
    free(send_window[front].packet);
    send_window[front].packet = NULL;
    front = (front + 1) % SWND_SIZE;
    sent++;
    
}

void* sans_backend(void* unused) {
    struct timeval timeout = {.tv_sec = TIMEOUT_SEC, .tv_usec = 0};

    while (1) {
        if (count - sent > 0) {
            int i = front;
            while (i != rear) {
                swnd_entry_t* entry = &send_window[i];
                struct sockaddr* address = NULL;

                for (size_t j = 0; j < MAX_SOCKETS; j++) {
                    if (socket_map[j].socket_id == entry->socket) {
                        address = (struct sockaddr*)&socket_map[j].address;
                        break;
                    }
                }
                sendto(entry->socket, entry->packet, sizeof(rudp_packet_t) + entry->packetlen, 0, address, sizeof(struct sockaddr_in));
                 i=(i+1)%SWND_SIZE;
            }

            i = front;
            int curr_rear = rear;
            while (i != curr_rear) {
                swnd_entry_t* entry = &send_window[i];
                rudp_packet_t ack;

                setsockopt(entry->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                int bytes_received = recvfrom(entry->socket, &ack, sizeof(ack), 0, NULL, NULL);
                if (bytes_received > 0 && ack.type == ACK) {
                    if (ack.seqnum == send_window[front].packet->seqnum) {
                        i = (i+1)%SWND_SIZE;
                        dequeue_packet();
                    }
                } else {
                    break;  // Break if no valid ACK is received
                }
            }
        }
    }
    return NULL;
}
