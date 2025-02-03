#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include "include/sans.h"
#include "include/rudp.h"


#define MAX_SOCKETS 10
#define PKT_LEN 1400
#define MAX_RETRIES 10
#define MAX_PORT_STR_LEN 10

typedef struct {
    int socket_id;
    struct sockaddr_in address;
    int seqnum;
} socket_entry_t;

socket_entry_t socket_map[MAX_SOCKETS];

int add_socket_entry(int sfd, struct sockaddr_in addr) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_map[i].socket_id == 0) {
            socket_map[i].socket_id = sfd;
            socket_map[i].address = addr;
            socket_map[i].seqnum = 2;
            printf("Socket added: id=%d, index=%d\n", sfd, i);
            return 0;
        }
    }
    fprintf(stderr, "No available slot for socket %d\n", sfd);
    return -1;
}

int sans_connect(const char* host, int port, int protocol) {
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_RUDP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    struct addrinfo hints, *result, *rp;
    int sfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = (protocol == IPPROTO_RUDP) ? SOCK_DGRAM : SOCK_STREAM;

    char port_str[MAX_PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host, port_str, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        if (protocol == IPPROTO_TCP) {
            if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
                close(sfd);
                sfd = -1;
                continue;
            }
            break;
        } else {
            struct timeval timeout = { .tv_usec = 200000 };
            setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            rudp_packet_t request = { .type = SYN, .seqnum = 0 };
            int retries = 0;
            while (retries < MAX_RETRIES) {
                int bytes_sent = sendto(sfd, &request, sizeof(request), 0, rp->ai_addr, rp->ai_addrlen);
                if (bytes_sent < 0) {
                    perror("Error with sending SYN");
                    continue;
                }

                rudp_packet_t response;
                int bytes_received = recvfrom(sfd, &response, sizeof(response), 0, rp->ai_addr, &rp->ai_addrlen);
                if (bytes_received > 0 && (response.type & SYN) && (response.type & ACK)) {
                    rudp_packet_t ack_packet = { .type = ACK, .seqnum = 1 };
                    sendto(sfd, &ack_packet, sizeof(ack_packet), 0, rp->ai_addr, rp->ai_addrlen);
                    if (add_socket_entry(sfd, *(struct sockaddr_in *)rp->ai_addr) == -1) {
                        close(sfd);
                        sfd = -1;
                    }
                    break;
                }
                retries++;
            }
            if (retries == MAX_RETRIES) {
                close(sfd);
                sfd = -1;
            }
        }
    }

    freeaddrinfo(result);
    return sfd;
}

int sans_accept(const char* iface, int port, int protocol) {
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_RUDP) {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    struct addrinfo hints, *result, *rp;
    int sfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = (protocol == IPPROTO_RUDP) ? SOCK_DGRAM : SOCK_STREAM;

    char port_str[MAX_PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(iface, port_str, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            perror("Bind failed");
            close(sfd);
            sfd = -1;
            continue;
        }

        if (protocol == IPPROTO_TCP) {
            if (listen(sfd, MAX_SOCKETS) == -1) {
                close(sfd);
                sfd = -1;
                continue;
            }
            if (add_socket_entry(sfd, *(struct sockaddr_in *)rp->ai_addr) == -1) {
                close(sfd);
                sfd = -1;
            }
            int new_socket = accept(sfd, NULL, NULL);
            close(sfd);
            return new_socket;
        } else {
            while (1) {
                rudp_packet_t request;
                int bytes_received = recvfrom(sfd, &request, sizeof(request), 0, rp->ai_addr, &rp->ai_addrlen);
                if (bytes_received > 0 && request.type & SYN) {
                    int x = 0;
                    struct timeval timeout = { .tv_usec = 200000 };
                    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    rudp_packet_t syn_ack_packet, ack_packet;
                    syn_ack_packet.type = SYN | ACK;
                    syn_ack_packet.seqnum = request.seqnum;
                    while (x < MAX_RETRIES) {
                        int bytes_sent = sendto(sfd, &syn_ack_packet, sizeof(rudp_packet_t), 0, rp->ai_addr, rp->ai_addrlen);
                        if (bytes_sent < 0) {
                            perror("Error with sending syn-ack");
                        }
                        int bytes_received = recvfrom(sfd, &ack_packet, sizeof(ack_packet), 0, rp->ai_addr, &rp->ai_addrlen);
                        if (bytes_received >= 0) {
                            if (add_socket_entry(sfd, *(struct sockaddr_in *)rp->ai_addr) == -1) {
                                close(sfd);
                                return -1;
                            }
                            return sfd;
                        } else {
                            perror("Error receiving ACK");
                        }
                    }
                }
            }
        }
    }

    freeaddrinfo(result);
    return -1;
}

int sans_disconnect(int socket) {
    if (socket != -1) {
        for (int i = 0; i < MAX_SOCKETS; i++) {
            if (socket_map[i].socket_id == socket) {
                close(socket);
                socket_map[i].socket_id = 0;
                return 0;
            }
        }
    }
    return -1;
}