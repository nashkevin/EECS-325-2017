// 
// Kevin Nash (kjn33)
// proj4.c
// 2017-04-28
// client for CANVAS
//
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define REQUIRED_ARGC 3
#define HOST_POS 1
#define PORT_POS 2
#define BUFLEN 2048

#define COLORSIZE 384
#define ROWS 20


int main (int argc, char **argv) { 
    struct sockaddr_in srvaddr;
    struct hostent *hostinfo;
    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(srvaddr);
    int recvlen;
    int sd;
    char buffer[BUFLEN];

    if (argc != REQUIRED_ARGC) {
        fprintf (stderr, "Usage: %s host port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    hostinfo = gethostbyname(argv[HOST_POS]);
    if (NULL == hostinfo) {
        fprintf(stderr, "Cannot find name: %s\n", argv[HOST_POS]);
    }

    sd = socket(AF_INET, SOCK_DGRAM, 0);

    if (-1 == (sd = socket(AF_INET, SOCK_DGRAM, 0))) {
        printf("Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    memset((char *)&clntaddr, 0, sizeof(clntaddr));
    clntaddr.sin_family = AF_INET;
    clntaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clntaddr.sin_port = htons(0);

    if (bind(sd, (struct sockaddr *)&clntaddr, sizeof(clntaddr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    memset((char *) &srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons((u_short)atoi(argv[PORT_POS]));
    memcpy((char *) &srvaddr.sin_addr, hostinfo->h_addr,hostinfo->h_length);
    
    if (srvaddr.sin_port < 1 || 65535 < atoi(argv[1])) {
        fprintf(stderr, "Invalid port: %d\n", atoi(argv[1]));
        exit(EXIT_FAILURE);
    }

    printf("Ready to send to %s:%hu\n", inet_ntoa(srvaddr.sin_addr), ntohs(srvaddr.sin_port));
    for (;;) {
        printf("> ");
        char operation[BUFLEN];
        scanf ("%[^\n]%*c", operation);
        sprintf(buffer, "%s", operation);
        if (sendto(sd, buffer, strlen(buffer), 0, (struct sockaddr *)&srvaddr, addrlen) == -1) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        recvlen = recvfrom(sd, buffer, BUFLEN, 0, (struct sockaddr *)&srvaddr, &addrlen);
        if (COLORSIZE == recvlen) {
            int i;
            for (i = 1; i < ROWS && 0 <= recvlen; i++) {
                buffer[recvlen] = 0;
                printf("server: %s\n", buffer);
                recvlen = recvfrom(sd, buffer, BUFLEN, 0, (struct sockaddr *)&srvaddr, &addrlen);
            }
        }
        else if (0 <= recvlen) {
            buffer[recvlen] = 0;
            printf("server: %s\n", buffer);
        }
    }
    close(sd);
    exit(EXIT_SUCCESS);
}
