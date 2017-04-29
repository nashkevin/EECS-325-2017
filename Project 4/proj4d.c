// 
// Kevin Nash (kjn33)
// proj4d.c
// 2017-04-28
// server for CANVAS
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define REQUIRED_ARGC 2
#define MAX_CMD_ARGS 4
#define MARK_ARGS 4
#define ERAS_ARGS 3
#define PRNT_ARGS 1
#define TIME_ARGS 1

#define CMD_CHARS 4

#define BUFLEN 2048

#define BLK  "\x1B[30m█\x1B[0m"
#define RED  "\x1B[31m█\x1B[0m"
#define GRN  "\x1B[32m█\x1B[0m"
#define YEL  "\x1B[33m█\x1B[0m"
#define BLU  "\x1B[34m█\x1B[0m"
#define MAG  "\x1B[35m█\x1B[0m"
#define CYN  "\x1B[36m█\x1B[0m"
#define WHT  "\x1B[37m█\x1B[0m"

#define COLS 32
#define ROWS 20


char *pic[ROWS][COLS] = {
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
    },
    {
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK,
        BLK, BLK, BLK, BLK, BLK, BLK, BLK, BLK
    }
};

char *testpic[ROWS][COLS] = {
    {
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
    },
    {
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
    },
    {
        BLU, BLU, WHT, WHT, WHT, WHT, WHT, WHT,
        WHT, WHT, WHT, BLU, BLU, BLU, BLU, BLU,
        WHT, WHT, WHT, WHT, WHT, BLU, BLU, BLU,
        WHT, WHT, WHT, WHT, WHT, BLU, BLU, BLU,
    },
    {
        WHT, WHT, WHT, WHT, WHT, WHT, WHT, WHT,
        WHT, WHT, WHT, WHT, WHT, WHT, BLU, BLU,
        WHT, WHT, WHT, WHT, BLU, BLU, WHT, WHT,
        WHT, WHT, WHT, WHT, WHT, WHT, WHT, WHT,
    },
    {
        WHT, WHT, WHT, WHT, WHT, WHT, WHT, WHT,
        WHT, WHT, WHT, WHT, WHT, WHT, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        WHT, WHT, WHT, WHT, WHT, WHT, WHT, WHT,
    },
    {
        WHT, WHT, WHT, WHT, WHT, WHT, WHT, WHT,
        WHT, WHT, WHT, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, WHT, WHT, WHT, WHT, WHT,
    },
    {
        WHT, WHT, WHT, WHT, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, YEL,
        YEL, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, WHT, WHT, WHT,
    },
    {
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, YEL,
        YEL, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
    },
    {
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
    },
    {
        WHT, WHT, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, WHT, WHT,
    },
    {
        WHT, WHT, WHT, WHT, WHT, CYN, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, CYN, WHT, WHT, WHT, WHT, WHT,
    },
    {
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
        CYN, CYN, BLU, BLU, BLU, BLU, BLU, BLU,
        BLU, BLU, BLU, BLU, BLU, BLU, CYN, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
    },
    {
        CYN, CYN, CYN, CYN, WHT, WHT, WHT, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, BLU, BLU,
        BLU, BLU, CYN, CYN, CYN, CYN, CYN, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
    },
    {
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
        CYN, CYN, CYN, CYN, CYN, CYN, CYN, CYN,
    },
    {
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
        GRN, GRN, GRN, GRN, GRN, GRN, YEL, YEL,
        YEL, YEL, GRN, GRN, GRN, GRN, GRN, GRN,
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
    },
    {
        GRN, GRN, RED, GRN, GRN, GRN, GRN, GRN,
        RED, GRN, GRN, GRN, GRN, YEL, YEL, YEL,
        YEL, YEL, YEL, GRN, GRN, GRN, GRN, GRN,
        GRN, RED, GRN, MAG, GRN, GRN, RED, GRN,
    },
    {
        GRN, GRN, GRN, GRN, GRN, GRN, MAG, GRN,
        GRN, GRN, GRN, GRN, YEL, YEL, YEL, YEL,
        YEL, YEL, YEL, YEL, GRN, GRN, GRN, GRN,
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
    },
    {
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
        GRN, GRN, GRN, YEL, YEL, YEL, YEL, YEL,
        YEL, YEL, YEL, YEL, YEL, GRN, GRN, GRN,
        GRN, GRN, GRN, GRN, RED, GRN, GRN, GRN,
    },
    {
        GRN, GRN, GRN, GRN, GRN, RED, GRN, GRN,
        GRN, GRN, YEL, YEL, YEL, YEL, YEL, YEL,
        YEL, YEL, YEL, YEL, YEL, YEL, GRN, GRN,
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
    },
    {
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN,
        GRN, YEL, YEL, YEL, YEL, YEL, YEL, YEL,
        YEL, YEL, YEL, YEL, YEL, YEL, YEL, GRN,
        GRN, GRN, GRN, GRN, GRN, GRN, GRN, GRN
    }
};

char *rowjoin(char *row[], int lim);

char *get_color(char *color) {
    if (0 == strcmp(color, "RED")) {
        return RED;
    }
    if (0 == strcmp(color, "GRN")) {
        return GRN;
    }
    if (0 == strcmp(color, "YEL")) {
        return YEL;
    }
    if (0 == strcmp(color, "BLU")) {
        return BLU;
    }
    if (0 == strcmp(color, "MAG")) {
        return MAG;
    }
    if (0 == strcmp(color, "CYN")) {
        return CYN;
    }
    if (0 == strcmp(color, "WHT")) {
        return WHT;
    }
    return NULL;
}

char *respond(char **args, int len) {
    if (MAX_CMD_ARGS < len) {
        return "Bad Request";
    }

    if (0 == strcmp(args[0], "MARK") && MARK_ARGS == len) {
        int x = atoi(args[1]);
        int y = atoi(args[2]);
        if (0 <= x && x < COLS && 0 <= y && y < ROWS) {
            char *color = get_color(args[3]);
            if (NULL != color) {
                pic[x][y] = color;
                return "MARK OK";
            }
            return "MARK Bad Color";
        }
        return "MARK Bad Coordinates";
    }
    if (0 == strcmp(args[0], "ERAS") && ERAS_ARGS == len) {
        int x = atoi(args[1]);
        int y = atoi(args[2]);
        if (0 <= x && x < COLS && 0 <= y && y < ROWS) {
            pic[x][y] = " ";
            return "ERAS OK";
        }
        return "ERAS Bad Coordinates";
    }
    if (0 == strcmp(args[0], "TIME") && TIME_ARGS == len) {;
        time_t t = time(NULL);
        char *out = asctime(localtime(&t));
        out[strlen(out) - 1] = 0;
        return out;
    }
    return "Request Failed";
}

char *rowjoin(char *row[], int lim) {
    char *str = NULL;
    size_t joinlen = 0;
    size_t len = 0;
    int i;
    for (i = 0; i < lim; i++) {
        joinlen += strlen(row[i]);
        if (row[i][strlen(row[i]) - 1] != '\n') {
            joinlen++;
        }
    }
    joinlen++;

    str = (char*)malloc(joinlen);
    str[0] = '\0';

    for (i = 0; i < lim; i++) {
        strcat(str, row[i]);
        len = strlen(str);

        if (str[len - 1] != '\n') {
            str[len + 1] = '\0';
        }
    }
    return str;
}

int main (int argc, char **argv) {
    int i;
    struct sockaddr_in srvaddr;
    struct sockaddr_in clntaddr;
    socklen_t addrlen = sizeof(srvaddr);
    int recvlen;
    int sd;
    char buffer[BUFLEN];

    if (argc != REQUIRED_ARGC) {
        fprintf (stderr, "usage: %s port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvaddr.sin_port = htons((u_short)atoi(argv[1]));

    if (srvaddr.sin_port < 1 || 65535 < atoi(argv[1])) {
        fprintf(stderr, "invalid port: %d\n", atoi(argv[1]));
        exit(EXIT_FAILURE);
    }

    if (bind(sd, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    printf("listening on port %hu\n", ntohs(srvaddr.sin_port));
    // begin listener loop
    for (;;) {
        recvlen = recvfrom(sd, buffer, BUFLEN, 0, (struct sockaddr *)&clntaddr, &addrlen);
        if (recvlen > 0) {
            buffer[recvlen] = 0;
            printf("client: %s\n", buffer);

            char *arg;
            char *args[MAX_CMD_ARGS];
            int len = 0;
            arg = strtok(buffer, " ");
            while (NULL != arg && len < MAX_CMD_ARGS) {
                args[len++] = arg;
                arg = strtok(NULL, " ");
            }

            int prnt_request = (0 == strcmp(args[0], "PRNT"));
            int test_request = (0 == strcmp(args[0], "TEST"));
            if (prnt_request || test_request) {
                for (i = 0; i < ROWS; i++) {
                    char *response;
                    if (test_request) {
                        response = rowjoin(testpic[i], COLS);
                    } else {
                        response = rowjoin(pic[i], COLS);
                    }
                    sprintf(buffer, "%s", response);
                    if (sendto(sd, buffer, strlen(buffer), 0,
                        (struct sockaddr *)&clntaddr, addrlen) < 0) {
                        perror("sendto");
                    }
                    else {
                        printf("server: %s\n", buffer);
                    }
                }
            }
            else {
                char *response = respond(args, len);
                sprintf(buffer, "%s", response);
                if (sendto(sd, buffer, strlen(buffer), 0,
                    (struct sockaddr *)&clntaddr, addrlen) < 0) {
                    perror("sendto");
                }
                else {
                    printf("server: %s\n", buffer);
                }
            }
        }
        else {
            fprintf(stderr, "listener error\n");
        }
    }
    // Merely here for robustness, unreachable
    close (sd);
    exit(EXIT_SUCCESS);
}
