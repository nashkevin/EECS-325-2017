// 
// Kevin Nash (kjn33)
// PacketTrace.c
// 2017-04-06
// [description goes here]
//

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* The number of bits in a byte, a constant as true as they come */
#define BITS_IN_BYTE 8
/* The minimum number of bytes in a single packet */
#define MIN_PKT_SIZE 42  // 14 Eth + 20 IP + 8 UDP (TCP would be larger at 20)
/* The maximum number of bytes in a single packet */
#define MAX_PKT_SIZE 65535
/* The EtherType for IPv4 in decimal */
#define IP_ETHERTYPE 2048  // 0x0800
/* The size, in bytes, of words specified in the IHL field */
#define IHL_WORD_SIZE 4
/* The size, in bytes, of words specified in the data offset field */
#define TCP_WORD_SIZE 4
/* The sinze, in bytes, of a UDP header */
#define ETH_HEADER_LEN 14
/* The size of the fixed-length portion of an IPv4 header */
#define IP_HEADER_LEN 20
/* The sinze, in bytes, of a UDP header */
#define UDP_HEADER_LEN 8

/* The number of bytes (octets) in the EtherType field */
#define BYTES_IN_TYPE 2
/* The number of bytes in an IPv4 address */
#define BYTES_IN_IPV4 4

/* Index of the last byte in the seconds timestamp */
#define TIME_S_END 3
/* Index of the last byte in the microseconds timestamp */
#define TIME_US_END 7
/* Index of the last byte in caplen */
#define CAPLEN_END 9
/* Index of the last byte of metadata */
#define META_END 12

/* Index of the last byte in the EtherType */
#define ETH_TYPE_END 25

/* Index of the byte containing the IHL in the IP header */
#define IP_IHL 26
/* Index of the last byte containing the total length of the IP packet */
#define IP_LEN_END 29
/* Index of the byte containing the transport protocol in the IP header */
#define IP_PROTOCOL 35
/* Index of the last byte containing the source IP address */
#define IP_SRC_END 41
/* Index of the last byte containing the destination IP address */
#define IP_DST_END 45

/******************************************************************
 * The following indices are given assuming no IP options present *
 ******************************************************************/

/* Index of the last byte containing the source port */
#define SRC_PORT_END 47
/* Index of the last byte containing the destination port */
#define DST_PORT_END 49

/* Index of the last byte containing the sequence number */
#define SEQ_NUM_END 53
/* Index of the last byte containing the acknowledgement number */
#define ACK_NUM_END 57
/* Index of the byte containing the data offset in the TCP header */
#define TCP_DATA_OFFSET 58

/* Index of the byte containing the length in the UDP header */
#define UDP_LEN_END 51

/* Extracts the low nibble from a byte  */
#define LOW_NIBBLE(byte) ((byte) & 0x0F)
/* Extracts the high nibble from a byte  */
#define HIGH_NIBBLE(byte) (((byte) & 0xF0) >> 4)


static struct {
    /* specifies printing a packet dump */
    uint8_t p;
    /* specifies printing connection summaries */
    uint8_t s;
    /* specifies printing RTTs */
    uint8_t t;
} options;

typedef struct {
    /* indicates that for whatever reason this packet should be ignored */
    uint8_t ignore;

    struct {
        /* number of seconds since Unix epoch */
        uint32_t timestamp_s;
        /* number of microseconds following timestamp_s */
        uint32_t timestamp_us;
        /* capture length, the number of bytes captured */
        uint16_t caplen;
    } meta;

    struct {
        /* The EtherType field */
        uint8_t EtherType[BYTES_IN_TYPE];
    } Eth;

    struct {
        /* The decimal number of bytes used for IP options */
        uint16_t optlen;
        /* The decimal number of bytes used for the entire IP packet */
        uint16_t totlen;
        /* The protocol number, in decimal, of the transport protocol */
        uint8_t protocol;
        /* The source IP address */
        uint8_t src_IP[BYTES_IN_IPV4];
        /* The destination IP address */
        uint8_t dst_IP[BYTES_IN_IPV4];
    } IP;

    struct {
        /* The source port number */
        uint16_t src_port;
        /* The destination port number */
        uint16_t dst_port;
        /* The sequence number of the packet */
        uint32_t seq_number;
        /* The acknowledgement number of the packet */
        uint32_t ack_number;
        /* The size of a TCP header in 32-bit words (20 min, 60 max bytes) */
        uint8_t data_offset;
        /* The length of a UDP header in bytes */
        uint16_t length;
    } trans;
} Packet;

void print_dump(FILE *trace_fileptr);
void print_summary(FILE *trace_fileptr);
void print_rtt(FILE *trace_fileptr);
uint16_t convert_2bytes_int(unsigned char *bytes, int index);
uint32_t convert_4bytes_int(unsigned char *bytes, int index);

int main(int argc, char **argv) {
    /* reusable counting variable */
    int i = 0;
    /* iterator for command line args */
    int option = 0;
    /* count of the optional flags provided */
    int option_cnt = 0;

    /* filename for the binary packet trace file */
    char *trace_filename = NULL;
    /* pointer to the file opened by trace_filename */
    FILE *trace_fileptr = NULL;

    /* external variable set to zero to override getopt error handling */
    opterr = 0;

    // Parse arguments
    while (-1 != (option = getopt(argc, argv, "r:pst")))
    switch (option) {
        case 'p':
            options.p = 1;
            option_cnt++;
            break;
        case 's':
            options.s = 1;
            option_cnt++;
            break;
        case 't':
            options.t = 1;
            option_cnt++;
            break;
        case 'r':
            trace_filename = optarg;
            break;
        case '?':
            if (optopt == 'r') {
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            }
            else if (isprint (optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            }
            else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
        default:
            exit(EXIT_FAILURE);
    }

    // Tell the user they typed something wrong
    for (i = optind; i < argc; i++) {
        fprintf(stderr, "Invalid argument: %s\n", argv[optind]);
        exit(EXIT_FAILURE); // Can be removed if we want to ignore unknown args
    }

    // Enforce mutual exclusion of options
    if (0 == option_cnt) {
        fprintf(stderr, "Specified no printing options.\n");
        exit(EXIT_FAILURE);
    }
    // Enforce mutual exclusion of options
    if (1 < option_cnt) {
        fprintf(stderr, "Specified multiple mutually exclusive options.\n");
        exit(EXIT_FAILURE);
    }
    // Check whether an input filename was given
    if (trace_filename == NULL) {
        fprintf(stderr, "Use of -r <filename> is required.\n");
        exit(EXIT_FAILURE);
    } else {
        // Attempt to open the specified file
        trace_fileptr = fopen(trace_filename, "rb");
        if (trace_fileptr == NULL) {
            perror("Error");
            exit(EXIT_FAILURE);
        }
    }

    // Begin specified task
    if (options.p) {
        print_dump(trace_fileptr);
    }
    else if (options.s) {
        print_summary(trace_fileptr);
    }
    else if (options.t) {
        print_rtt(trace_fileptr);
    }
    exit(EXIT_SUCCESS);
}

void print_dump(FILE *trace_fileptr) {
    /* reusable counting variable */
    int i = 0;
    /* reusable counting variable */
    int j = 0;
    /* the current packet */
    Packet pkt = {0};
    pkt.meta.caplen = MAX_PKT_SIZE; // initialize to max

    /* stores some of the most recent bytes read */
    unsigned char bytes[MAX_PKT_SIZE] = {0};

    i = 0;
    while (!feof(trace_fileptr)) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        // Start with metadata
        if (TIME_S_END == i) {
            pkt.meta.timestamp_s = convert_4bytes_int(bytes, i);
        }
        else if (TIME_US_END == i) {
            pkt.meta.timestamp_us = convert_4bytes_int(bytes, i);
        }
        else if (CAPLEN_END == i) {
            pkt.meta.caplen = convert_2bytes_int(bytes, i);
            if (pkt.meta.caplen < MIN_PKT_SIZE) {
                pkt.ignore = 1;
                printf("Set to ignore (1)\n");
            }
        }
        // Reached the end of the Ethernet header
        else if (ETH_TYPE_END == i) {
            for (j = 0; j < BYTES_IN_TYPE; j++) {
                pkt.Eth.EtherType[(BYTES_IN_TYPE - 1) - j] = bytes[i - j];
            }
            if (2048 != convert_2bytes_int(pkt.Eth.EtherType, BYTES_IN_TYPE - 1)) {
                pkt.ignore = 1;
                // printf("Set to ignore (2)\n");
            }
        }
        // Reached the begining of the fixed IP header
        else if (IP_IHL == i) {
            pkt.IP.optlen = (LOW_NIBBLE(bytes[i]) * IHL_WORD_SIZE) - IP_HEADER_LEN;
        }
        else if (IP_LEN_END == i) {
            pkt.IP.totlen = convert_2bytes_int(bytes, i);
        }
        else if (IP_PROTOCOL == i) {
            pkt.IP.protocol = bytes[i];
            if (6 != pkt.IP.protocol && 17 != pkt.IP.protocol) {
                pkt.ignore = 1;
                // printf("Set to ignore (3)\n");
            }
        }
        else if (IP_SRC_END + pkt.IP.optlen == i) {
            for (j = 0; j < BYTES_IN_IPV4; j++) {
                pkt.IP.src_IP[(BYTES_IN_IPV4 - 1)- j] = bytes[i - j];
            }
        }
        else if (IP_DST_END + pkt.IP.optlen == i) {
            for (j = 0; j < BYTES_IN_IPV4; j++) {
                pkt.IP.dst_IP[(BYTES_IN_IPV4 - 1)- j] = bytes[i - j];
            }
        }
        // Reached the begining of the transport header
        else if (SRC_PORT_END + pkt.IP.optlen == i) {
            pkt.trans.src_port = convert_2bytes_int(bytes, i);
        }
        else if (DST_PORT_END + pkt.IP.optlen == i) {
            pkt.trans.dst_port = convert_2bytes_int(bytes, i);
        }
        else if (6 == pkt.IP.protocol) {
            if (SEQ_NUM_END + pkt.IP.optlen == i) {
                pkt.trans.seq_number = convert_4bytes_int(bytes, i);
            }
            else if (ACK_NUM_END + pkt.IP.optlen == i) {
                pkt.trans.ack_number = convert_4bytes_int(bytes, i);
            }
            else if (TCP_DATA_OFFSET + pkt.IP.optlen == i) {
                pkt.trans.data_offset = HIGH_NIBBLE(bytes[i]) * TCP_WORD_SIZE;
                if (pkt.meta.caplen < pkt.trans.data_offset + pkt.IP.optlen +
                    IP_HEADER_LEN) {
                    pkt.ignore = 1;
                    printf("Set to ignore (4)\n");
                }
            }
        }
        else if (17 == pkt.IP.protocol) {
            if (UDP_LEN_END + pkt.IP.optlen == i) {
                pkt.trans.length = convert_2bytes_int(bytes, i) - UDP_HEADER_LEN;
                if (pkt.meta.caplen < ETH_HEADER_LEN + IP_HEADER_LEN +
                    pkt.IP.optlen + UDP_HEADER_LEN) {
                    pkt.ignore = 1;
                    printf("Set to ignore (5)\n");
                }
            }
        }

        // Reached the end of the packet
        if (pkt.meta.caplen + META_END - 1 <= i) {
            if (0 == pkt.ignore) {
                printf("%lu.%06lu ", (unsigned long)pkt.meta.timestamp_s,
                                     (unsigned long)pkt.meta.timestamp_us);
                printf("%u", pkt.IP.src_IP[0]);
                for (j = 1; j < BYTES_IN_IPV4; j++) {
                    printf(".%u", pkt.IP.src_IP[j]);
                }
                printf(" %u ", pkt.trans.src_port);
                printf("%u", pkt.IP.dst_IP[0]);
                for (j = 1; j < BYTES_IN_IPV4; j++) {
                    printf(".%u", pkt.IP.dst_IP[j]);
                }
                printf(" %u", pkt.trans.dst_port);
                if (6 == pkt.IP.protocol) {
                    printf(" T ");
                    uint16_t payload = pkt.IP.totlen - (pkt.IP.optlen +
                        IP_HEADER_LEN + pkt.trans.data_offset);
                    printf("%u ", payload);
                    printf("%u ", pkt.trans.seq_number);
                    printf("%u\n", pkt.trans.ack_number);
                }
                else if (17 == pkt.IP.protocol) {
                    printf(" U ");
                    uint16_t payload = pkt.trans.length;
                    printf("%d\n", payload);
                }
                else {
                    printf(" ?\n");
                }
            }
            pkt.ignore = 0;
            i = 0;
        } else {
            i++;
        }
    }
}

void print_summary(FILE *trace_fileptr) {
    ;
}

void print_rtt(FILE *trace_fileptr) {
    ;
}

/**
 * Converts two bytes into a 16-bit integer
 */
uint16_t convert_2bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE;
}

/**
 * Converts four bytes into a 32-bit integer
 */
uint32_t convert_4bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE
                    | bytes[index - 2] << (BITS_IN_BYTE * 2)
                    | bytes[index - 3] << (BITS_IN_BYTE * 3);
}
