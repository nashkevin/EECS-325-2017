// 
// Kevin Nash (kjn33)
// PacketTrace.c
// 2017-02-26
// [description goes here]
// 

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The number of bits in a byte, a constant as true as they come */
#define BITS_IN_BYTE 8
/* The number of bytes (octets) in a MAC address */
#define BYTES_IN_MAC 6
/* The number of bytes (octets) in the EtherType field */
#define BYTES_IN_TYPE 2
/* The number of bytes (octets) in an IPv4 address */
#define BYTES_IN_IPV4 4
/* The size, in bytes, of the word specified in the IHL field */
#define IHL_WORD_SIZE 4

/* The maximum number of bytes in a single packet */
#define BYTES_CACHED 66
/* The number of bytes in metadata */
#define META_LENGTH 12
/* One greater than the maximum number representable in six decimal digits */
#define US_DIGIT_MAX 1000000

/* Index of the first and last byte in the seconds timestamp */
#define TIME_S_START 0
#define TIME_S_END 3

/* Index of the first and last byte in the microseconds timestamp */
#define TIME_US_START 4
#define TIME_US_END 7

/* Index of the first and last byte in caplen */
#define CAPLEN_START 8
#define CAPLEN_END 9

/* Index of the first and last byte in the ignored segment */
#define IGNORED_START 10
#define IGNORED_END 11

/* Index of the first and last byte in the Ethernet header */
#define ETH_HEAD_START 12
#define ETH_HEAD_END 25

/* Index of the first and last byte in the fixed IP header */
#define IP_HEAD_START 26
#define IP_HEAD_END 45

/* The octal in an IP header that contains the TTL */
#define IP_TTL_OCT 8
/* The octal in an IP header that contains the transport protocol */
#define IP_PROT_OCT 9
/* The first octal in an IP header that contains the source address */
#define IP_SRC_OCT 12
/* The first octal in an IP header that contains the destination address */
#define IP_DST_OCT 16

/* Extracts the low nibble from a byte  */
#define LOW_NIBBLE(byte) ((byte) & 0x0F)


typedef struct {
    struct {
        /* number of seconds since Unix epoch */
        uint32_t timestamp_s;
        /* number of microseconds following timestamp_s */
        uint32_t timestamp_us;
        /* capture length, the number of bytes captured */
        uint16_t caplen;
    } metadata;

    struct {
        /* Signifies that the Ethernet header is truncated */
        uint8_t is_truncated;
        /* The destination MAC address stored as a byte array */
        uint8_t dst_MAC[BYTES_IN_MAC];
        /* The source MAC address stored as a byte array */
        uint8_t src_MAC[BYTES_IN_MAC];
        /* The EtherType field stored as a byte array */
        uint8_t EtherType[BYTES_IN_TYPE];
    } Ethernet;

    struct {
        /* Signifies that the packet is not an IP packet */
        uint8_t is_non_IP;
        /* Signifies that the IP header is truncated */
        uint8_t is_truncated;
        /* The length of the IP header in decimal */
        uint8_t headlen;
        /* The protocol number, in decimal, of the transport protocol */
        uint8_t protocol;
        /* The time to live in decimal */
        uint8_t ttl;
        /* The destination IP address stored as a byte array */
        uint8_t dst_IP[BYTES_IN_IPV4];
        /* The source IP address stored as a byte array */
        uint8_t src_IP[BYTES_IN_IPV4];
    } IP;
} Packet;

static struct {
    /* specifies printing a trace summary */
    uint8_t s;
    /* specifies printing Ethernet headers */
    uint8_t e;
    /* specifies printing IP headers */
    uint8_t i;
    /* specifies printing a count of packet types */
    uint8_t t;
    /* specifies printing a traffic matrix */
    uint8_t m;
} options;

void trace_summary(FILE *trace_fileptr);
void Ethernet_dump(FILE *trace_fileptr);
void IP_dump(FILE *trace_fileptr);
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
    while (-1 != (option = getopt(argc, argv, "r:seitm")))
    switch (option) {
        case 's':
            options.s = 1;
            option_cnt++;
            break;
        case 'e':
            options.e = 1;
            option_cnt++;
            break;
        case 'i':
            options.i = 1;
            option_cnt++;
            break;
        case 't':
            options.t = 1;
            option_cnt++;
            break;
        case 'm':
            options.m = 1;
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
    if (1 < option_cnt) {
        fprintf(stderr, "Specified multiple mutually exclusive options.\n");
        exit(EXIT_FAILURE);
    }
    // do nothing if the user asks for nothing
    else if (0 == option_cnt) {
        exit(EXIT_SUCCESS);
    }

    // Check whether an input filename was given
    if (trace_filename == NULL) {
        printf("Use of -r <filename> is required.\n");
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
    if (options.s) {
        trace_summary(trace_fileptr);
    }
    else if (options.e) {
        Ethernet_dump(trace_fileptr);
    }
    else if (options.i) {
        IP_dump(trace_fileptr);
    }
    else if (options.t) {
        // asd;
    }
    else if (options.m) {
        // asd;
    }

    exit(EXIT_SUCCESS);
}

/**
 * Prints a four line summary of the trace file
 */
void trace_summary(FILE *trace_fileptr) {
    /* reusable counting variable */
    int i = 0;
    /* total number of packets contained in the FILE */
    unsigned long packet_cnt = 0;
    /* the last packet in the file */
    Packet pkt_first;
    /* the last packet in the file */
    Packet pkt_last;
    pkt_last.metadata.caplen = BYTES_CACHED; // initialize to max caplen
    /* stores some of the most recent bytes read */
    unsigned char bytes[BYTES_CACHED] = {0};

    // Store the timestamp for the first packet
    for (i = 0; !feof(trace_fileptr) && i <= TIME_US_END; i++) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (TIME_S_END == i) {
            pkt_first.metadata.timestamp_s = convert_4bytes_int(bytes, i);
        }
        else if (TIME_US_END == i) {
            pkt_first.metadata.timestamp_us = convert_4bytes_int(bytes, i);
        }
    }
    while (!feof(trace_fileptr)) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (CAPLEN_END == i) {
            pkt_last.metadata.caplen = convert_2bytes_int(bytes, i);
        }
        // Reached the end of the packet
        if (i >= pkt_last.metadata.caplen + META_LENGTH - 1) {
            printf("packet_cnt before: %lu\n", packet_cnt);
            packet_cnt++;
            printf("packet_cnt after: %lu\n", packet_cnt);
            i = 0;
        } else {
            i++;
        }
    }
    pkt_last.metadata.timestamp_s = convert_4bytes_int(bytes, TIME_S_END);
    pkt_last.metadata.timestamp_us = convert_4bytes_int(bytes, TIME_US_END);

    printf("PACKETS: %lu\n", (unsigned long)packet_cnt);
    printf("FIRST: %lu.%06lu\n", (unsigned long)pkt_first.metadata.timestamp_s,
                                 (unsigned long)pkt_first.metadata.timestamp_us);
    printf("LAST: %lu.%06lu\n", (unsigned long)pkt_last.metadata.timestamp_s,
                                (unsigned long)pkt_last.metadata.timestamp_us);
    uint32_t duration_s = pkt_last.metadata.timestamp_s -
                          pkt_first.metadata.timestamp_s;
    uint32_t duration_us;
    if (pkt_first.metadata.timestamp_us > pkt_last.metadata.timestamp_us) {
        duration_us = US_DIGIT_MAX - (pkt_first.metadata.timestamp_us -
                                      pkt_last.metadata.timestamp_us);
        duration_s--;
    } else {
        duration_us = pkt_last.metadata.timestamp_us -
                      pkt_first.metadata.timestamp_us;
    }
    printf("DURATION: %lu.%06lu\n", (unsigned long)duration_s,
                                    (unsigned long)duration_us);
}

/**
 * Prints information from the Ethernet frames found in the trace file
 */
void Ethernet_dump(FILE *trace_fileptr) {
    /* reusable counting variable */
    int i = 0;
    /* reusable counting variable */
    int j = 0;
    /* the current packet */
    Packet pkt;
    // Zero all arrays so that we're not accidentally working with garbage
    memset(pkt.Ethernet.dst_MAC, 0, sizeof pkt.Ethernet.dst_MAC);
    memset(pkt.Ethernet.src_MAC, 0, sizeof pkt.Ethernet.src_MAC);
    memset(pkt.Ethernet.EtherType, 0, sizeof pkt.Ethernet.EtherType);

    /* stores some of the most recent bytes read */
    unsigned char bytes[BYTES_CACHED] = {0};

    i = 0;
    while (!feof(trace_fileptr)) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (TIME_S_END == i) {
            pkt.metadata.timestamp_s = convert_4bytes_int(bytes, i);
        }
        else if (TIME_US_END == i) {
            pkt.metadata.timestamp_us = convert_4bytes_int(bytes, i);
        }
        else if (CAPLEN_END == i) {
            pkt.metadata.caplen = convert_2bytes_int(bytes, i);
            pkt.Ethernet.is_truncated =
                (pkt.metadata.caplen > ETH_HEAD_END - META_LENGTH) ? 0 : 1;
        }
        // Reached the end of the Ethernet header
        else if (ETH_HEAD_END == i) {
            // Read bytes into destination MAC address
            for (j = 0; j < BYTES_IN_MAC; j++) {
                pkt.Ethernet.dst_MAC[j] = bytes[ETH_HEAD_START + j];
            }
            // Read bytes into source MAC address
            for (j = 0; j < BYTES_IN_MAC; j++) {
                pkt.Ethernet.src_MAC[j] = bytes[ETH_HEAD_START + BYTES_IN_MAC + j];
            }
            // Read bytes into EtherType
            for (j = 0; j < BYTES_IN_TYPE; j++) {
                pkt.Ethernet.EtherType[j] =
                    bytes[ETH_HEAD_START + (2 * BYTES_IN_MAC) + j];
            }
        }
        // Reached the end of the packet
        if (i >= pkt.metadata.caplen + META_LENGTH - 1) {
            printf("%lu.%06lu ", (unsigned long)pkt.metadata.timestamp_s,
                                 (unsigned long)pkt.metadata.timestamp_us);
            if (pkt.Ethernet.is_truncated) {
                printf("Ethernet-truncated\n");
            } else {
                printf("%02x", pkt.Ethernet.src_MAC[0]);
                for (j = 1; j < BYTES_IN_MAC; j++) {
                    printf(":%02x", pkt.Ethernet.src_MAC[j]);
                }
                printf(" %02x", pkt.Ethernet.dst_MAC[0]);
                for (j = 1; j < BYTES_IN_MAC; j++) {
                    printf(":%02x", pkt.Ethernet.dst_MAC[j]);
                }
                printf(" 0x");
                for (j = 0; j < BYTES_IN_TYPE; j++) {
                    printf("%02x", pkt.Ethernet.EtherType[j]);
                }
                printf("\n");
            }
            pkt.Ethernet.is_truncated = 0;
            i = 0;
        } else {
            i++;
        }
    }
}

/**
 * Prints information from the IP headers found in the trace file
 */
void IP_dump(FILE *trace_fileptr) {
    /* reusable counting variable */
    int i;
    /* reusable counting variable */
    int j;
    /* the current packet */
    Packet pkt;
    // Zero all arrays so that we're not accidentally working with garbage
    memset(pkt.Ethernet.dst_MAC, 0, sizeof pkt.Ethernet.dst_MAC);
    memset(pkt.Ethernet.src_MAC, 0, sizeof pkt.Ethernet.src_MAC);
    memset(pkt.Ethernet.EtherType, 0, sizeof pkt.Ethernet.EtherType);

    /* stores some of the most recent bytes read */
    unsigned char bytes[BYTES_CACHED] = {0};

    i = 0;
    while (!feof(trace_fileptr)) {
        unsigned char byte = fgetc(trace_fileptr);
        if (feof(trace_fileptr)) {
            break;
        }
        bytes[i] = byte;
        if (TIME_S_END == i) {
            pkt.metadata.timestamp_s = convert_4bytes_int(bytes, i);
        }
        else if (TIME_US_END == i) {
            pkt.metadata.timestamp_us = convert_4bytes_int(bytes, i);
        }
        else if (CAPLEN_END == i) {
            pkt.metadata.caplen = convert_2bytes_int(bytes, i);
            pkt.Ethernet.is_truncated =
                (pkt.metadata.caplen > ETH_HEAD_END - META_LENGTH) ? 0 : 1;
        }
        // Reached the end of the Ethernet header
        else if (ETH_HEAD_END == i) {
            // Read bytes into EtherType
            for (j = 0; j < BYTES_IN_TYPE; j++) {
                pkt.Ethernet.EtherType[j] =
                    bytes[ETH_HEAD_START + (2 * BYTES_IN_MAC) + j];
            }
            if (pkt.Ethernet.EtherType[0] != 0x08 ||
                pkt.Ethernet.EtherType[1] != 0x00) {
                pkt.IP.is_non_IP = 1;
            }
        }
        // Reached the end of the fixed IP header
        else if (IP_HEAD_END == i) {
            pkt.IP.headlen = LOW_NIBBLE(bytes[IP_HEAD_START]) * IHL_WORD_SIZE;
            pkt.IP.ttl = bytes[IP_HEAD_START + IP_TTL_OCT];
            pkt.IP.protocol = bytes[IP_HEAD_START + IP_PROT_OCT];
            for (j = 0; j < BYTES_IN_IPV4; j++) {
                pkt.IP.src_IP[j] = bytes[IP_HEAD_START + IP_SRC_OCT + j];
            }
            for (j = 0; j < BYTES_IN_IPV4; j++) {
                pkt.IP.dst_IP[j] = bytes[IP_HEAD_START + IP_DST_OCT + j];
            }
        }
        // Reached the end of the packet
        if (i >= pkt.metadata.caplen + META_LENGTH - 1) {
            printf("%lu.%06lu ", (unsigned long)pkt.metadata.timestamp_s,
                                 (unsigned long)pkt.metadata.timestamp_us);
            if (pkt.Ethernet.is_truncated) {
                printf("unknown\n");
            }
            else if (pkt.IP.is_truncated) {
                printf("IP-truncated\n");
            }
            else if (pkt.IP.is_non_IP) {
                printf("non-IP\n");
            }
            else {
                printf("%d", pkt.IP.src_IP[0]);
                for (j = 1; j < BYTES_IN_IPV4; j++) {
                    printf(".%d", pkt.IP.src_IP[j]);
                }
                printf(" %d", pkt.IP.dst_IP[0]);
                for (j = 1; j < BYTES_IN_IPV4; j++) {
                    printf(".%d", pkt.IP.dst_IP[j]);
                }
                printf(" %d", pkt.IP.headlen);
                printf(" %d", pkt.IP.protocol);
                printf(" %d\n", pkt.IP.ttl);
            }
            pkt.Ethernet.is_truncated = 0;
            pkt.IP.is_truncated = 0;
            pkt.IP.is_non_IP = 0;
            i = 0;
        } else {
            i++;
        }
    }
}

/**
 * Converts four bytes into a 32-bit integer
 */
uint32_t convert_4bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE
                    | bytes[index - 2] << (BITS_IN_BYTE * 2)
                    | bytes[index - 3] << (BITS_IN_BYTE * 3);
}

/**
 * Converts two bytes into a 16-bit integer
 */
uint16_t convert_2bytes_int(unsigned char *bytes, int index) {
    return bytes[index] | bytes[index - 1] << BITS_IN_BYTE;
}
