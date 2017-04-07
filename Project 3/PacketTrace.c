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
/* One greater than the maximum number representable in six decimal digits */
#define US_DIGIT_MAX 1000000
/* The EtherType for IPv4 in decimal */
#define IP_ETHERTYPE 2048  // 0x0800
/* The size, in bytes, of words specified in the IHL field */
#define IHL_WORD_SIZE 4
/* The size, in bytes, of words specified in the data offset field */
#define TCP_WORD_SIZE 4
/* The size, in bytes, of a UDP header */
#define ETH_HEADER_LEN 14
/* The size of the fixed-length portion of an IPv4 header */
#define IP_HEADER_LEN 20
/* The size, in bytes, of a UDP header */
#define UDP_HEADER_LEN 8
/* The protrocol number for TCP */
#define TCP_PROTOCOL 6
/* The protrocol number for UDP */
#define UDP_PROTOCOL 17

/* Largest prime X such that (2^32 > 2 * (2^32 mod X) + 2 * 2^16 + 1) */
#define MAGIC_NUMBER 2147418083u
/* Arbitrary initial length for array of Connections :( */
#define INITIAL_LENGTH 100

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

typedef struct {
    /* A (mostly) unique identifier */
    uint32_t id;
    /* number of seconds since Unix epoch */
    uint32_t first_ts_s;
    /* number of microseconds following first_ts_s */
    uint32_t first_ts_us;
    /* number of seconds since Unix epoch */
    uint32_t last_ts_s;
    /* number of microseconds following last_ts_s */
    uint32_t last_ts_us;
    /* The originator IP address */
    uint8_t orig_IP[BYTES_IN_IPV4];
    /* The originator port number */
    uint16_t orig_port;
    /* The responder IP address */
    uint8_t resp_IP[BYTES_IN_IPV4];
    /* The responder port number */
    uint16_t resp_port;
    /* The protocol number, in decimal, of the transport protocol */
    uint8_t protocol;
    /* the number of packets sent from the originator to the responder */
    uint32_t o_to_r_pkts;
    /* the number of payload bytes from the originator to the responder */
    uint32_t o_to_r_bytes;
    /* the number of packets sent from the responder to the originator */
    uint32_t r_to_o_pkts;
    /* the number of payload bytes from the responder to the originator */
    uint32_t r_to_o_bytes;
} Connection;

void stream_bytes(FILE *trace_fileptr);
void dump_packet(Packet pkt);
void add_connection(Packet pkt);
uint32_t get_connection_id(Packet pkt);
void double_cxns_cap();
void print_connections();
void print_rtt(FILE *trace_fileptr);
uint16_t convert_2bytes_int(unsigned char *bytes, int index);
uint32_t convert_4bytes_int(unsigned char *bytes, int index);

/* array of connections and its utilities */
short int curr_cxns_size = INITIAL_LENGTH;
Connection *cxns;
short int num_unique_cxns = 0;

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

    /* initialize cxns */
    cxns = malloc(sizeof(*cxns) * INITIAL_LENGTH);
    if (!cxns) {
        fprintf(stderr, "Could not allocate memory for connection summaries");
        exit(EXIT_FAILURE);
    }

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
            perror("Error opening file");
            exit(EXIT_FAILURE);
        }
    }

    // Begin specified task
    stream_bytes(trace_fileptr);
    exit(EXIT_SUCCESS);
}

void stream_bytes(FILE *trace_fileptr) {
    /* reusable counting variable */
    int i = 0;
    /* reusable counting variable */
    int j = 0;
    /* model empty Packet */
    static const Packet emptyPacket;
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
                // printf("Set to ignore (%u < %u)\n", pkt.meta.caplen, MIN_PKT_SIZE);
            }
        }
        // Reached the end of the Ethernet header
        else if (ETH_TYPE_END == i) {
            for (j = 0; j < BYTES_IN_TYPE; j++) {
                pkt.Eth.EtherType[(BYTES_IN_TYPE - 1) - j] = bytes[i - j];
            }
            if (IP_ETHERTYPE != convert_2bytes_int(pkt.Eth.EtherType, BYTES_IN_TYPE - 1)) {
                pkt.ignore = 1;
                // printf("Set to ignore (%u != 2048)\n", convert_2bytes_int(pkt.Eth.EtherType, BYTES_IN_TYPE - 1));
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
            if (TCP_PROTOCOL != pkt.IP.protocol && UDP_PROTOCOL != pkt.IP.protocol) {
                pkt.ignore = 1;
                // printf("Set to ignore (%u not in {6, 17})\n", pkt.IP.protocol);
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
        else if (TCP_PROTOCOL == pkt.IP.protocol) {
            if (SEQ_NUM_END + pkt.IP.optlen == i) {
                pkt.trans.seq_number = convert_4bytes_int(bytes, i);
            }
            else if (ACK_NUM_END + pkt.IP.optlen == i) {
                pkt.trans.ack_number = convert_4bytes_int(bytes, i);
            }
            else if (TCP_DATA_OFFSET + pkt.IP.optlen == i) {
                pkt.trans.data_offset = HIGH_NIBBLE(bytes[i]) * TCP_WORD_SIZE;
                if (pkt.meta.caplen < ETH_HEADER_LEN + IP_HEADER_LEN +
                    pkt.IP.optlen + pkt.trans.data_offset) {
                    pkt.ignore = 1;
                    // printf("Set to ignore (%u < %u + %u + %u + %u)\n", pkt.meta.caplen, ETH_HEADER_LEN, IP_HEADER_LEN, pkt.IP.optlen, pkt.trans.data_offset);
                }
            }
        }
        else if (UDP_PROTOCOL == pkt.IP.protocol) {
            if (UDP_LEN_END + pkt.IP.optlen == i) {
                pkt.trans.length = convert_2bytes_int(bytes, i) - UDP_HEADER_LEN;
                if (pkt.meta.caplen < ETH_HEADER_LEN + IP_HEADER_LEN +
                    pkt.IP.optlen + UDP_HEADER_LEN) {
                    pkt.ignore = 1;
                    // printf("Set to ignore (%u < %u + %u + %u + %u)\n", pkt.meta.caplen, ETH_HEADER_LEN, IP_HEADER_LEN, pkt.IP.optlen, UDP_HEADER_LEN);
                }
            }
        }

        // Reached the end of the packet
        if (pkt.meta.caplen + META_END - 1 <= i) {
            // Packet is intact and of interest
            if (0 == pkt.ignore) {
                if (options.p) {
                    dump_packet(pkt);
                }
                else if (options.s) {
                    add_connection(pkt);
                }
            }
            pkt = emptyPacket;
            i = 0;
        } else {
            i++;
        }
    }
    if (options.s) {
        print_connections();
        free(cxns);
    }
}

void dump_packet(Packet pkt) {
    /* reusable counting variable */
    int i = 0;

    printf("%lu.%06lu ", (unsigned long)pkt.meta.timestamp_s,
                         (unsigned long)pkt.meta.timestamp_us);
    printf("%u", pkt.IP.src_IP[0]);
    for (i = 1; i < BYTES_IN_IPV4; i++) {
        printf(".%u", pkt.IP.src_IP[i]);
    }
    printf(" %u ", pkt.trans.src_port);
    printf("%u", pkt.IP.dst_IP[0]);
    for (i = 1; i < BYTES_IN_IPV4; i++) {
        printf(".%u", pkt.IP.dst_IP[i]);
    }
    printf(" %u", pkt.trans.dst_port);
    if (TCP_PROTOCOL == pkt.IP.protocol) {
        printf(" T ");
        uint16_t payload = pkt.IP.totlen - (pkt.IP.optlen +
            IP_HEADER_LEN + pkt.trans.data_offset);
        printf("%u ", payload);
        printf("%u ", pkt.trans.seq_number);
        printf("%u\n", pkt.trans.ack_number);
    }
    else if (UDP_PROTOCOL == pkt.IP.protocol) {
        printf(" U ");
        uint16_t payload = pkt.trans.length;
        printf("%d\n", payload);
    }
    else {
        printf(" ?\n");
    }
}

void add_connection(Packet pkt) {
    int i = 0;
    uint32_t id = get_connection_id(pkt);
    uint8_t id_is_new = 1;
    for (i = 0; i < num_unique_cxns; i++) {
        // This ID already exists
        if (cxns[i].id == id) {
            id_is_new = 0;
            cxns[i].last_ts_s = pkt.meta.timestamp_s;
            cxns[i].last_ts_us = pkt.meta.timestamp_us;
            // Source IP matches the originator IP
            if (convert_4bytes_int(pkt.IP.src_IP, BYTES_IN_IPV4 - 1) ==
                convert_4bytes_int(cxns[i].orig_IP, BYTES_IN_IPV4 - 1)) {
                cxns[i].o_to_r_pkts++;
                // The transport protocol is UDP
                if (UDP_PROTOCOL == pkt.IP.protocol) {
                    cxns[i].o_to_r_bytes += pkt.trans.length;
                }
                // We assume the transport protocol is TCP
                else {
                    cxns[i].o_to_r_bytes += pkt.IP.totlen -
                        (pkt.IP.optlen + IP_HEADER_LEN +
                         pkt.trans.data_offset);
                }
            }
            // We assume source IP must match responder IP
            else {
                cxns[i].r_to_o_pkts++;
                // The transport protocol is UDP
                if (UDP_PROTOCOL == pkt.IP.protocol) {
                    cxns[i].r_to_o_bytes += pkt.trans.length;
                }
                // We assume the transport protocol is TCP
                else {
                    cxns[i].r_to_o_bytes += pkt.IP.totlen -
                        (pkt.IP.optlen + IP_HEADER_LEN +
                         pkt.trans.data_offset);
                }
            }
            break;
        }
    }
    // This connection's combination of endpoints and protocol is new
    if (id_is_new) {
        // If the array is full, copy it into a larger array
        if (curr_cxns_size <= num_unique_cxns) {
            size_t newsize = sizeof(*cxns) * (curr_cxns_size * 2);
            Connection *cxns_new = realloc(cxns, newsize);
            if (!cxns_new) {
                fprintf(stderr, "Could not expand memory for additional connection summaries");
                exit(EXIT_FAILURE);
            }
            else {
                cxns = cxns_new;
                curr_cxns_size *= 2;
            }
        }
        cxns[num_unique_cxns].id = id;
        cxns[num_unique_cxns].first_ts_s = pkt.meta.timestamp_s;
        cxns[num_unique_cxns].first_ts_us = pkt.meta.timestamp_us;
        cxns[num_unique_cxns].last_ts_s = pkt.meta.timestamp_s;
        cxns[num_unique_cxns].last_ts_us = pkt.meta.timestamp_us;
        for (i = 0; i < BYTES_IN_IPV4; i++) {
            cxns[num_unique_cxns].orig_IP[i] = pkt.IP.src_IP[i];
        }
        cxns[num_unique_cxns].orig_port = pkt.trans.src_port;
        for (i = 0; i < BYTES_IN_IPV4; i++) {
            cxns[num_unique_cxns].resp_IP[i] = pkt.IP.dst_IP[i];
        }
        cxns[num_unique_cxns].resp_port = pkt.trans.dst_port;
        cxns[num_unique_cxns].protocol = pkt.IP.protocol;
        cxns[num_unique_cxns].o_to_r_pkts = 1;
        // The transport protocol is UDP
        if (UDP_PROTOCOL == pkt.IP.protocol) {
            cxns[num_unique_cxns].o_to_r_bytes = pkt.trans.length;
        }
        // We assume the transport protocol is TCP
        else {
            cxns[num_unique_cxns].o_to_r_bytes = pkt.IP.totlen -
                (pkt.IP.optlen + IP_HEADER_LEN +
                 pkt.trans.data_offset);
        }
        cxns[num_unique_cxns].r_to_o_pkts = 0;
        cxns[num_unique_cxns].r_to_o_bytes = 0;
        num_unique_cxns++;
    }
}

uint32_t get_connection_id(Packet pkt) {
    return convert_4bytes_int(pkt.IP.src_IP, BYTES_IN_IPV4 - 1) % MAGIC_NUMBER +
           convert_4bytes_int(pkt.IP.dst_IP, BYTES_IN_IPV4 - 1) % MAGIC_NUMBER +
           pkt.trans.src_port + pkt.trans.dst_port +
           ((UDP_PROTOCOL == pkt.IP.protocol) ? 1 : 0);
}

/**
 * When the array of connections reaches its capacity,
 * use this method to copy the connections into a new array
 * with twice the capacity of the original
 */
void double_cxns_cap() {
    int i = 0;
    Connection cxns_new[curr_cxns_size * 2];
    for (i = 0; i < curr_cxns_size; i++) {
        cxns_new[i] = cxns[i];
    }
    cxns = cxns_new;
    curr_cxns_size *= 2;
}

void print_connections() {
    int i;
    int j;
    uint32_t duration_s;
    uint32_t duration_us;
    for (i = 0; i < num_unique_cxns; i++) {
        printf("%lu.%06lu ", (unsigned long)cxns[i].first_ts_s,
                              (unsigned long)cxns[i].first_ts_us);
        duration_s = cxns[i].last_ts_s - cxns[i].first_ts_s;
        if (cxns[i].first_ts_us > cxns[i].last_ts_us) {
            duration_us = US_DIGIT_MAX - (cxns[i].first_ts_us - cxns[i].last_ts_us);
            duration_s--;
        } else {
            duration_us = cxns[i].last_ts_us - cxns[i].first_ts_us;
        }
        printf("%lu.%06lu ", (unsigned long)duration_s,
                             (unsigned long)duration_us);
        printf("%u", cxns[i].orig_IP[0]);
        for (j = 1; j < BYTES_IN_IPV4; j++) {
            printf(".%u", cxns[i].orig_IP[j]);
        }
        printf(" %u ", cxns[i].orig_port);
        printf("%u", cxns[i].resp_IP[0]);
        for (j = 1; j < BYTES_IN_IPV4; j++) {
            printf(".%u", cxns[i].resp_IP[j]);
        }
        printf(" %u ", cxns[i].resp_port);
        if (UDP_PROTOCOL == cxns[i].protocol) {
            printf("U ");
        }
        else if (TCP_PROTOCOL == cxns[i].protocol) {
            printf("T ");
        }
        else {
            printf("? ");
        }
        printf("%lu ", (unsigned long)cxns[i].o_to_r_pkts);
        printf("%lu ", (unsigned long)cxns[i].o_to_r_bytes);
        if (0 == cxns[i].r_to_o_pkts) {
            printf("? ?\n");
        }
        else {
            printf("%lu ", (unsigned long)cxns[i].r_to_o_pkts);
            printf("%lu\n", (unsigned long)cxns[i].r_to_o_bytes);
        }
    }
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
