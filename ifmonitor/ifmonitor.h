#ifndef IFMONITOR_H
#define IFMONITOR_H

#include <linux/types.h>
#include <pcap/pcap.h>
#include "list.h"

struct ethernet_frame {
    __u8 dest_mac[6];
    __u8 src_mac[6];
    __u16 type;
    __u8 data[];
};

struct ip_packet {
    __u8 reserved1[2];
    __u16 length;
    __u32 reserved2[2];
    __u32 src_ip;
    __u32 dst_ip;
    __u8 data[];
};

struct link_transfer {
    struct list_head list;
    __u32 src_ip;       // network bytes order
    __u32 dst_ip;       // network bytes order
    __u16 src2dst_len;  // host bytes order
    __u16 dst2src_len;  // host bytes order
};

#define STATE_BUFFER_LENGTH 10
struct state_info {
    int curr_index;
    __u32 bandwidth_in[STATE_BUFFER_LENGTH];  // in byte
    __u32 bandwidth_out[STATE_BUFFER_LENGTH];  // in byte
    struct list_head link_list;
    pthread_mutex_t link_list_mutex;
    int link_count;
};

struct thread_info {
    struct list_head list;
    pthread_t th;

#define ETHERNET    0
#define RAW         1
    int data_link;
    int if_is_p2p;
    char if_name[64];
    __u32 if_addr;
    __u32 if_network;
    __u32 if_netmask;
    __u32 if_broadaddr;
    __u32 if_dstaddr;
    pcap_t *handle;

#define FILTER_EXP_LEN  256
    char filter_expression[FILTER_EXP_LEN];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    __u32 bytes_in;
    __u32 bytes_out;
    struct state_info if_state;

    struct list_head trans_list;
    pthread_mutex_t trans_list_mutex;
    __u32 trans_count;
};

#endif /* IFMONITOR_H */
