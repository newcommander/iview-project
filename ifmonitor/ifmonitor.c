#define _GNU_SOURCE
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
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
};

static struct list_head thread_list;

static void packet_process(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct thread_info *info = (struct thread_info*)arg;
    struct ethernet_frame *frame = NULL;
    struct ip_packet *pkt = NULL;
    char ip_addr_buf[INET_ADDRSTRLEN], ip_addr_buf1[INET_ADDRSTRLEN];

    if (!info) {
        printf("packet_process: Invalid parameter.\n");
        return;
    }

    switch (info->data_link) {
    case ETHERNET:
        frame = (struct ethernet_frame*)packet;
#if 0
        if (htons(frame->type) != 0x0800)  // IPv4
            return;
#endif
        pkt = (struct ip_packet*)frame->data;
        break;
    case RAW:
        pkt = (struct ip_packet*)packet;
        break;
    default:
        printf("[%s] Invalid data link type: %d.\n", info->if_name, info->data_link);
        return;
    }

    inet_ntop(AF_INET, &pkt->src_ip, ip_addr_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &pkt->dst_ip, ip_addr_buf1, INET_ADDRSTRLEN);
    printf("[%s]: %s > %s, length=%d\n", info->if_name, ip_addr_buf, ip_addr_buf1, ntohs(pkt->length));

#if 0
    int i;
    for (i = 0; i < header->len; i++) {
        printf("%02X ", packet[i]);
        if (i == 0)
            continue;
        else if ((i % 16) == 15)
            printf("\n");
        else if ((i % 16) == 7)
            printf(" ");
    }
    printf("\n");
#endif
}

static int get_device_config(struct thread_info *info)
{
    struct sockaddr_in *sin;
    struct ifreq ifr;
    int fd = 0, len;

    if (!info || !info->if_name)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[%s] Create socket failed: %s\n", info->if_name, strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    len = sizeof(ifr.ifr_name) < strlen(info->if_name) ? sizeof(ifr.ifr_name) : strlen(info->if_name);
    strncpy(ifr.ifr_name, info->if_name, len);
    ifr.ifr_addr.sa_family = AF_INET;

    /*cmds defined in linux/sockios.h */
    if (ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) < 0) {
        printf("[%s] SIOCGIFFLAGS: %s\n", info->if_name, strerror(errno));
        close(fd);
        return -1;
    }
    if (ifr.ifr_flags & IFF_POINTOPOINT)
        info->if_is_p2p = 1;
    else
        info->if_is_p2p = 0;

    if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) < 0) {
        if (errno == EADDRNOTAVAIL)
            printf("[%s] address not assigned\n", info->if_name);
        else
            printf("[%s] SIOCGIFADDR: %s\n", info->if_name, strerror(errno));
        close(fd);
        return -1;
    }
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    info->if_addr = (__u32)sin->sin_addr.s_addr;

    if (info->if_is_p2p) {
        if (ioctl(fd, SIOCGIFDSTADDR, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFDSTADDR: %s\n", info->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        info->if_dstaddr = (__u32)sin->sin_addr.s_addr;
    } else {
        if (ioctl(fd, SIOCGIFNETMASK, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFNETMASK: %s\n", info->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        info->if_netmask = (__u32)sin->sin_addr.s_addr;
        info->if_network = info->if_addr & info->if_netmask;

        if (ioctl(fd, SIOCGIFBRDADDR, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFBRDADDR: %s\n", info->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        info->if_broadaddr = (__u32)sin->sin_addr.s_addr;
    }

#if 0
    char ip_addr_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->if_addr, ip_addr_buf, INET_ADDRSTRLEN);
    printf("addr: %s\n", ip_addr_buf);
    if (info->if_is_p2p) {
        inet_ntop(AF_INET, &info->if_dstaddr, ip_addr_buf, INET_ADDRSTRLEN);
        printf("dstaddr: %s\n", ip_addr_buf);
    } else {
        inet_ntop(AF_INET, &info->if_netmask, ip_addr_buf, INET_ADDRSTRLEN);
        printf("netmask: %s\n", ip_addr_buf);
        inet_ntop(AF_INET, &info->if_network, ip_addr_buf, INET_ADDRSTRLEN);
        printf("network: %s\n", ip_addr_buf);
        inet_ntop(AF_INET, &info->if_broadaddr, ip_addr_buf, INET_ADDRSTRLEN);
        printf("broadaddr: %s\n", ip_addr_buf);
    }
#endif

    close(fd);
    return 0;
}

void* thread_fn(void *arg)
{
    struct thread_info *info = (struct thread_info*)arg;
    int ret, i, *dl_list = NULL;

    if (!info)
        return NULL;

    if (get_device_config(info) < 0) {
        printf("[%s]: Get device config failed.\n", info->if_name);
        return NULL;
    }

    info->handle = pcap_create(info->if_name, info->errbuf);
    if (!info->handle) {
        printf("[%s] Create handle failed: %s\n", info->if_name, info->errbuf);
        return NULL;
    }

    ret = pcap_activate(info->handle);
    if (ret < 0) {
        switch (ret) {
        case PCAP_ERROR_ACTIVATED:
            printf("[%s] The handle has already been activated.\n", info->if_name);
            break;
        case PCAP_ERROR_NO_SUCH_DEVICE:
            printf("[%s] The capture source doesn't exist.\n", info->if_name);
            break;
        case PCAP_ERROR_PERM_DENIED:
            printf("[%s] The process doesn't have permission to open the capture source.\n", info->if_name);
            break;
        case PCAP_ERROR_PROMISC_PERM_DENIED:
            printf("[%s] The process doesn't have permission to put it into promiscuous mode.\n", info->if_name);
            break;
        case PCAP_ERROR_RFMON_NOTSUP:
            printf("[%s] The capture source doesn't support monitor mode.\n", info->if_name);
            break;
        case PCAP_ERROR_IFACE_NOT_UP:
            printf("[%s] The capture source device is not up.\n", info->if_name);
            break;
        case PCAP_ERROR:
            // TODO
            pcap_perror(info->handle, "Active capture device failed");
            break;
        }
        goto close;
    } else if (ret > 0) {
        switch (ret) {
        case PCAP_WARNING_PROMISC_NOTSUP:
            printf("[%s] The capture source doesn't support promiscuous mode.\n", info->if_name);
            break;
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
            printf("[%s] The time stamp type specified isn't supported by the capture source.\n", info->if_name);
            break;
        case PCAP_WARNING:
            pcap_perror(info->handle, "Warning: Active capture device");
            break;
        }
    }

    ret = pcap_list_datalinks(info->handle, &dl_list);
    if (ret < 0) {
        switch (ret) {
        case PCAP_ERROR_NOT_ACTIVATED:
            printf("[%s] Cannot get datalink list, the capture source has not yet been activated.\n", info->if_name);
            break;
        case PCAP_ERROR:
            // TODO
            pcap_perror(info->handle, "Get datalink list failed");
            break;
        }
        goto close;
    }
    for (i = 0; i < ret; i++) {
        // TODO: how to select ?
        if (dl_list[i] == pcap_datalink_name_to_val("EN10MB")) {
            info->data_link = ETHERNET;
            break;
        }
        if (dl_list[i] == pcap_datalink_name_to_val("RAW")) {
            info->data_link = RAW;
            break;
        }
    }
    if (i == ret) {
        printf("[%s] Don't support datalink 'Ethernet' and 'Raw'.\n", info->if_name);
        goto free_data_links;
    }

    if (pcap_set_datalink(info->handle, dl_list[i]) < 0) {
        // TODO
        pcap_perror(info->handle, "Set datalink failed");
        goto free_data_links;
    }

    snprintf(info->filter_expression, FILTER_EXP_LEN, "ip");

    if (pcap_compile(info->handle, &info->filter, info->filter_expression, 1, info->if_netmask) < 0) {
        pcap_perror(info->handle, "Compile filter failed");
        goto free_data_links;
    }

    if (pcap_setfilter(info->handle, &info->filter) < 0) {
        pcap_perror(info->handle, "Set filter failed");
        goto free_code;
    }

    printf("[%s] Start capture... %s\n", info->if_name, (info->data_link == ETHERNET) ? "ETHERNET" : "RAW");

    ret = pcap_loop(info->handle, -1, packet_process, (void*)info);
    if (ret == -2)
        printf("\r[%s] Cancled.\n", info->if_name);

free_code:
    pcap_freecode(&info->filter);
free_data_links:
    pcap_free_datalinks(dl_list);
close:
    pcap_close(info->handle);

    return NULL;
}

void sigint_handler(int signal, siginfo_t *sg_info, void *unused)
{
    struct thread_info *ti = NULL;

    list_for_each_entry(ti, &thread_list, list)
        pcap_breakloop(ti->handle);
}

int main(int argc, char **argv)
{
    struct thread_info *ti = NULL, *ti_tmp;
    struct sigaction sa;
    pcap_if_t *if_list = NULL, *p;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigint_handler;

    ret = sigaction(SIGINT, &sa, NULL);
    if (ret < 0) {
        switch (ret) {
        case EFAULT:
            printf("sigaction: Invalid action parameter.\n");
            break;
        case EINVAL:
            printf("sigaction: An invalid signal was specified.\n");
        }
        return 1;
    }

    INIT_LIST_HEAD(&thread_list);
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (pcap_findalldevs(&if_list, errbuf) < 0) {
        printf("find device failed: %s\n", errbuf);
        return 1;
    }

#if 0
    p = if_list;
    while (p) {
        printf("name: %s\n", p->name);
        printf("    : %s\n", p->description);
        printf("    : LOOPBACK | UP | RUNNING | WIRELESS | CONNECTION_STATUS\n");
        printf("    : %d          %d    %d         %d          %d\n\n",
                p->flags & PCAP_IF_LOOPBACK,
                (p->flags & PCAP_IF_UP) >> 1,
                (p->flags & PCAP_IF_RUNNING) >> 2,
                (p->flags & PCAP_IF_WIRELESS) >> 3,
                (p->flags & PCAP_IF_CONNECTION_STATUS) >> 4);
        p = p->next;
    }
#endif

    p = if_list;
    while (p) {
        if (((p->flags & PCAP_IF_CONNECTION_STATUS) != PCAP_IF_CONNECTION_STATUS_CONNECTED) ||
            (p->flags & PCAP_IF_LOOPBACK) || !(p->flags & PCAP_IF_UP) || !(p->flags & PCAP_IF_RUNNING)) {
            p = p->next;
            continue;
        }

        ti = (struct thread_info*)calloc(1, sizeof(struct thread_info));
        if (!ti)
            printf("Allocate memory for capture [%s] failed.\n", p->name);
        strncpy(ti->if_name, p->name, (strlen(p->name) > 63) ? 63 : strlen(p->name));
        list_add_tail(&ti->list, &thread_list);

        ret = pthread_create(&ti->th, NULL, thread_fn, ti);
        if (ret != 0) {
            printf("Create capture thread for [%s] failed: %s\n", ti->if_name, strerror(ret));
            list_del(&ti->list);
            free(ti);
        }
        p = p->next;
    }

    if (list_empty_careful(&thread_list))
        printf("No suitable device found.\n");

    list_for_each_entry_safe(ti, ti_tmp, &thread_list, list) {
        ret = pthread_join(ti->th, NULL);
        if (ret == 0) {
            list_del(&ti->list);
            free(ti);
        } else {
            printf("Join failed: [%s] %s\n", ti->if_name, strerror(ret));
            // TODO: then what ?
        }
    }

    pcap_freealldevs(if_list);

    return 0;
}
