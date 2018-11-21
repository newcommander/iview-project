#define _GNU_SOURCE
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <termios.h>
#include <pcap/pcap.h>
#include <cjson/cJSON.h>
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

static struct list_head thread_list;
static pthread_t timing_th;

static void packet_process(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct thread_info *ti = (struct thread_info*)arg;
    struct ethernet_frame *frame = NULL;
    struct ip_packet *pkt = NULL;
    struct link_transfer *trans = NULL;
    char ip_addr_buf[INET_ADDRSTRLEN], ip_addr_buf1[INET_ADDRSTRLEN];

    if (!ti || !packet) {
        printf("packet_process: Invalid parameter.\n");
        return;
    }

    switch (ti->data_link) {
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
        printf("[%s] Invalid data link type: %d.\n", ti->if_name, ti->data_link);
        return;
    }

    trans = (struct link_transfer*)calloc(1, sizeof(struct link_transfer));
    if (trans) {
        trans->src_ip = pkt->src_ip;
        trans->dst_ip = pkt->dst_ip;
        trans->src2dst_len = ntohs(pkt->length);
        pthread_mutex_lock(&ti->trans_list_mutex);
        list_add_tail(&trans->list, &ti->trans_list);
        ti->trans_count++;
        pthread_mutex_unlock(&ti->trans_list_mutex);
    } else {
        inet_ntop(AF_INET, &pkt->src_ip, ip_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &pkt->dst_ip, ip_addr_buf1, INET_ADDRSTRLEN);
        printf("[%s] Alloc packet transfer failed: src_ip: %s, dst_ip: %s, length=%d\n", ti->if_name, ip_addr_buf, ip_addr_buf1, ntohs(pkt->length));
    }

    if (ti->if_addr == pkt->src_ip)
        ti->bytes_out += ntohs(pkt->length);
    else
        ti->bytes_in += ntohs(pkt->length);

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

static int get_device_config(struct thread_info *ti)
{
    struct sockaddr_in *sin;
    struct ifreq ifr;
    int fd = 0, len;

    if (!ti || !ti->if_name)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[%s] Create socket failed: %s\n", ti->if_name, strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    len = sizeof(ifr.ifr_name) < strlen(ti->if_name) ? sizeof(ifr.ifr_name) : strlen(ti->if_name);
    strncpy(ifr.ifr_name, ti->if_name, len);
    ifr.ifr_addr.sa_family = AF_INET;

    /*cmds defined in linux/sockios.h */
    if (ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) < 0) {
        printf("[%s] SIOCGIFFLAGS: %s\n", ti->if_name, strerror(errno));
        close(fd);
        return -1;
    }
    if (ifr.ifr_flags & IFF_POINTOPOINT)
        ti->if_is_p2p = 1;
    else
        ti->if_is_p2p = 0;

    if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) < 0) {
        if (errno == EADDRNOTAVAIL)
            printf("[%s] address not assigned\n", ti->if_name);
        else
            printf("[%s] SIOCGIFADDR: %s\n", ti->if_name, strerror(errno));
        close(fd);
        return -1;
    }
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    ti->if_addr = (__u32)sin->sin_addr.s_addr;

    if (ti->if_is_p2p) {
        if (ioctl(fd, SIOCGIFDSTADDR, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFDSTADDR: %s\n", ti->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        ti->if_dstaddr = (__u32)sin->sin_addr.s_addr;
    } else {
        if (ioctl(fd, SIOCGIFNETMASK, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFNETMASK: %s\n", ti->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        ti->if_netmask = (__u32)sin->sin_addr.s_addr;
        ti->if_network = ti->if_addr & ti->if_netmask;

        if (ioctl(fd, SIOCGIFBRDADDR, (char*)&ifr) < 0) {
            printf("[%s] SIOCGIFBRDADDR: %s\n", ti->if_name, strerror(errno));
            close(fd);
            return -1;
        }
        sin = (struct sockaddr_in*)&ifr.ifr_addr;
        ti->if_broadaddr = (__u32)sin->sin_addr.s_addr;
    }

#if 0
    char ip_addr_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ti->if_addr, ip_addr_buf, INET_ADDRSTRLEN);
    printf("addr: %s\n", ip_addr_buf);
    if (ti->if_is_p2p) {
        inet_ntop(AF_INET, &ti->if_dstaddr, ip_addr_buf, INET_ADDRSTRLEN);
        printf("dstaddr: %s\n", ip_addr_buf);
    } else {
        inet_ntop(AF_INET, &ti->if_netmask, ip_addr_buf, INET_ADDRSTRLEN);
        printf("netmask: %s\n", ip_addr_buf);
        inet_ntop(AF_INET, &ti->if_network, ip_addr_buf, INET_ADDRSTRLEN);
        printf("network: %s\n", ip_addr_buf);
        inet_ntop(AF_INET, &ti->if_broadaddr, ip_addr_buf, INET_ADDRSTRLEN);
        printf("broadaddr: %s\n", ip_addr_buf);
    }
#endif

    close(fd);
    return 0;
}

void* thread_fn(void *arg)
{
    struct thread_info *ti = (struct thread_info*)arg;
    int ret, i, *dl_list = NULL;

    if (!ti)
        return NULL;

    if (get_device_config(ti) < 0) {
        printf("[%s]: Get device config failed.\n", ti->if_name);
        return NULL;
    }

    ti->handle = pcap_create(ti->if_name, ti->errbuf);
    if (!ti->handle) {
        printf("[%s] Create handle failed: %s\n", ti->if_name, ti->errbuf);
        return NULL;
    }

    ret = pcap_activate(ti->handle);
    if (ret < 0) {
        switch (ret) {
        case PCAP_ERROR_ACTIVATED:
            printf("[%s] The handle has already been activated.\n", ti->if_name);
            break;
        case PCAP_ERROR_NO_SUCH_DEVICE:
            printf("[%s] The capture source doesn't exist.\n", ti->if_name);
            break;
        case PCAP_ERROR_PERM_DENIED:
            printf("[%s] The process doesn't have permission to open the capture source.\n", ti->if_name);
            break;
        case PCAP_ERROR_PROMISC_PERM_DENIED:
            printf("[%s] The process doesn't have permission to put it into promiscuous mode.\n", ti->if_name);
            break;
        case PCAP_ERROR_RFMON_NOTSUP:
            printf("[%s] The capture source doesn't support monitor mode.\n", ti->if_name);
            break;
        case PCAP_ERROR_IFACE_NOT_UP:
            printf("[%s] The capture source device is not up.\n", ti->if_name);
            break;
        case PCAP_ERROR:
            // TODO
            pcap_perror(ti->handle, "Active capture device failed");
            break;
        }
        goto close;
    } else if (ret > 0) {
        switch (ret) {
        case PCAP_WARNING_PROMISC_NOTSUP:
            printf("[%s] The capture source doesn't support promiscuous mode.\n", ti->if_name);
            break;
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
            printf("[%s] The time stamp type specified isn't supported by the capture source.\n", ti->if_name);
            break;
        case PCAP_WARNING:
            pcap_perror(ti->handle, "Warning: Active capture device");
            break;
        }
    }

    ret = pcap_list_datalinks(ti->handle, &dl_list);
    if (ret < 0) {
        switch (ret) {
        case PCAP_ERROR_NOT_ACTIVATED:
            printf("[%s] Cannot get datalink list, the capture source has not yet been activated.\n", ti->if_name);
            break;
        case PCAP_ERROR:
            // TODO
            pcap_perror(ti->handle, "Get datalink list failed");
            break;
        }
        goto close;
    }
    for (i = 0; i < ret; i++) {
        // TODO: how to select ?
        if (dl_list[i] == pcap_datalink_name_to_val("EN10MB")) {
            ti->data_link = ETHERNET;
            break;
        }
        if (dl_list[i] == pcap_datalink_name_to_val("RAW")) {
            ti->data_link = RAW;
            break;
        }
    }
    if (i == ret) {
        printf("[%s] Don't support datalink 'Ethernet' and 'Raw'.\n", ti->if_name);
        goto free_data_links;
    }

    if (pcap_set_datalink(ti->handle, dl_list[i]) < 0) {
        // TODO
        pcap_perror(ti->handle, "Set datalink failed");
        goto free_data_links;
    }

    snprintf(ti->filter_expression, FILTER_EXP_LEN, "ip");

    if (pcap_compile(ti->handle, &ti->filter, ti->filter_expression, 1, ti->if_netmask) < 0) {
        pcap_perror(ti->handle, "Compile filter failed");
        goto free_data_links;
    }

    if (pcap_setfilter(ti->handle, &ti->filter) < 0) {
        pcap_perror(ti->handle, "Set filter failed");
        goto free_code;
    }

    printf("[%s] Start capture... %s\n", ti->if_name, (ti->data_link == ETHERNET) ? "ETHERNET" : "RAW");

    ret = pcap_loop(ti->handle, -1, packet_process, (void*)ti);
    if (ret == -2)
        printf("\r[%s] Cancled.\n", ti->if_name);

free_code:
    pcap_freecode(&ti->filter);
free_data_links:
    pcap_free_datalinks(dl_list);
close:
    pcap_close(ti->handle);

    return NULL;
}

/* in decrease order */
void sort_list_by_src2dst_len(struct list_head *link_list)
{
    struct link_transfer *trans, *trans_tmp;
    struct link_transfer *_trans, *_trans_tmp;
    struct list_head order_list;

    if (list_empty(link_list))
        return;

    INIT_LIST_HEAD(&order_list);
    list_for_each_entry_safe(trans, trans_tmp, link_list, list) {
        list_for_each_entry_safe(_trans, _trans_tmp, &order_list, list) {
            if (trans->src2dst_len >= _trans->src2dst_len)
                break;
        }
        list_del(&trans->list);
        list_add_tail(&trans->list, &_trans->list);
    }
    move_list(link_list, &order_list);
}

char* parse_link_list_to_json(struct thread_info *ti)
{
    struct list_head *link_list = &ti->if_state.link_list;
    struct link_transfer *trans;
    pthread_mutex_t *link_list_mutex = &ti->if_state.link_list_mutex;
    cJSON *root = NULL, *links = NULL, *link = NULL;
    char *string = NULL, ip_addr_buf[INET_ADDRSTRLEN];

    memset(ip_addr_buf, 0, INET_ADDRSTRLEN);

    root = cJSON_CreateObject();
    if (!root)
        return NULL;

    if (cJSON_AddStringToObject(root, "if_name", ti->if_name) == NULL)
        goto end;

    links = cJSON_AddArrayToObject(root, "links");
    if (!links)
        goto end;

    pthread_mutex_lock(link_list_mutex);

    list_for_each_entry(trans, link_list, list) {
        link = cJSON_CreateObject();
        if (!link)
            goto end;

        inet_ntop(AF_INET, &trans->src_ip, ip_addr_buf, INET_ADDRSTRLEN);
        if (cJSON_AddStringToObject(link, "s_ip", ip_addr_buf) == NULL)
            goto end;
        inet_ntop(AF_INET, &trans->dst_ip, ip_addr_buf, INET_ADDRSTRLEN);
        if (cJSON_AddStringToObject(link, "d_ip", ip_addr_buf) == NULL)
            goto end;
        if (cJSON_AddNumberToObject(link, "s2d_len", trans->src2dst_len) == NULL)
            goto end;
        if (cJSON_AddNumberToObject(link, "d2s_len", trans->dst2src_len) == NULL)
            goto end;

        cJSON_AddItemToArray(links, link);
    }

    pthread_mutex_unlock(link_list_mutex);

    string = cJSON_PrintUnformatted(root);

end:
    cJSON_Delete(root);
    return string;  // should be freed in caller.
}

void merge_link_transfer(struct thread_info *ti, const struct list_head *trans_list)
{
    struct link_transfer *trans, *trans_tmp, *obj, *obj_tmp;
    struct list_head *link_list = &ti->if_state.link_list;
    pthread_mutex_t *link_list_mutex = &ti->if_state.link_list_mutex;
    int done;

    pthread_mutex_lock(link_list_mutex);

    list_for_each_entry_safe(trans, trans_tmp, link_list, list) {
        list_del(&trans->list);
        free(trans);
    }

    list_for_each_entry_safe(trans, trans_tmp, trans_list, list) {
        done = 0;
        list_for_each_entry_safe(obj, obj_tmp, link_list, list) {
            if ((trans->src_ip == obj->src_ip) && (trans->dst_ip == obj->dst_ip)) {
                obj->src2dst_len += trans->src2dst_len;
                done = 1;
            } else if ((trans->src_ip == obj->dst_ip) && (trans->dst_ip == obj->src_ip)) {
                obj->dst2src_len += trans->src2dst_len;
                done = 1;
            }
        }
        list_del(&trans->list);
        if (done)
            free(trans);
        else
            list_add_tail(&trans->list, link_list);
    }

    sort_list_by_src2dst_len(link_list);

    pthread_mutex_unlock(link_list_mutex);
}

void* timing_fn(void *arg)
{
    struct list_head trans_list;
    struct thread_info *ti;
    struct timeval tv;
    __u32 bytes_in, bytes_out;
    char *string = NULL;
    int ret;

    while (1) {
        pthread_testcancel();
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        ret = select(0, NULL, NULL, NULL, &tv); // Timer
        if (ret < 0) {
            printf("Timer select error: %s\n", strerror(errno));
            return NULL;
        }

        list_for_each_entry(ti, &thread_list, list) {
            bytes_in = ti->bytes_in;
            bytes_out = ti->bytes_out;
            ti->bytes_in -= bytes_in;
            ti->bytes_out -= bytes_out;
            ti->if_state.bandwidth_in[ti->if_state.curr_index] = bytes_in;
            ti->if_state.bandwidth_out[ti->if_state.curr_index] = bytes_out;
            ti->if_state.curr_index = (ti->if_state.curr_index + 1) % STATE_BUFFER_LENGTH;

            pthread_mutex_lock(&ti->trans_list_mutex);
            move_list(&trans_list, &ti->trans_list);
            ti->trans_count = 0;
            pthread_mutex_unlock(&ti->trans_list_mutex);
            merge_link_transfer(ti, &trans_list);
            string = parse_link_list_to_json(ti);
            if (string) {
                printf("%s\n", string);
                free(string);
            }
        }

#if 0
        char *print_buf = (char*)arg;
        int buf_len;

        buf_len = strlen(print_buf) + 1;
        memset(print_buf, 0, buf_len);

        print_buf[0] = '\0';
        list_for_each_entry(ti, &thread_list, list) {
            snprintf(print_buf + strlen(print_buf), buf_len, "[%s: IN=%u.%02uKB/s, OUT=%u.%02uKB/s] ", ti->if_name,
                    bytes_in / 1024, (bytes_in % 1024) * 100 / 1024,
                    bytes_out / 1024, (bytes_out % 1024) * 100 / 1024);
        }
        if (strlen(print_buf) < buf_len)
            memset(print_buf + strlen(print_buf), ' ', buf_len - strlen(print_buf) - 1);
        print_buf[buf_len - 1] = '\0';
        printf("\r%s", print_buf);

        fflush(stdout);
#endif
    }

    return NULL;
}

void sigint_handler(int signal, siginfo_t *sg_info, void *unused)
{
    struct thread_info *ti = NULL;
    int ret;

    if (timing_th != 0) {
        ret = pthread_cancel(timing_th);
        if (ret != 0) {
            printf("Cancel timing thread error: %s\n", strerror(ret));
            // TODO: then what ?
            return;
        }

        ret = pthread_join(timing_th, NULL);
        if (ret != 0) {
            printf("Join timing thread error: %s\n", strerror(ret));
            // TODO: then what ?
            return;
        }
        timing_th = 0;
    }

    list_for_each_entry(ti, &thread_list, list)
        pcap_breakloop(ti->handle);
}

int main(int argc, char **argv)
{
    struct link_transfer *trans, *trans_tmp;
    struct thread_info *ti = NULL, *ti_tmp;
    struct winsize w_size;
    struct sigaction sa;
    pcap_if_t *if_list = NULL, *p;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *print_buf = NULL;
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
    timing_th = 0;

    ioctl(STDIN_FILENO, TIOCGWINSZ, &w_size);
    if (w_size.ws_col <= 0)
        w_size.ws_col = 86;

    print_buf = (char*)calloc(w_size.ws_col, 1);
    if (!print_buf) {
        printf("Alloc print buffer failed.\n");
        return 1;
    }
    memset(print_buf, 'A', w_size.ws_col - 1);

    if (pcap_findalldevs(&if_list, errbuf) < 0) {
        printf("find device failed: %s\n", errbuf);
        free(print_buf);
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
            (p->flags & PCAP_IF_LOOPBACK) || !(p->flags & PCAP_IF_UP) || !(p->flags & PCAP_IF_RUNNING) ||
            !(strncmp(p->name, "virbr", 5))) {
            p = p->next;
            continue;
        }

        ti = (struct thread_info*)calloc(1, sizeof(struct thread_info));
        if (!ti)
            printf("Allocate memory for capture [%s] failed.\n", p->name);
        strncpy(ti->if_name, p->name, (strlen(p->name) > 63) ? 63 : strlen(p->name));
        ti->if_state.curr_index = 0;
        INIT_LIST_HEAD(&ti->trans_list);
        INIT_LIST_HEAD(&ti->if_state.link_list);
        pthread_mutex_init(&ti->trans_list_mutex, NULL);
        pthread_mutex_init(&ti->if_state.link_list_mutex, NULL);
        list_add_tail(&ti->list, &thread_list);

        ret = pthread_create(&ti->th, NULL, thread_fn, ti);
        if (ret != 0) {
            printf("Create capture thread for [%s] failed: %s\n", ti->if_name, strerror(ret));
            list_del(&ti->list);
            free(ti);
        }
        p = p->next;
    }

    if (!list_empty_careful(&thread_list)) {
        ret = pthread_create(&timing_th, NULL, timing_fn, print_buf);
        if (ret != 0) {
            printf("Create timing thread failed: %s\n", strerror(ret));
            list_for_each_entry(ti, &thread_list, list)
                pcap_breakloop(ti->handle);
        }
    } else
        printf("No suitable device found, pcap_lib_version: %s.\n", pcap_lib_version());

    list_for_each_entry_safe(ti, ti_tmp, &thread_list, list) {
        ret = pthread_join(ti->th, NULL);
        if (ret == 0) {
            list_del(&ti->list);
            pthread_mutex_destroy(&ti->trans_list_mutex);
            pthread_mutex_destroy(&ti->if_state.link_list_mutex);
            list_for_each_entry_safe(trans, trans_tmp, &ti->if_state.link_list, list) {
                list_del(&trans->list);
                free(trans);
            }
            free(ti);
        } else {
            printf("Join error: [%s] %s\n", ti->if_name, strerror(ret));
            // TODO: then what ?
        }
    }

    pcap_freealldevs(if_list);
    free(print_buf);

    return 0;
}
