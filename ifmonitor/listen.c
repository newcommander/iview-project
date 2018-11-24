#include <arpa/inet.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/buffer.h>

#include "ifmonitor.h"

#define SERVICE_IP "0.0.0.0"
#define SERVICE_PORT 554

#define HTTP_HEADER_BUFFER_LENGTN   1024

enum {
    r_ping = 0,
    r_link_list
};

static char *error_str_list[] = {
    "Alloc recive buffer failed.",
    "You should specify HTTP POST data.",
    "Bad json format of request recived.",
    "Request should contain string items 'if_name' and 'item' at least.",
    "Cannot find device spcified in 'if_name'.",
    "Cannot find data spcified in 'item'.",
    "Make response failed."
};

#define get_error_string(code) \
    (((code) >= sizeof(error_str_list)/sizeof(char*)) ? "Unknow error.": error_str_list[(code)])

static struct event_base *base = NULL;
static char *static_error_response_string = "{'status':1,'data':'static error response'}";

static void make_html_header(char *buf, int buf_len, int data_len)
{
    char *p = buf;

    snprintf(p, 18, "HTTP/1.1 200 OK\r\n");
    p += strlen(p);
    snprintf(p, 24, "Server: ifmonitor/1.0\r\n");
    p += strlen(p);
    snprintf(p, 21 + 20, "Content-Length: %d\r\n", data_len);
    p += strlen(p);
    snprintf(p, 33, "Content-Type: application/json\r\n");
    p += strlen(p);
    //snprintf(p, 20, "Connection: close\r\n");
    //p += strlen(p);
    snprintf(p, 3, "\r\n");
}

static char* make_error_response_string(char *error_str)
{
    cJSON *root = NULL;
    char *ret_str = NULL;

    if (!error_str)
        return static_error_response_string;

    root = cJSON_CreateObject();
    if (!root)
        return static_error_response_string;

    if (!cJSON_AddNumberToObject(root, "status", 1)) {
        cJSON_Delete(root);
        return static_error_response_string;
    }

    if (!cJSON_AddStringToObject(root, "data", error_str)) {
        cJSON_Delete(root);
        return static_error_response_string;
    }

    ret_str = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    if (ret_str)
        return ret_str;
    else
        return static_error_response_string;
}

static char* make_response_string(cJSON *root)
{
    char *ret_str = NULL;

    if (!root)
        return make_error_response_string(get_error_string(6));

    ret_str = cJSON_PrintUnformatted(root);
    if (ret_str)
        return ret_str;
    else
        return make_error_response_string(NULL);
}

static cJSON* make_link_list_obj(struct thread_info *ti)
{
    cJSON *obj = NULL;

    if (!ti)
        return NULL;

    obj = parse_link_list_to_json(ti);
    if (!obj)
        goto failed;

    return obj;

failed:
    if (obj)
        cJSON_Delete(obj);
    return NULL;
}

static cJSON* make_response(struct thread_info *ti, int r_code)
{
    cJSON *root = NULL, *data_obj = NULL;

    if (!ti)
        return NULL;

    root = cJSON_CreateObject();
    if (!root)
        goto failed;

    if (!cJSON_AddNumberToObject(root, "status", 0))
        goto failed;

    switch (r_code) {
    case r_ping:
        if (!cJSON_AddStringToObject(root, "data", "pong"))
            goto failed;
        break;
    case r_link_list:
        data_obj = make_link_list_obj(ti);
        if (!data_obj)
            goto failed;
        cJSON_AddItemToObject(root, "data", data_obj);
        break;
    default:
        goto failed;
    }

    return root;

failed:
    if (root)
        cJSON_Delete(root);
    return NULL;
}

static void read_cb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    struct thread_info *ti = NULL, *ti_tmp;
    cJSON *req = NULL, *if_name, *item;
    cJSON *result_data = NULL;
    char *recv_buf = NULL;
    size_t recv_len = 0, offset = 0;
    char *request_str = NULL, *response_str = NULL, *error_str = NULL, *p;
    char http_header[HTTP_HEADER_BUFFER_LENGTN];
    int r_code;

    recv_len = evbuffer_get_length(input);
    recv_buf = (char*)calloc(recv_len + 1, 1);
    if (!recv_buf) {
        printf("%s: Alloc recive buffer failed.\n", __func__);
        error_str = get_error_string(0);
        goto reply;
    }

    p = recv_buf;
    offset = 0;
    while ((offset = bufferevent_read(bev, p, recv_buf + recv_len - p)) > 0)
        p += offset;

    request_str = strstr(recv_buf, "\r\n\r\n");
    if (!request_str || strlen(&request_str[4]) == 0) {
        error_str = get_error_string(1);
        goto reply;
    }
    request_str = &request_str[4];

    req = cJSON_Parse(request_str);
    if (!req) {
        error_str = get_error_string(2);
        goto reply;
    }

    if (!(cJSON_HasObjectItem(req, "if_name") && cJSON_HasObjectItem(req, "item")) ||
        !(cJSON_IsString(cJSON_GetObjectItem(req, "if_name")) && cJSON_IsString(cJSON_GetObjectItem(req, "item")))) {
        error_str = get_error_string(3);
        goto reply;
    }

    if_name = cJSON_GetObjectItem(req, "if_name");
    item = cJSON_GetObjectItem(req, "item");

    list_for_each_entry(ti_tmp, &thread_list, list) {
        if (!strcmp(ti_tmp->if_name, if_name->valuestring)) {
            ti = ti_tmp;
            break;
        }
    }

    if (!ti) {
        error_str = get_error_string(4);
        goto reply;
    }

    if (!strncmp(item->valuestring, "ping", 4)) {
        r_code = r_ping;
    } else if (!strncmp(item->valuestring, "link_list", 9)) {
        r_code = r_link_list;
    } else {
        error_str = get_error_string(5);
        goto reply;
    }

    result_data = make_response(ti, r_code);

reply:
    if (result_data)
        response_str = make_response_string(result_data);
    else
        response_str = make_error_response_string(error_str);

    make_html_header(http_header, HTTP_HEADER_BUFFER_LENGTN, strlen(response_str));

    bufferevent_write(bev, http_header, strlen(http_header));
    bufferevent_write(bev, response_str, strlen(response_str));
    bufferevent_flush(bev, EV_WRITE, BEV_FLUSH);

    //bufferevent_free(bev);

    if (result_data)
        cJSON_Delete(result_data);
    if (req)
        cJSON_Delete(req);
    if (response_str != static_error_response_string)
        free(response_str);
    if (recv_buf)
        free(recv_buf);
}

static void write_cb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *output = bufferevent_get_output(bev);
    if (evbuffer_get_length(output) == 0) {
        ;
    }
}

static void event_cb(struct bufferevent *bev, short events, void *user_data)
{
    if (events & BEV_EVENT_EOF) {
        printf("%s: Connection closed.\n", __func__);
    } else if (events & BEV_EVENT_ERROR) {
        printf("%s: Got an error on the connection: %s\n", __func__, strerror(errno));
    } else {
        switch (events) {
        case BEV_EVENT_READING:
            printf("%s: Unexpected event: BEV_EVENT_READING\n", __func__);
            break;
        case BEV_EVENT_WRITING:
            printf("%s: Unexpected event: BEV_EVENT_WRITING\n", __func__);
            break;
        case BEV_EVENT_TIMEOUT:
            printf("%s: Unexpected event: BEV_EVENT_TIMEOUT\n", __func__);
            break;
        case BEV_EVENT_CONNECTED:
            printf("%s: Unexpected event: BEV_EVENT_CONNECTED\n", __func__);
            break;
        default:
            printf("%s: Unknow event: 0x%x\n", __func__, events);
        }
        return;
    }

    bufferevent_flush(bev, EV_WRITE, BEV_FLUSH);
    bufferevent_free(bev);
}

static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *user_data)
{
    struct event_base *base = (struct event_base*)user_data;
    struct bufferevent *bev = NULL;

    if (!base) {
        printf("%s: Invalid parameter\n", __func__);
        return;
    }

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        printf("%s: Error constructing bufferevent!", __func__);
        event_base_loopbreak(base);
        return;
    }

    bufferevent_setcb(bev, read_cb, write_cb, event_cb, NULL);
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_enable(bev, EV_READ);
}

void listen_loop_exit()
{
    struct timeval delay = { 0, 500000 }; // 0.5 second

    if (!base)
        return;

    event_base_loopexit(base, &delay);
}

void *listen_fn(void *arg)
{
    struct evconnlistener *listener = NULL;
    struct sockaddr_in sin;

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Could not initialize libevent!\n");
        return NULL;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(SERVICE_IP);
    sin.sin_port = htons(SERVICE_PORT);

    listener = evconnlistener_new_bind(base, listener_cb, (void *)base,
            LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        fprintf(stderr, "Could not create a listener!\n");
        goto listener_bind_failed;
    }

    event_base_dispatch(base);

    evconnlistener_free(listener);
listener_bind_failed:
    event_base_free(base);

    return NULL;
}
