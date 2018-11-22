#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>

#include <cjson/cJSON.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/buffer.h>
#include <event2/listener.h>

#include "ifmonitor.h"

static char *service_ip = "0.0.0.0";
static int service_port = 554;
static struct event_base *base = NULL;

extern struct list_head thread_list;

struct error_list {
    int code;
    char *string;
} error_str_list[] = {
    { 401, "Bad json format of request recived." },
    { 402, "Request should contain string items 'if_name' and 'item' at least." },
    { 403, "Cannot find device spcified in 'if_name'." },
    { 501, "Alloc recive buffer failed." },
    { 502, "Have no response." }
};

char* make_error_reply(int code)
{
    int i;

    for (i = 0; i < sizeof(error_str_list) / sizeof(struct error_list); i++) {
        if (error_str_list[i].code == code)
            return error_str_list[i].string;
    }
    return NULL;
}

static void read_cb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    struct thread_info *ti = NULL, *ti_tmp;
    cJSON *req = NULL, *if_name, *item;
    char *response_str = NULL, *request_str = NULL, *p;
    char *result_str = NULL, *error_str = NULL;
    int offset = 0;

    size_t len = evbuffer_get_length(input);
    char *buf = (char*)calloc(len + 1, 1);
    if (!buf) {
        printf("%s: alloc recive buffer failed\n", __func__);
        error_str = make_error_reply(501);
        goto reply;
    }

    p = buf;
    offset = 0;
    while ((offset = bufferevent_read(bev, p, buf + len - p)) > 0)
        p += offset;

    request_str = strstr(buf, "\r\n\r\n");
    if (!request_str || strlen(&request_str[4]) == 0) {
        error_str = make_error_reply(402);
        goto reply;
    }
    request_str = &request_str[4];

    req = cJSON_Parse(request_str);
    if (!req) {
        error_str = make_error_reply(401);
        goto reply;
    }

    if (!(cJSON_HasObjectItem(req, "if_name") && cJSON_HasObjectItem(req, "item")) ||
        !(cJSON_IsString(cJSON_GetObjectItem(req, "if_name")) && cJSON_IsString(cJSON_GetObjectItem(req, "item")))) {
        error_str = make_error_reply(402);
        goto reply;
    }

    if_name = cJSON_GetObjectItem(req, "if_name");
    item = cJSON_GetObjectItem(req, "item");

    printf("if_name: %s, item: %s\n", if_name->valuestring, item->valuestring);

    list_for_each_entry(ti_tmp, &thread_list, list) {
        if (!strcmp(ti_tmp->if_name, if_name->valuestring)) {
            ti = ti_tmp;
            break;
        }
    }

    if (!ti) {
        error_str = make_error_reply(403);
        goto reply;
    }

reply:
    if (result_str)
        response_str = result_str;
    else if (error_str)
        response_str = error_str;
    else
        response_str = make_error_reply(502);

    bufferevent_write(bev, response_str, strlen(response_str));
    bufferevent_flush(bev, EV_WRITE, BEV_FLUSH);

    if (result_str)
        free(result_str);

    //bufferevent_free(bev);

    cJSON_Delete(req);
    if (buf)
        free(buf);
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
    sin.sin_addr.s_addr = inet_addr(service_ip);
    sin.sin_port = htons(service_port);

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
