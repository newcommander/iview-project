#!/usr/local/bin/python3

import threading, time, io, json, sys, os
import socketserver, datetime

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from functools import partial

ERROR_DATA = """\
{
    "status": "error",
    "code": "%(code)d",
    "message": "%(message)s",
}
"""
ERROR_TYPE = "application/json"

class Monitor():
    def __init__(self):
        self.should_stop = False
        self.extractor = threading.Thread(target=self.extract, name="extractor")
        self.net_file = open('/proc/net/dev', "r")
        self.net_recv_bw_data1 = 0
        self.net_recv_bw_data2 = 0
        self.net_send_bw_data1 = 0
        self.net_send_bw_data2 = 0
        self.bw_buffer_len = 7 * 24 * 3600
        self.recv_bw_buffer = [0] * self.bw_buffer_len
        self.send_bw_buffer = [0] * self.bw_buffer_len
        self.bw_buffer_p = 0
        self.tag = 'this is monitor tag'

    def __del__(self):
        self.net_file.close()

    def extract(self):
        print('extracting started.')
        try:
            while not self.should_stop:
                self.net_file.seek(0)
                recv_bw = 0
                send_bw = 0
                for line in self.net_file:
                    if (len(line.split(':')) != 2):
                        continue
                    if ('wlp3s0' in line):
                        l = line.replace(':', ' ').split()
                        if (len(l) < 17):
                            continue
                        if (l[2] == '0' and l[10] == '0'):
                            continue

                        self.net_recv_bw_data2 = int(l[1])
                        if (self.net_recv_bw_data1 != 0):
                            recv_bw = self.net_recv_bw_data2 - self.net_recv_bw_data1
                        self.net_recv_bw_data1 = self.net_recv_bw_data2

                        self.net_send_bw_data2 = int(l[9])
                        if (self.net_send_bw_data1 != 0):
                            send_bw = self.net_send_bw_data2 - self.net_send_bw_data1
                        self.net_send_bw_data1 = self.net_send_bw_data2

                        self.recv_bw_buffer[self.bw_buffer_p] = recv_bw
                        self.send_bw_buffer[self.bw_buffer_p] = send_bw
                        self.bw_buffer_p = (self.bw_buffer_p + 1) % self.bw_buffer_len

                time.sleep(1)
        except KeyboardInterrupt:
            pass

    def dispatch(self):
        self.extractor.start()

    def stop(self):
        self.should_stop = True
        self.extractor.join()
        print('extracting stoped.')

    def pull_data(self, request):
        print('type: %s, length: %d' % (request['type'], request['length']))
        req_type = request['type']
        if (req_type == 'net_bw'):
            length = request['length']
            if (length > self.bw_buffer_len):
                length = self.bw_buffer_len
            position = self.bw_buffer_p - 1
            recv_bw = []
            send_bw = []
            if (position >= (length - 1)):
                recv_bw.extend(self.recv_bw_buffer[(position - length + 1) : (position + 1)])
                send_bw.extend(self.send_bw_buffer[(position - length + 1) : (position + 1)])
            else:
                recv_bw.extend(self.recv_bw_buffer[(self.bw_buffer_len - (length - position) + 1):])
                recv_bw.extend(self.recv_bw_buffer[:(position + 1)])
                send_bw.extend(self.send_bw_buffer[(self.bw_buffer_len - (length - position) + 1):])
                send_bw.extend(self.send_bw_buffer[:(position + 1)])
            start_time = (datetime.datetime.now() + datetime.timedelta(seconds=-length)).strftime('%Y/%m/%d %H:%M:%S')
            net_bw = { 'start_time': start_time, 'recv': recv_bw, 'send': send_bw }
            return net_bw
        else:
            return {}


class Local_HTTP_Request_Handler(BaseHTTPRequestHandler):

    def __init__(self, *args, mon=None, **kwargs):
        self.monitor = mon
        self.error_message_format = ERROR_DATA
        self.error_content_type = ERROR_TYPE
        self.server_version = "Supervisor/1.0"
        self.sys_version = ""
        self.error_list = [
            { 'code': 0, 'msg': 'placeholder' },
            { 'code': 1, 'msg': 'Bad JSON format' },
            { 'code': 2, 'msg': 'Need item "type" in request data' },
            { 'code': 3, 'msg': 'Unknow type data' },
            { 'code': 4, 'msg': 'Need item "length" in request data' }
        ]
        super().__init__(*args, **kwargs)

    def make_error_response(self, code):
        return (self.error_message_format % {
            'code': self.error_list[code]['code'],
            'message': self.error_list[code]['msg']
        })

    def handle_ping(self):
        response = { 'status': 'OK', 'data': 'pong' }
        return response

    def handle_monitor_req(self, req):
        return self.monitor.pull_data(req)

    def do_POST(self):
        obj1 = {}
        obj2 = {}
        obj1['name'] = "binbin"
        obj2['name'] = "jiajia"
        objs = [obj1, obj2]
        print('test: %s' % obj1.__contains__('name'))
        print('objs: %s' % json.dumps(objs))

        response_status = HTTPStatus.OK
        response_str = ''

        try:
            request_data = self.rfile.read1()
            request_obj = json.loads(request_data)
            if (request_obj.__contains__('type')):
                req_type = request_obj['type']
                if (req_type == 'ping'):
                    response_str = json.dumps(self.handle_ping())
                elif (req_type == 'net_bw'):
                    if (request_obj.__contains__('length')):
                        response_str = json.dumps(self.handle_monitor_req( { 'type':'net_bw', 'length':request_obj['length'] } ))
                    else:
                        response_status = HTTPStatus.BAD_REQUEST
                        response_str = self.make_error_response(4)
                else:
                    response_status = HTTPStatus.BAD_REQUEST
                    response_str = self.make_error_response(3)
            else:
                response_status = HTTPStatus.BAD_REQUEST
                response_str = self.make_error_response(2)
        except json.JSONDecodeError as msg:
            response_status = HTTPStatus.BAD_REQUEST
            response_str = self.make_error_response(1)

        self.close_connection = True
        self.protocol_version = 'HTTP/1.1'
        self.send_response(response_status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(response_str.encode())
        #print('client_address: %s:%s' % self.client_address)
        #print('requestline: %s' % self.requestline)
        #print('command: %s' % self.command)
        #print('path: %s' % self.path)
        #print('request_version: %s' % self.request_version)
        #print('headers: %s' % self.headers.as_string())
        #print('server_version: %s' % self.server_version)
        #print('sys_version: %s' % self.sys_version)
        #print('protocol_version: %s' % self.protocol_version)

class MainHTTPServer(ThreadingHTTPServer):
    def set_monitor(self, mon):
        self.monitor = mon

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host if (host != '') else os.popen('hostname').read()
        self.server_port = port

def main(server_class=MainHTTPServer, handler_class=Local_HTTP_Request_Handler):
    monitor = Monitor()
    monitor.dispatch()

    server_address = ('', 8000)
    http_server = server_class(server_address, partial(handler_class, mon=monitor))
    http_server.set_monitor(monitor)
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass

    monitor.stop()

if __name__ == '__main__':
    main()
