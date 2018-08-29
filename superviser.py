#!/usr/local/bin/python3

import threading, time, io, json

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus

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
        print('init()')

    def __del__(self):
        self.net_file.close()
        print('del()')

    def extract(self):
        while not self.should_stop:
            self.net_file.seek(0)
            for line in self.net_file:
                if (len(line.split(':')) != 2):
                    continue
                if ('eth0' in line):
                    print('%s' % line)
            time.sleep(1)

    def dispatch(self):
        self.extractor.start()

    def stop(self):
        self.should_stop = True
        self.extractor.join()


class Local_HTTP_Request_Handler(BaseHTTPRequestHandler):
    error_message_format = ERROR_DATA
    error_content_type = ERROR_TYPE
    server_version = "Supervisor/1.0"
    sys_version = ""

    error_list = [
        { 'code': 0, 'msg': 'placeholder' },
        { 'code': 1, 'msg': 'Bad JSON format' },
        { 'code': 2, 'msg': 'Need item "type" in request data' },
        { 'code': 3, 'msg': 'Unknow type data' }
    ]

    def handle_ping(self):
        response = { 'status': 'OK', 'data': 'pong' }
        return response

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
        request_data = self.rfile.read1()

        try:
            request_obj = json.loads(request_data)
            if (request_obj.__contains__('type')):
                if (request_obj['type'] == 'ping'):
                    response_str = json.dumps(self.handle_ping())
                else:
                    response_status = HTTPStatus.BAD_REQUEST
                    response_str = (self.error_message_format % {
                        'code': self.error_list[3]['code'],
                        'message': self.error_list[3]['msg']
                    })
            else:
                response_status = HTTPStatus.BAD_REQUEST
                response_str = (self.error_message_format % {
                    'code': self.error_list[2]['code'],
                    'message': self.error_list[2]['msg']
                })
        except json.JSONDecodeError as msg:
            response_status = HTTPStatus.BAD_REQUEST
            response_str = (self.error_message_format % {
                'code': self.error_list[1]['code'],
                'message': self.error_list[1]['msg']
            })

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

def main(server_class=ThreadingHTTPServer, handler_class=Local_HTTP_Request_Handler):
    monitor = Monitor()
    monitor.dispatch()

    server_address = ('', 8000)
    http_server = server_class(server_address, handler_class)
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass

    monitor.stop()

if __name__ == '__main__':
    main()
