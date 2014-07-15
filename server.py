#!/usr/bin/env python
import SocketServer
import struct
import socket
import argparse
import time
import yaml
import json
import os
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

class DnsReaderServer(SocketServer.ThreadingUDPServer):
    '''
    SocketServer.ThreadingUDPServer 

    Instance variables:
    
    - RequestHandlerClass
    '''
    def __init__(self,server_address,RequestHandlerClass):
        SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)

class DnsReaderHanlder(SocketServer.BaseRequestHandler):
    '''
    Base Handeler class 
    '''

    message  = None
    serial   = None
    data     = None
    incoming = None
    qname    = None

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def format_qname (self, qname):
        if qname == '.':
            return 'root'
        else:
            return qname[:-1]

    def parse_dns(self):
        '''
        parse the data package into dns elements
        '''
        self.data = str(self.request[0]).strip()
        self.incoming = self.request[1]
        #incoming Data
        try:
            self.message = dns.message.from_wire(self.data)
        except dns.name.BadLabelType:
            #Error processing lable (bit flip?)
            return False 
        except dns.message.ShortHeader:
            #Recived junk
            return False
        else:
            current_time = int(time.time())
            if self.message.opcode() == 4:
                self.qname = self.format_qname(self.message.question[0].name.to_text())
                self.serial = self.message.answer[0].to_rdataset()[0].serial
                return True
        return False

    def handle(self):
        '''
        RequestHandlerClass handle function
        handler listens for dns packets
        '''
        if self.parse_dns():
            print self.qname
            print self.serial
            print self.client_address[0]


def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description='dns spoof monitoring script')
    parser.add_argument('-l', '--listen', metavar="0.0.0.0:53", 
            default="0.0.0.0:53", help='listen on address:port ')
    args = parser.parse_args()
    host, port = args.listen.split(":")

    server = DnsReaderServer((host, int(port)), DnsReaderHanlder) 
    server.serve_forever()

if __name__ == "__main__":
    main()
