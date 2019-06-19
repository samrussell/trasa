from eventlet.green import socket
from eventlet import sleep, GreenPool
from time import time

import struct
import select
from copy import copy

from .ldp_pdu import LdpPdu, parse_ldp_pdu
from .ldp_message import LdpHelloMessage, LdpInitialisationMessage
from .stream_server import StreamServer
from .chopper import Chopper

from .error import SocketClosedError

def build_byte_string(hex_stream):
    values = [int(x, 16) for x in map(''.join, zip(*[iter(hex_stream)]*2))]
    return struct.pack("!" + "B" * len(values), *values)

class Ldp(object):
    def __init__(self):
        self.listen_ip = "172.26.1.106"
        self.listen_port = 646
        self.running = False
        self.socket = None
        self.eventlets = []

    def run(self):
        self.running = True
        self.pool = GreenPool()
        self.eventlets = []

        self.eventlets.append(self.pool.spawn(self.handle_packets_in))
        self.eventlets.append(self.pool.spawn(self.hello_timer))
        self.eventlets.append(self.pool.spawn(self.run_tcp_handler))

        self.pool.waitall()

    def run_tcp_handler(self):
        print("Starting TCP socket on %s:%s" % (self.listen_ip, self.listen_port))
        self.stream_server = StreamServer((self.listen_ip, self.listen_port), self.handle_tcp)
        self.stream_server.serve_forever()

    def handle_tcp(self, socket, address):
        peer_ip, peer_port = address
        messages_sent = 0
        print("Got connection from %s:%s" % (peer_ip, peer_port))
        input_stream = socket.makefile(mode="rb")
        chopper = Chopper(4, 2, 0, input_stream)
        while True:
            sleep(0)
            try:
                serialised_pdu = chopper.next()
                print("Got PDU from %s:%s" % (peer_ip, peer_port))
                print("PDU: %s" % serialised_pdu)
                pdu = parse_ldp_pdu(serialised_pdu)
                print("PDU: %s" % pdu)
                messages = pdu.messages
                for message in messages:
                    print("Message: %s" % message)
                    # simple mode - when we get an initialisation message send one back
                    if isinstance(message, LdpInitialisationMessage):
                        #reply_message = copy(message)
                        #reply_message.receiver_ldp_identifier = bytes.fromhex("ac1a01700000")
                        message_id = messages_sent+1
                        reply_message = LdpInitialisationMessage(
                            message_id,
                            1,
                            180,
                            0,
                            0,
                            0,
                            bytes.fromhex("ac1a01700000"),
                            {}
                        )
                        pdu = LdpPdu(1, 0xac1a016a, 0, [reply_message.pack()])
                        socket.send(pdu.pack())
                        messages_sent += 1

            except SocketClosedError as e:
                print("Socket closed from %s:%s" % (peer_ip, peer_port))
        socket.close()

    def handle_packets_in(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listen_ip, self.listen_port))

        self.poller = select.poll()
        self.poller.register(self.socket,
                          select.POLLIN |
                          select.POLLPRI |
                          select.POLLERR |
                          select.POLLHUP |
                          select.POLLNVAL)

        try:
            while self.running:
                sleep(1)
                events = self.poller.poll(10)
                if events:
                    while events:
                        if len(events) > 1:
                            raise Exception("Too many events returned from poller")
                        fd, event = events[0]
                        if event == select.POLLERR or event == select.POLLHUP or event == select.POLLNVAL:
                            break
                        if event == select.POLLIN:
                            print("Receiving message")
                            data, address = self.socket.recvfrom(4096)
                            print("Received %s from %s" % (data, address))
                            pdu = parse_ldp_pdu(data)
                            print("PDU: %s" % pdu)
                            messages = pdu.messages
                            for message in messages:
                                print("Message: %s" % message)
                            #self.queue.put(data)
                        events = self.poller.poll(10)
        except OSError:
            pass

    def hello_timer(self):
        next_timer_at = int(time())
        message_id = 1
        while self.running:
            sleep(1)
            if int(time()) > next_timer_at:
                self.send_hello(message_id)
                message_id += 1
                next_timer_at += 5

    def send_hello(self, message_id):
        print("Sending hello message")
        tlvs = {
            0x0400 : build_byte_string("000f0000"),
            0x0401 : build_byte_string("ac1a016a")
        }
        message = LdpHelloMessage(message_id, tlvs)
        pdu = LdpPdu(1, 0xac1a016a, 0, [message.pack()])
        address = ('224.0.0.2', 646)
        if self.socket:
            self.socket.sendto(pdu.pack(), address)
        else:
            print("Not sending; UDP socket dead")

    def shutdown(self):
        self.running = False
        self.socket.close()

        for eventlet in self.eventlets:
            eventlet.kill()
