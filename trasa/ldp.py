from eventlet.green import socket
from eventlet import sleep, GreenPool
from time import time

import struct
import select

from .ldp_pdu import LdpPdu, parse_ldp_pdu
from .ldp_message import LdpHelloMessage

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

        self.pool.waitall()

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
                self.send_hello(1)
                message_id += 1
                next_timer_at += 5

    def send_hello(self, message_id):
        tlvs = [
            build_byte_string("04000004002dc000"),
            build_byte_string("04010004ac1a016a"),
            build_byte_string("0402000400000001")
        ]
        message = LdpHelloMessage(message_id, tlvs)
        pdu = LdpPdu(1, 0xac1a016a, 0, [message.pack()])
        address = ('172.26.1.101', 646)
        if self.socket:
            self.socket.sendto(pdu.pack(), address)

    def shutdown(self):
        self.running = False
        self.socket.close()

        for eventlet in self.eventlets:
            eventlet.kill()
