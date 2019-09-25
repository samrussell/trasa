from eventlet.green import socket
from eventlet import sleep, GreenPool
from time import time

import struct
import select

from .ldp_pdu import LdpPdu, parse_ldp_pdu
from .ldp_message import LdpHelloMessage
from .ldp_state_machine import LdpStateMachine
from .stream_server import StreamServer
from .chopper import Chopper

from .error import SocketClosedError

def build_byte_string(hex_stream):
    values = [int(x, 16) for x in map(''.join, zip(*[iter(hex_stream)]*2))]
    return struct.pack("!" + "B" * len(values), *values)

class Ldp(object):
    LISTEN_PORT = 646
    MULTICAST_ADDRESS = '224.0.0.2'

    def __init__(self, listen_ip):
        self.listen_ip = listen_ip
        self.running = False
        self.socket = None
        self.state_machine = None
        self.eventlets = []

    def run(self):
        self.running = True
        self.state_machine = LdpStateMachine()
        self.pool = GreenPool()
        self.eventlets = []

        self.eventlets.append(self.pool.spawn(self.handle_packets_in))
        self.eventlets.append(self.pool.spawn(self.hello_timer))
        self.eventlets.append(self.pool.spawn(self.run_tcp_handler))

        self.pool.waitall()

    def run_tcp_handler(self):
        print("Starting TCP socket on %s:%s" % (self.listen_ip, self.LISTEN_PORT))
        self.stream_server = StreamServer((self.listen_ip, self.LISTEN_PORT), self.handle_tcp)
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
                pdu = parse_ldp_pdu(serialised_pdu)
                messages = pdu.messages
                for message in messages:
                    outbound_pdus = self.state_machine.message_received(message)
                    for pdu in outbound_pdus:
                        socket.send(pdu.pack())

            except SocketClosedError as e:
                print("Socket closed from %s:%s" % (peer_ip, peer_port))
        socket.close()

    def handle_packets_in(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.MULTICAST_ADDRESS, self.LISTEN_PORT))
        self.socket.setsockopt(
            socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(self.MULTICAST_ADDRESS) + socket.inet_aton(self.listen_ip)
        )

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
                            data, address = self.socket.recvfrom(4096)
                            pdu = parse_ldp_pdu(data)
                            messages = pdu.messages
                            if len(messages) > 1:
                                print("Weird... got PDU from %s with lots of messages: " % (address, messages))
                                continue

                            message = messages[0]
                            if not isinstance(message, LdpHelloMessage):
                                print("Got message from %s but it isn't a hello message: %s" % (address, message))
                                continue

                            print("Got hello message from %s ID %s" % (address, message.message_id))
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
        address = (self.MULTICAST_ADDRESS, self.LISTEN_PORT)
        if self.socket:
            self.socket.sendto(pdu.pack(), address)
        else:
            print("Not sending; UDP socket dead")

    def shutdown(self):
        self.running = False
        self.socket.close()

        for eventlet in self.eventlets:
            eventlet.kill()
