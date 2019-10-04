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
from .multicast_socket import MulticastSocket

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
                    outbound_messages = self.state_machine.message_received(message)
                    outbound_pdus = []
                    for message in outbound_messages:
                        pdu = LdpPdu(1, "172.26.1.106", 0, [message.pack()])
                        outbound_pdus.append(pdu)
                    for pdu in outbound_pdus:
                        socket.send(pdu.pack())

            except SocketClosedError as e:
                print("Socket closed from %s:%s" % (peer_ip, peer_port))
        socket.close()

    def handle_packets_in(self):
        self.multicast_socket = MulticastSocket(self.MULTICAST_ADDRESS, self.LISTEN_PORT, self.listen_ip)
        self.multicast_socket.bind()

        try:
            while self.running:
                sleep(1)
                while True:
                    data, address = self.multicast_socket.recv(4096, 10)
                    if not data:
                        break

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
            0x0401 : build_byte_string("ac1a016a")
        }
        message = LdpHelloMessage(message_id, 15, False, False, tlvs)
        pdu = LdpPdu(1, "172.26.1.106", 0, [message.pack()])
        if self.multicast_socket:
            self.multicast_socket.send(pdu.pack())
        else:
            print("Not sending; UDP socket dead")

    def shutdown(self):
        self.running = False
        self.multicast_socket.shutdown()

        for eventlet in self.eventlets:
            eventlet.kill()
