from eventlet.green import socket
from eventlet import sleep, GreenPool

import select

from .ldp_pdu import LdpPdu, parse_ldp_pdu

class Ldp(object):
    def __init__(self):
        self.listen_ip = "172.26.1.106"
        self.listen_port = 646
        self.running = False
        self.socket = None

    def run(self):
        self.running = True
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

    def shutdown(self):
        self.running = False
        self.socket.close()
