from eventlet.green import socket
import select

class MulticastSocket:
    def __init__(self, multicast_group, port, listen_ip):
        self.multicast_group = multicast_group
        self.port = port
        self.listen_ip = listen_ip
        self.socket = None
        self.poller = None

    def bind(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.multicast_group, self.port))
        self.socket.setsockopt(
            socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(self.multicast_group) + socket.inet_aton(self.listen_ip)
        )

        self.poller = select.poll()
        self.poller.register(self.socket,
                          select.POLLIN |
                          select.POLLPRI |
                          select.POLLERR |
                          select.POLLHUP |
                          select.POLLNVAL)

    def recv(self, size, timeout):
        events = self.poller.poll(timeout)
        if events:
            while events:
                if len(events) > 1:
                    raise Exception("Too many events returned from poller")
                fd, event = events[0]
                if event == select.POLLERR or event == select.POLLHUP or event == select.POLLNVAL:
                    # should do something proper here, it's probably a dead socket or something
                    raise Exception("Socket error")
                if event == select.POLLIN:
                    data, address = self.socket.recvfrom(size)
                    return data, address # this is awful, find a better way to get the data out and return something
        return None, None

    def send(self, data):
        address = (self.multicast_group, self.port)
        self.socket.sendto(data, address)

    def shutdown(self):
        self.socket.close()

