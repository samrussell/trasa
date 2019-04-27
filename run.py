import sys
import yaml
import signal

from eventlet import GreenPool
import eventlet.greenthread as greenthread

from trasa.ldp import Ldp

def printmsg(msg):
    sys.stderr.write("%s\n" % msg)
    sys.stderr.flush()

class Server(object):
    def __init__(self):
        self.peering_hosts = []
        self.greenlets = set()
        self.trasas = []

    def run(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        pool = GreenPool()

        with open("config.yml") as file:
            config = yaml.load(file.read())
        for router in config["routers"]:
            printmsg("Starting trasa on %s" % router["local_address"])
            trasa = Ldp()
            self.trasas.append(trasa)
            pool.spawn(self.call_handler, trasa)
        pool.waitall()
        printmsg("All greenlets gone, exiting")

    def call_handler(self, trasa):
        self.greenlets.add(greenthread.getcurrent())
        trasa.run()
        self.greenlets.remove(greenthread.getcurrent())

    def signal_handler(self, _signal, _frame):
        printmsg("[SIGINT] Shutting down")
        self.shutdown()

    def shutdown(self):
        for trasa in self.trasas:
            printmsg("Shutting down trasa %s" % trasa)
            trasa.shutdown()

    def peer_up_handler(self, peer_ip, peer_as):
        printmsg("[Peer up] %s %d" % (peer_ip, peer_as))

    def peer_down_handler(self, peer_ip, peer_as):
        printmsg("[Peer down] %s %s" % (peer_ip, peer_as))

    def error_handler(self, msg):
        printmsg("[Error] %s" % msg)

    def route_handler(self, route_update):
        if route_update.is_withdraw:
            printmsg("[Route handler] Route removed: %s" % route_update)
        else:
            printmsg("[Route handler] New route received: %s" % route_update)

if __name__ == "__main__":
    server = Server()
    server.run()
