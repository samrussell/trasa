class LdpRouteDb(object):
    def __init__(self):
        self.routes = set()

    def add_route(self, route):
        self.routes.add(route)

    def remove_route(self, route):
        self.routes.remove(route)
