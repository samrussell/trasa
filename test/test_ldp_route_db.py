from trasa.ldp_route_db import LdpRouteDb

from ipaddress import IPv4Address, IPv4Network
import unittest

class LdpRouteDbTestCase(unittest.TestCase):
    def test_add_route(self):
        route_db = LdpRouteDb()
        self.assertEqual(len(route_db.routes), 0)
        route_db.add_route((IPv4Network('10.0.0.8/30'), 16))
        self.assertEqual(len(route_db.routes), 1)

    def test_remove_route(self):
        route_db = LdpRouteDb()
        self.assertEqual(len(route_db.routes), 0)
        route_db.add_route((IPv4Network('10.0.0.8/30'), 16))
        self.assertEqual(len(route_db.routes), 1)
        route_db.remote_route((IPv4Network('10.0.0.8/30'), 16))
        self.assertEqual(len(route_db.routes), 0)
