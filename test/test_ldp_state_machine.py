from trasa.ldp_state_machine import LdpStateMachine
from trasa.ldp_message import LdpInitialisationMessage

import unittest

class LdpStateMachineTestCase(unittest.TestCase):
    def test_initialisation_message_received(self):
        state_machine = LdpStateMachine()
        message = LdpInitialisationMessage(
            1,
            1,
            180,
            0,
            0,
            0,
            "172.26.1.112",
            0,
            {}
        )
        outbound_pdus = state_machine.message_received(message)
        self.assertEqual(len(outbound_pdus), 1)
