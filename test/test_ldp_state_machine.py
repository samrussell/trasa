from trasa.ldp_state_machine import LdpStateMachine
from trasa.ldp_message import LdpInitialisationMessage, LdpKeepaliveMessage

import unittest

class LdpStateMachineTestCase(unittest.TestCase):
    def test_initialised_initialisation_message_received(self):
        state_machine = LdpStateMachine("172.26.1.106", "172.26.1.112")
        self.assertEqual(state_machine.state, "INITIALISED")

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
        outbound_messages = state_machine.message_received(message)
        self.assertEqual(len(outbound_messages), 1)
        self.assertTrue(isinstance(outbound_messages[0], LdpInitialisationMessage))
        self.assertEqual(state_machine.state, "OPENREC")

    def test_initialised_keepalive_message_received(self):
        state_machine = LdpStateMachine("172.26.1.106", "172.26.1.112")
        self.assertEqual(state_machine.state, "INITIALISED")
        message = LdpKeepaliveMessage(2, {})
        outbound_messages = state_machine.message_received(message)
        self.assertEqual(len(outbound_messages), 1)
        #self.assertTrue(isinstance(outbound_messages[0], LdpNotificationMEssage)) # doesn't exist yet
        self.assertEqual(state_machine.state, "NONEXISTENT")

    def test_openrec_keepalive_message_received(self):
        state_machine = LdpStateMachine("172.26.1.106", "172.26.1.112")

        self.assertEqual(state_machine.state, "INITIALISED")
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
        outbound_messages = state_machine.message_received(message)
        self.assertEqual(state_machine.state, "OPENREC")

        message = LdpKeepaliveMessage(2, {})
        outbound_messages = state_machine.message_received(message)
        self.assertEqual(state_machine.state, "OPERATIONAL")
