from .ldp_message import LdpInitialisationMessage, LdpKeepaliveMessage, LdpAddressMessage, LdpLabelMappingMessage, LdpNotificationMessage
from .ldp_pdu import LdpPdu
from ipaddress import IPv4Address, IPv4Network
from copy import copy
from functools import reduce

class LdpStateMachine:
    def __init__(self, local_ip, remote_ip):
        self.local_ip = local_ip
        self.remote_ip = remote_ip

        self.initialised = False
        self.state = "INITIALISED"

    def message_received(self, message):
        print("Message: %s" % message)
        if self.state == "INITIALISED":
            return self.handle_message_initialised_state(message)
        if self.state == "OPENREC":
            return self.handle_message_openrec_state(message)
        if self.state == "OPERATIONAL":
            return self.handle_message_operational_state(message)

        raise Exception("Message received in unknown state")

    def handle_message_initialised_state(self, message):
        outbound_messages = []
        # simple mode - when we get an initialisation message send one back
        if isinstance(message, LdpInitialisationMessage):
            # send back init message
            reply_message = LdpInitialisationMessage(
                0,
                1,
                180,
                0,
                0,
                0,
                self.remote_ip,
                0,
                {}
            )
            print("Replying to initialisation message with our own message: %s" % reply_message)
            outbound_messages.append(reply_message)
            self.state = "OPENREC"
        else:
            reply_message = LdpNotificationMessage(0, 1, 0, 0x0a, message.message_id, message.MSG_TYPE, {})
            outbound_messages.append(reply_message)
            self.state = "NONEXISTENT"

        return outbound_messages

    def handle_message_openrec_state(self, message):
        outbound_messages = []
        if isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            outbound_messages.append(reply_message)
            if not self.initialised:
                # try sending some addresses too
                tlvs = {}
                addresses = [
                    IPv4Address(self.local_ip)
                ]
                # also a path and routes
                tlvs = {}
                prefixes = [
                    IPv4Network('10.0.0.8/30'),
                    IPv4Network('8.8.0.0/16')
                ]
                label = 3

                address_message = LdpAddressMessage(0, addresses, tlvs)
                label_mapping_message = LdpLabelMappingMessage(0, prefixes, label, tlvs)

                outbound_messages.append(address_message)
                outbound_messages.append(label_mapping_message)
                self.initialised = True
            self.state = "OPERATIONAL"

        return outbound_messages

    def handle_message_operational_state(self, message):
        outbound_messages = []
        if isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            outbound_messages.append(reply_message)

        return outbound_messages
