from .ldp_message import LdpInitialisationMessage, LdpKeepaliveMessage, LdpAddressMessage, LdpLabelMappingMessage, LdpGenericMessage
from .ldp_pdu import LdpPdu
from ipaddress import IPv4Address, IPv4Network
from copy import copy
from functools import reduce

class LdpStateMachine:
    def __init__(self, local_ip, remote_ip):
        self.local_ip = local_ip
        self.remote_ip = remote_ip

        self.messages_sent = 0
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
            self.messages_sent = self.messages_sent + 1
            message_id = self.messages_sent
            # send back init message
            reply_message = LdpInitialisationMessage(
                message_id,
                1,
                180,
                0,
                0,
                0,
                self.remote_ip,
                0,
                {}
            )
            outbound_messages.append(reply_message)
            self.state = "OPENREC"
        else:
            self.messages_sent = self.messages_sent + 1
            message_id = self.messages_sent
            reply_message = LdpGenericMessage(0x001, message_id, {})
            outbound_messages.append(reply_message)
            self.state = "NONEXISTENT"

        return outbound_messages

    def handle_message_openrec_state(self, message):
        outbound_messages = []
        if isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            self.messages_sent = self.messages_sent + 1
            message_id = self.messages_sent
            reply_message.message_id = message_id
            outbound_messages.append(reply_message)
            if not self.initialised:
                # try sending some addresses too
                tlvs = {}
                addresses = [
                    IPv4Address('10.1.67.6'),
                    IPv4Address('10.1.56.6'),
                    IPv4Address('6.6.6.6'),
                    IPv4Address('66.6.6.6')
                ]
                self.messages_sent = self.messages_sent + 1
                message_id = self.messages_sent
                address_message = LdpAddressMessage(message_id, addresses, tlvs)
                # also a path and routes
                tlvs = {}
                prefixes = [
                    IPv4Network('10.0.0.8/30')
                ]
                label = 3
                self.messages_sent = self.messages_sent + 1
                message_id = self.messages_sent
                label_mapping_message = LdpLabelMappingMessage(message_id, prefixes, label, tlvs)

                outbound_messages.append(address_message)
                outbound_messages.append(label_mapping_message)
                self.initialised = True
            self.state = "OPERATIONAL"

        return outbound_messages

    def handle_message_operational_state(self, message):
        outbound_messages = []
        if isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            self.messages_sent = self.messages_sent + 1
            message_id = self.messages_sent
            reply_message.message_id = message_id
            outbound_messages.append(reply_message)

        return outbound_messages
