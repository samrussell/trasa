from .ldp_message import LdpInitialisationMessage, LdpKeepaliveMessage, LdpAddressMessage, LdpLabelMappingMessage
from .ldp_pdu import LdpPdu
from ipaddress import IPv4Address, IPv4Network
from copy import copy
from functools import reduce

class LdpStateMachine:
    def __init__(self):
        self.messages_sent = 0
        self.initialised = False

    def message_received(self, message):
        print("Message: %s" % message)

        outbound_pdus = []
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
                "172.26.1.112",
                0,
                {}
            )
            pdu = LdpPdu(1, "172.26.1.106", 0, [reply_message.pack()])
            outbound_pdus.append(pdu)
        # simple mode part 2 - do the same with keepalives
        elif isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            self.messages_sent = self.messages_sent + 1
            message_id = self.messages_sent
            reply_message.message_id = message_id
            pdu = LdpPdu(1, "172.26.1.106", 0, [reply_message.pack()])
            outbound_pdus.append(pdu)
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

                pdu = LdpPdu(1, "172.26.1.106", 0, [address_message.pack(), label_mapping_message.pack()])
                outbound_pdus.append(pdu)
                self.initialised = True

        return outbound_pdus
