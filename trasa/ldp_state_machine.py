from .ldp_message import LdpInitialisationMessage, LdpKeepaliveMessage
from .ldp_pdu import LdpPdu
from copy import copy

class LdpStateMachine:
    def __init__(self):
        self.messages_sent = 0

    def message_received(self, message):
        print("Message: %s" % message)

        outbound_pdus = []
        # simple mode - when we get an initialisation message send one back
        if isinstance(message, LdpInitialisationMessage):
            message_id = self.messages_sent+1
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
            pdu = LdpPdu(1, 0xac1a016a, 0, [reply_message.pack()])
            outbound_pdus.append(pdu)
        # simple mode part 2 - do the same with keepalives
        elif isinstance(message, LdpKeepaliveMessage):
            reply_message = copy(message)
            message_id = self.messages_sent+1
            reply_message.message_id = message_id
            pdu = LdpPdu(1, 0xac1a016a, 0, [reply_message.pack()])
            outbound_pdus.append(pdu)

        self.messages_sent += len(outbound_pdus)

        return outbound_pdus
