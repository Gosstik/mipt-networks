import random
import socket
import inspect
import time
import threading
import queue

# Starting point
# https://github.com/ethay012/TCP-over-UDP/blob/master/TCP_over_UDP.py

# MAXIMUM_TRANSMISSION_UNIT = 1460
# DATA_DIVIDE_LENGTH =

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()

################################################################################

# TCP RFC: https://www.rfc-editor.org/rfc/rfc9293.html

#   0               1               2               3
#   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |       |C|E|U|A|P|R|S|F|                               |
#  | Offset| Rsrvd |W|C|R|C|S|S|Y|I|         window size           |
#  |       |       |R|E|G|K|H|T|N|N|                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                         Sending Time                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               :
#  :                             Data                              :
#  :                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class TCPPacket:
    CWR_OFFSET = 0
    ECE_OFFSET = 1
    URG_OFFSET = 2
    ACK_OFFSET = 3
    PSH_OFFSET = 4
    RST_OFFSET = 5
    SYN_OFFSET = 6
    FIN_OFFSET = 7

    # All sizes are written in bytes.
    HEADER_SIZE = 12
    MTU_SIZE = 1012  # == (1500 - sizeof(IP addr))
    # MTU_SIZE = 512
    MSS_SIZE = MTU_SIZE - HEADER_SIZE
    START_WINDOW_SIZE = 2**15

    def __init__(
            self,
            seq: int,
            ack: int,
            reserved: int,
            flag2: int,
            window_size: int,
            data: bytes
    ):
        # Parts of packet
        self.seq = seq  # 32 bits == 4 bytes
        self.ack = ack  # 32 bits == 4 bytes
        self.reserved = reserved  # 8 bits == 1 byte
        self.flags2 = flag2  # 8 bits == 1 byte
        self.window_size = window_size  # 16 bits == 2 bytes
        self.data = data

        # Other
        self.sending_time = time.time()  # for rtt, not included in packet

    @staticmethod
    def create_new(seq: int, ack: int, data: bytes) -> 'TCPPacket':
        res = TCPPacket(
            seq=seq,
            ack=ack,
            reserved=0,
            flag2=0,
            window_size=0,
            data=data,
        )
        return res

    def dump(self) -> bytes:
        seq = self.seq.to_bytes(4, "big", signed=False)
        ack = self.ack.to_bytes(4, "big", signed=False)
        reserved = int(0).to_bytes(1, "big", signed=False)
        flag2 = self.flags2.to_bytes(1, "big", signed=False)
        window_size = self.window_size.to_bytes(2, "big", signed=False)

        return seq + ack + reserved + flag2 + window_size + self.data

    @staticmethod
    def load(data: bytes) -> 'TCPPacket':
        res = TCPPacket(
            seq=int.from_bytes(data[:4], "big", signed=False),
            ack=int.from_bytes(data[4:8], "big", signed=False),
            reserved=int.from_bytes(data[8:9], "big", signed=False),
            flag2=int.from_bytes(data[9:10], "big", signed=False),
            window_size=int.from_bytes(data[10:12], "big", signed=False),
            data=data[12:],
        )

        return res

    def set_ack(self) -> None:
        self.flags2 |= (1 << TCPPacket.ACK_OFFSET)

    def is_ack(self) -> bool:
        return (self.flags2 & (1 << TCPPacket.ACK_OFFSET)) != 0

    def set_fin(self) -> None:
        self.flags2 |= (1 << TCPPacket.FIN_OFFSET)

    def is_fin(self) -> bool:
        return (self.flags2 & (1 << TCPPacket.FIN_OFFSET)) != 0

    # Compatibility with PriorityQueue
    def __lt__(self, other: 'TCPPacket'):
        return self.seq < other.seq

    def __eq__(self, other: 'TCPPacket'):
        return self.seq == other.seq

    # Debug.
    def __str__(self):
        res = inspect.cleandoc(f"""
        SEQ Number: {self.seq}
        ACK Number: {self.ack}
        ACK: {self.is_ack()}
        (sending_time): {self.sending_time}
        (elapsed_time): {time.time() - self.sending_time}
        DATA: {self.data}""")

        res = f"{res}\n(data_len):{len(self.data)}\n(packet_len):{len(res)}"

        return res

################################################################################


# Retransmission timeout: https://datatracker.ietf.org/doc/html/rfc6298
class TcpRetransmissionTimeout:
    _alpha = 1 / 8
    _beta = 1 / 4

    def __init__(self):
        self._srtt: int | None = None
        self._rttvar: int | None = None
        self._rto = 0.1

    def get(self) -> float:
        return self._rto

    def update(self, rtt: float) -> None:
        if self._rttvar is not None:
            self._rttvar = (1 - self._beta) * self._rttvar + \
                           self._beta * abs(self._srtt - rtt)
            self._srtt = (1 - self._alpha) * self._srtt + self._alpha * rtt
        else:
            self._srtt = rtt
            self._rttvar = rtt / 2
            # self._rto = max(self._alpha * self._rttvar + self._beta * self._srtt, 0.0001)
            self._rto = self._alpha * self._rttvar + self._beta * self._srtt


################################################################################


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._seq = 0
        self._ack = 0

        self._send_cv = threading.Condition()

        self.timeout = TcpRetransmissionTimeout()

        self.conn_closed = False

        # Items from that window will eventually be received.
        self._recv_window = queue.PriorityQueue(
            maxsize=0  # TCPPacket.START_WINDOW_SIZE // TCPPacket.MSS_SIZE
        )

        self.recv_loop_t = threading.Thread(target=self._recv_loop)
        self.recv_loop_t.daemon = True
        self.recv_loop_t.start()

        pass

    def send(self, send_data: bytes) -> int:
        data_list = self._split_send_data(send_data, TCPPacket.MSS_SIZE)
        for data in data_list:
            packet = TCPPacket.create_new(self._seq, self._ack, data)
            packet.sending_time = time.time()
            old_seq = self._seq
            self.sendto(packet.dump())
            time.sleep(self.timeout.get() * 1.5)

            while self._seq == old_seq:
                packet.sending_time = time.time()
                self.sendto(packet.dump())
                time.sleep(self.timeout.get() * 1.5)

        return len(send_data)

    def recv(self, n: int) -> bytes:
        cur_size = 0
        res_data = b""
        while cur_size < n:
            packet = self._recv_window.get()
            res_data += packet.data
            cur_size += len(packet.data)

        assert cur_size == n
        return res_data

    def close(self):
        fin_packet = TCPPacket.create_new(self._seq, self._ack, b"")
        fin_packet.set_fin()
        self.sendto(fin_packet.dump())

        # self.recv_loop_t.join()  # TODO

        # super().close()  # TODO

    ############################################################################
    # Internals

    @staticmethod
    def _split_send_data(send_data: bytes, gran: int) -> list[bytes]:
        res = [send_data[i: i + min(gran, len(send_data) - i)] for i in range(0, len(send_data), gran)]
        return res

    def _recv_loop(self):
        while not self.conn_closed:
            recv_data = self.recvfrom(TCPPacket.MTU_SIZE)
            recv_packet = TCPPacket.load(recv_data)

            if recv_packet.is_fin():
                break

            if recv_packet.is_ack():
                # assert self._ack <= recv_packet.seq
                if self._seq < recv_packet.ack:
                    self._seq = recv_packet.ack  # sync with send()
                    self.timeout.update(time.time() - recv_packet.sending_time)
                else:
                    # Duplicate ack
                    pass
                continue

            assert self._ack >= recv_packet.seq  # otherwise it is reordering
            if self._ack == recv_packet.seq:
                # expected packet
                self._ack = recv_packet.seq + len(recv_packet.data)
                self._recv_window.put(recv_packet)  # TODO: change in previous solution

            reply_packet = TCPPacket.create_new(recv_packet.ack, self._ack, b"")
            reply_packet.set_ack()
            self.sendto(reply_packet.dump())  # TODO: maybe in loop?
