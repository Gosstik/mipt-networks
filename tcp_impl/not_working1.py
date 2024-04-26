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
#  |                                                               :
#  :                             Data                              :
#  :                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class TCPPacket:
    SMALLEST_STARTING_SEQ = 0
    HIGHEST_STARTING_SEQ = 4294967295

    CWR_OFFSET = 0
    ECE_OFFSET = 1
    URG_OFFSET = 2
    ACK_OFFSET = 3
    PSH_OFFSET = 4
    RST_OFFSET = 5
    SYN_OFFSET = 6
    FIN_OFFSET = 7

    # All sizes are written in bytes.
    HEADER_SIZE = 96 // 8  # == 12
    # MTU_SIZE = 1460  # == (1500 - sizeof(IP addr))
    MTU_SIZE = 512  # == (1500 - sizeof(IP addr))
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
        self.sending_time = time.time()

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

    # @staticmethod
    # def cmp(a, b):
    #     return (a > b) - (a < b)
    #
    # def __cmp__(self, other):
    #     return TCPPacket.cmp(self.seq, other.seq)

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


# https://datatracker.ietf.org/doc/html/rfc6298
class TcpRetransmissionTimeout:
    _alpha = 1 / 8
    _beta = 1 / 4

    def __init__(self):
        self._srtt: int | None = None
        self._rttvar: int | None = None
        self._rto = 1

    def get(self) -> float:
        # print(f"rto = {self._rto}")
        return self._rto

    def update(self, rtt: float) -> None:
        if self._rttvar is not None:
            self._rttvar = (1 - self._beta) * self._rttvar + \
                           self._beta * abs(self._srtt - rtt)
            self._srtt = (1 - self._alpha) * self._srtt + self._alpha * rtt
        else:
            self._srtt = rtt
            self._rttvar = rtt / 2
            self._rto = max(self._alpha * self._rttvar + self._beta * self._srtt, 0.005)


################################################################################


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Items in that window must be ok-ed.
        self._send_window = queue.PriorityQueue(
            maxsize=TCPPacket.START_WINDOW_SIZE // TCPPacket.MSS_SIZE
        )
        # Items from that window will eventually be received.
        self._recv_window = queue.PriorityQueue(
            maxsize=TCPPacket.START_WINDOW_SIZE // TCPPacket.MSS_SIZE
        )
        self._recv_set: set[int] = set()

        self.timeout = TcpRetransmissionTimeout()
        self._prev_packet: TCPPacket | None = None

        self._seq: int = 0  # TODO: make random
        self._seq_acked: int = 0
        self._ack: int = 0
        self.conn_closed = False
        self._require_retransmission = False
        self._cv = threading.Condition()

        self.recv_loop_thread = threading.Thread(target=self._recv_loop)
        self.recv_loop_thread.daemon = True
        self.recv_loop_thread.start()

        self.retr_loop_thread = threading.Thread(target=self._retransmission_loop)  # TODO: join
        self.retr_loop_thread.daemon = True
        self.retr_loop_thread.start()

    def send(self, send_data: bytes) -> int:
        data_lst = MyTCPProtocol._divide_into_packages(send_data)
        for data in data_lst:
            # print("START SENDING", flush=True)
            packet = TCPPacket.create_new(self._seq, self._ack, data)
            self._prev_packet = packet
            raw_packet = packet.dump()
            self._seq += len(raw_packet)
            ret = self.sendto(packet.dump())  # TODO: what if it returns less?
            assert ret == len(raw_packet)

            while self._seq != self._seq_acked:
                # print("IN CYCLE", flush=True)
                if time.time() - self._prev_packet.sending_time > self.timeout.get():
                    # print("RESENDING", flush=True)
                    self._prev_packet.sending_time = time.time()
                    self.sendto(self._prev_packet.dump())  # TODO: what if it returns less?
                    # self.sendto(self._prev_packet.dump())
                time.sleep(0)

        # print("EXIT SENDING", flush=True)

        return len(send_data)
        # return self.sendto(data)

    def recv(self, n: int) -> bytes:
        recv_size = 0
        res_data = b""
        while recv_size < n:  # TODO: not the best way
            # print(f"BEFORE GET, recv_size = {recv_size}, n = {n}", flush=True)
            # packet: TCPPacket = self._recv_window.get()
            # print("AFTER GET", flush=True)
            # res_data += packet.data

            # print(f"BEFORE GET, recv_size = {recv_size}, n = {n}", flush=True)
            new_data = self._recv_window.get()
            res_data += new_data
            # print("AFTER GET", flush=True)

            # print(f"DATA: {res_data}")

            recv_size += len(new_data)
            # recv_size = n

        # print("EXIT RECV", flush=True)

        return res_data

    def close(self):
        try:
            if not self.conn_closed:
                self.conn_closed = True
                fin_packet = TCPPacket.create_new(self._seq, self._ack, b"")
                fin_packet.set_fin()
                raw_fin_packet = fin_packet.dump()
                self.sendto(raw_fin_packet)

                with self._cv:
                    self._cv.notify()
                # self.recv_loop_thread.join()
                self.retr_loop_thread.join()

                # super().close()  # TODO: fix
        except OSError as e:
            print(f"Error, must be bad descriptor (FIX IT): {e}")

    ############################################################################
    # Internals

    @staticmethod
    def _divide_into_packages(data: bytes) -> list[bytes]:
        res = [data[i:i + min(TCPPacket.MSS_SIZE, len(data) - i)]
               for i in range(0, len(data), TCPPacket.MSS_SIZE)]

        return res

    rl = 0

    def _recv_loop(self) -> None:
        try:
            while not self.conn_closed:
                # print("START RECV LOOP", flush=True)
                raw_packet = self.recvfrom(TCPPacket.MTU_SIZE)
                packet = TCPPacket.load(raw_packet)

                # print(f"######\npacket = {str(packet)}\n######", flush=True)
                if packet.is_fin():
                    # print("CLOSING")
                    # super().close()
                    # fin_packet = TCPPacket.create_new(self._seq, self._ack, b"")
                    # fin_packet.set_fin()
                    # fin_packet.set_ack()
                    # self.sendto(fin_packet.dump())
                    return

                if self._require_retransmission:
                    if packet.is_ack() and self._seq == packet.ack:
                        self._require_retransmission = False
                        self._seq_acked = packet.ack
                        self.timeout.update(time.time() - packet.sending_time)
                    continue

                if packet.is_ack():
                    if self._seq > packet.ack:
                        # Retransmission of lost or reordered packet
                        with self._cv:
                            self._require_retransmission = True
                            self._cv.notify()
                    else:
                        self._seq_acked = packet.ack
                        self.timeout.update(time.time() - packet.sending_time)
                    continue

                # New packet
                if self._ack > packet.seq:
                    # print("Packet loss or reordering!!!!!!!!!!!!!!!!!!", flush=True)
                    # Packet loss or reordering
                    packet.set_ack()
                    packet.seq = packet.ack  # TODO: remove, it is unused
                    packet.ack = self._ack  # retransmission must occur
                    packet.data = b""  # to make packet less
                    self.sendto(packet.dump())  # TODO: batch them
                    continue

                # if self._ack == packet.seq:
                #     # print("ACKED", flush=True)
                self._ack = packet.seq + len(raw_packet)
                self._recv_window.put(packet.data, block=True, timeout=None)

                packet.set_ack()
                packet.seq = self._seq  # TODO: remove, it is unused
                packet.ack = self._ack
                packet.data = b""  # to make packet less
                self.sendto(packet.dump())  # TODO: batch them

                #     packet, address = self.own_socket.recvfrom(SENT_SIZE)
                #     packet = pickle.loads(packet)
                #     self.sort_answers(packet, address)
                # except socket.timeout:
                #     continue
        except socket.error as error:
            self.close()
            # super().close()
            print(f"Recv loop socket error {error}")

    def _retransmission_loop(self):
        while not self.conn_closed:
            with self._cv:
                while not self._require_retransmission:
                    # print("WAITING")
                    self._cv.wait()
                    if self.conn_closed:
                        # print("FINISHED WAITING")
                        return

            if time.time() - self._prev_packet.sending_time > self.timeout.get():
                # print(f"rto = {self.timeout._rto}")
                # print(f"_retransmission_loop {MyTCPProtocol.rl}", flush=True)
                # MyTCPProtocol.rl += 1
                # self._prev_packet.is_ack()
                self._prev_packet.sending_time = time.time()
                self.sendto(self._prev_packet.dump())
            time.sleep(time.time() - self._prev_packet.sending_time)  # TODO: sleep more


############################################################################
############################################################################
############################################################################


import os
import struct

class Base:
    def __init__(self, socket: MyTCPProtocol, iterations: int, msg_size: int):
        self.socket = socket
        self.iterations = iterations
        self.msg_size = msg_size


class EchoServer(Base):
    def run(self):
        for i in range(self.iterations):
            # print(f"Server iter = {i}")
            # print("Server receiving msg", flush=True)
            msg = self.socket.recv(self.msg_size)
            # print("Server sending msg", flush=True)
            self.socket.send(msg)


class EchoClient(Base):
    def run(self):
        for i in range(self.iterations):
            # print(f"Client iter = {i}")
            msg = os.urandom(self.msg_size)
            # print("Client sending msg", flush=True)
            n = self.socket.send(msg)
            assert n == self.msg_size
            # print("Client receiving msg", flush=True)
            assert msg == self.socket.recv(n)


class ParallelClientServer(Base):
    def run(self):
        for i in range(self.iterations):
            msg = struct.pack('!Q', i)
            n = self.socket.send(msg)
            assert n == len(msg)

        for i in range(self.iterations):
            msg = self.socket.recv(8)
            i_recv = struct.unpack('!Q', msg)[0]
            assert i_recv == i


used_ports = {}


def generate_port():
    while True:
        port = random.randrange(25000, 30000)
        if port not in used_ports:
            break
    used_ports[port] = True
    return port


def run_test(client_class, server_class, iterations, msg_size=None):
    a_addr = ('127.0.0.1', generate_port())
    b_addr = ('127.0.0.1', generate_port())

    a = MyTCPProtocol(local_addr=a_addr, remote_addr=b_addr)
    b = MyTCPProtocol(local_addr=b_addr, remote_addr=a_addr)

    client = client_class(a, iterations=iterations, msg_size=msg_size)
    server = server_class(b, iterations=iterations, msg_size=msg_size)

    # client_thread = threading.Thread(target=client.run)
    server_thread = threading.Thread(target=server.run)
    # client_thread.daemon = True
    server_thread.daemon = True

    # client_thread.start()
    server_thread.start()

    client.run()

    # client_thread.join()
    server_thread.join()

    a.close()
    b.close()


if __name__ == "__main__":
    iterations = 2
    run_test(EchoClient, EchoServer, iterations=iterations, msg_size=11)
