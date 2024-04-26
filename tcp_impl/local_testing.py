import random
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
            res = self.socket.recv(n)
            if msg != res:
                print(f"len(msg) = {len(msg)}")
                # print(f"msg = {msg}")
                print(f"len(res) = {len(res)}")
                # print(f"res = {res}")
                for i in range(len(res)):
                    if msg[i] != res[i]:
                        print(f"i = {i}, msg[i] = {msg[i]}, res[i] = {res[i]}")
                        break

                assert False
            # assert msg == self.socket.recv(n)


class ParallelClientServer(Base):
    def run(self):
        for i in range(self.iterations):
            print("sending msg: {}", i, flush=True)
            msg = struct.pack('!Q', i)
            n = self.socket.send(msg)
            assert n == len(msg)

        for i in range(self.iterations):
            print("receiving msg", flush=True)
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
    iterations = 50
    msg_size = 10_000_000
    # run_test(EchoClient, EchoServer, iterations=iterations, msg_size=11)
    # run_test(EchoClient, EchoServer, iterations=2, msg_size=msg_size)
    run_test(ParallelClientServer, ParallelClientServer, iterations=iterations)
