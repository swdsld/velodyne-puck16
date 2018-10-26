import socket
import struct
import time
import datetime
import keyboard
import re
from types import SimpleNamespace
import queue
import binascii
import threading

# class for packet live capture
class LiveCapture():
    def __init__(self, interface_address, queue_size=10000):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.s.bind((interface_address, 0))
        self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.packet_count = 0
        self.myqueue = queue.Queue(maxsize=queue_size)

    @staticmethod
    def make_filename():
        time_ = datetime.datetime.now()
        filename = "velodyne_" + str(time_)
        filename = filename.replace(" ", "_").replace(":", "-").replace(".", "-")
        filename += "." + 'mcap'
        return filename

    # capture packets continuously
    def sniff_continuously(self, udp_port=None):  # sniff packet
        self.packet_count = float('inf')
        while True:
            packet = self.s.recvfrom(65565)
            packet = packet[0]

            ip_header_ = struct.unpack('!BBHHHBBH4s4s', packet[0:20])
            ip_header_length = (ip_header_[0] & 0xF) * 4

            tcp_header_ = packet[ip_header_length:ip_header_length + 20]
            tcp_header_ = struct.unpack('!HHLLBBHHH', tcp_header_)

            source_port = tcp_header_[0]
            dest_port = tcp_header_[1]

            data = packet[28:]
            data = binascii.b2a_hex(data).decode('utf-8')

            packet = {'captured_length': len(packet) + 14, 'timestamp': time.time(), 'source': source_port, 'dest': dest_port, 'data': data}
            packet = SimpleNamespace(**packet)
            if (udp_port is None) or (udp_port == source_port):
                if self.myqueue.full() is False:
                    self.myqueue.put(packet)

    # capture packet with packet_count or timeout option
    def sniff(self, packet_count=None, timeout=None, udp_port=None):  # sniff packet
        count = 0
        start_time = time.time()
        count_flag = packet_count is not None
        time_flag = timeout is not None

        and_flag = count_flag & time_flag
        or_flag = count_flag | time_flag
        if and_flag is True or or_flag is False:
            return
        while True:
            if count_flag is True:
                if count >= packet_count:
                    break
            elif time_flag is True:
                if time.time() - start_time >= timeout:
                    break
            packet = self.s.recvfrom(65565)
            packet = packet[0]

            ip_header_ = struct.unpack('!BBHHHBBH4s4s', packet[0:20])
            ip_header_length = (ip_header_[0] & 0xF) * 4

            tcp_header_ = packet[ip_header_length:ip_header_length + 20]
            tcp_header_ = struct.unpack('!HHLLBBHHH', tcp_header_)

            source_port = tcp_header_[0]
            dest_port = tcp_header_[1]

            data = packet[28:]
            data = binascii.b2a_hex(data).decode('utf-8')

            packet = {'captured_length': len(packet) + 14, 'timestamp': time.time(), 'source': source_port, 'dest': dest_port, 'data': data}
            packet = SimpleNamespace(**packet)

            if (udp_port is None) or (udp_port == source_port):
                if self.myqueue.full() is False:
                    self.myqueue.put(packet)
                count += 1
        self.packet_count = count

    # capture and save as mcap file (mcap is just text file) -- threading applied due to performance challenge
    def sniff_save(self, udp_port=None, packet_count=float('inf')):
        filename = self.make_filename()
        file = open(filename, 'w')
        init_time = time.time()
        worker = threading.Thread(target=self.sniff_continuously, args=(udp_port,))
        worker.setDaemon(True)
        worker.start()
        count = 0
        while count < packet_count:
            file.write(str(self.myqueue.get()))
            count += 1
            if count % 10000 == 0:
                print(count, ' packet saved..')
            if time.time() - init_time > 60 * 5:
                break
            if keyboard.is_pressed('f1'):
                break
        file.close()
        print('file will be stored as ', filename)
        return filename

    def connection_check(self, udp_port=None):
        self.sniff(timeout=1, udp_port=udp_port)
        if self.myqueue.empty() is True:
            return False
        else:
            return True

# class for captured packet file
class FileCapture():
    def __init__(self, filename):
        self.file = open(filename, 'r')
        self.myqueue = queue.Queue()
        self.packet_count = 0
        return
    # load packets to queue --
    def load_packets(self):
        packets = self.file.readline().split('namespace')
        count = 0

        for packet in packets:
            if len(packet) == 0:
                continue
            if count % 10000 == 0:
                print(count, ' packet loaded..')

            packet = packet.replace(')', '').replace('(', '').replace(' ', '')
            packet = re.split(',|=', packet)
            packet = {packet[0]: int(packet[1]), packet[2]: packet[3].replace('\'', ''), packet[4]: int(packet[5]),
                      packet[6]: int(packet[7]), packet[8]: float(packet[9])}
            packet = SimpleNamespace(**packet)
            self.myqueue.put(packet)
            count += 1
        self.packet_count = count
        return

def pcap2mcap(input_filename, output_filename, udp_port):
    import pyshark
    capture = pyshark.FileCapture(input_filename)
    capture.load_packets()
    file = open(output_filename, 'w')
    count = 0
    for packet in capture._packets:
        if udp_port is None or int(packet[2].port) == udp_port:
            packet_ = {'captured_length': int(packet.captured_length), 'timestamp': time.time(),
                       'source': int(packet[2].port), 'dest': int(packet[2].port), 'data': packet[3].data}
            packet_ = SimpleNamespace(**packet_)
            file.write(str(packet_))
        count += 1
        if count % 1000 == 0:
            print(count, ' packet converted')
    file.close()
    return

if __name__ == '__main__':
    print('main')
    # ---------- LiveCapture example ----------------
    capture = LiveCapture('192.168.1.77',10)
    filename = capture.sniff_save(udp_port=2368)

    # capture = LiveCapture('192.168.1.77', 10)
    # for packet in capture.sniff_continuously(udp_port=2368):
    #     print(packet)
    # -----------------------------------------------

    # ---------- FileCapture example -----------------
    # cap = FileCapture('velodyne_2018-08-27_13-28-05-028528.mcap')
    # cap.load_packets()
    # packet = cap.myqueue.get()
    # print(packet.data)
    # ------------------------------------------------

    # print(capture.connection_check(udp_port=2368))
    # pcap2mcap('2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.pcap', '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap', 2368)
