import Myshark
import numpy as np
import threading
import keyboard
import winsound
import queue
import time
import matplotlib
from types import SimpleNamespace
from scipy.signal import medfilt2d
import cv2
import vtk_visualizer as vtkv

data_port = 2368  # vlp 16 udp data port
data_packet_len = 1248  # vlp 16 data packet length
position_port = 8308  # vlp 16 upd position port
position_packet_len = 554  # vlp 16 position packet length
channel_num = 16
data_block_num = 12
block_length = 200
laser_angle = np.array([-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5, 11, -3, 13, -1, 15])
azimuth_head_threshold = 0.4
azimuth_tail_threshold = 359.5
alarm_count = 0

# just capture and enqueue packets
def sniffing(interface_address='192.168.1.77', udp_port=data_port, queue_size=30):
    capture = Myshark.LiveCapture(interface_address, queue_size)
    worker = threading.Thread(target=capture.sniff_continuously, args=(udp_port,))
    worker.setDaemon(True)
    worker.start()

    return capture

# capture packets, then execute method packet by packet
def exec_method_while_sniffing(method, interface_address='192.168.1.77', packet_count=float('inf'), udp_port=data_port, queue_size=50):
    capture = Myshark.LiveCapture(interface_address, queue_size)
    worker = threading.Thread(target=capture.sniff_continuously, args=(udp_port,))
    worker.setDaemon(True)
    worker.start()

    #method should only have 1 argument, packet
    count = 0
    while count < packet_count:
        if keyboard.is_pressed('f1'):
            break
        method(capture.myqueue.get())
        count += 1
    return

# capture packets, then execute method packet py packet with yield option
def exec_method_while_sniffing_yield(method, interface_address='192.168.1.77', packet_count=float('inf'), udp_port=data_port, queue_size=50):
    capture = Myshark.LiveCapture(interface_address, queue_size)
    worker = threading.Thread(target=capture.sniff_continuously, args=(udp_port,))
    worker.setDaemon(True)
    worker.start()

    #method should only have 1 argument, packet
    count = 0
    while count < packet_count:
        if keyboard.is_pressed('f1'):
            break
        yield method(capture.myqueue.get())
        count += 1
    return

def print_packet(packet):
    print(packet)
    return

def return_packet(packet):
    return packet

def get_azimuth(azimuth):
    azimuth = azimuth[2:] + azimuth[:2]
    return int(azimuth, 16) / 100

def get_distance_reflectivify(channel_data):
    # distance = int(channel_data[2:4] + channel_data[:2], 16) * 2  # mm
    distance = int(channel_data[2:4] + channel_data[:2], 16) / 500  # m
    reflectivity = int(channel_data[4:], 16)
    return distance, reflectivity

def get_timestamp(timestamp):
    temp = split_by_length(timestamp, 2)
    temp = temp[::-1]
    temp = ''.join(temp)
    temp = int(temp, 16) / 1000000
    return temp

def get_factory_bytes(factory_bytes):
    return_mode = ['strongest', 'last', 'dual']
    sensor = ['hdl-32e', 'vlp-16']
    return_mode_value = int(factory_bytes[:2])
    sensor_value = int(factory_bytes[2:])
    return return_mode[return_mode_value-37], sensor[sensor_value-21]

def split_by_length(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]

def azimuth_interpolation(azimuth):
    for i in range(0, data_block_num):
        if i == 11:
            azimuth[2 * i + 1] = azimuth[2 * i] + temp
        else:
            if azimuth[2 * i] < azimuth[2 * i + 2]:
                azimuth[2 * i + 1] = (azimuth[2*i] + azimuth[2 * i + 2])/2
                temp = (azimuth[2 * i + 2] - azimuth[2 * i]) / 2
            else:
                azimuth[2 * i + 1] = (azimuth[2 * i] + azimuth[2 * i + 2] + 360) / 2
        if azimuth[2 * i + 1] > 360:
            azimuth[2 * i + 1] -= 360
    return azimuth

def sphere_to_cart(distance, vertical_angle, horizontal_angle):
    x = distance*np.cos(np.deg2rad(vertical_angle))*np.sin(np.deg2rad(horizontal_angle))
    y = distance*np.cos(np.deg2rad(vertical_angle))*np.cos(np.deg2rad(horizontal_angle))
    z = distance*np.sin(np.deg2rad(vertical_angle))
    return x, y, z

def myhstack(input, target):
    if len(input) == 0:
        input = target
    else:
        input = np.hstack([input, target])
    return input

def myvstack(input, target):
    if len(input) == 0:
        input = target
    else:
        input = np.vstack([input, target])
    return input

# convert velodyne data block to azimuth, distance, reflectivity, timestamp and factory bytes
def convert_data(data, show=False):
    data = split_by_length(data, block_length)
    azimuth = np.zeros(data_block_num * 2)
    azimuth_ = [data[i][4:8] for i in range(0, 12)]
    azimuth[0::2] = [get_azimuth(x) for x in azimuth_]
    azimuth = azimuth_interpolation(azimuth)
    distance_reflectivity = [split_by_length(data[i][8:], 6) for i in range(0, 12)]
    distance_reflectivity = np.reshape(distance_reflectivity, [24, 16])
    # idx = 0
    dist_reflect_stack = []
    for channel_data in distance_reflectivity:
        temp = [get_distance_reflectivify(channel_data[i]) for i in range(0, 16)]
        if len(dist_reflect_stack) == 0:
            dist_reflect_stack = temp
        else:
            dist_reflect_stack = np.hstack([dist_reflect_stack, temp])

    distance = dist_reflect_stack[:, 0::2]
    reflectivity = dist_reflect_stack[:, 1::2]
    timestamp = get_timestamp(data[12][:8])
    factory_bytes = get_factory_bytes(data[12][8:])

    converted_data = {'azimuth': azimuth, 'distance': distance, 'reflectivity': reflectivity, 'timestamp': timestamp,
            'factory_bytes': factory_bytes}
    if show is True:
        print(convert_data)
    converted_data = SimpleNamespace(**converted_data)
    return converted_data

# just for input type change (packet.data -> packet) -- packet sniffer requires packet as argument
def packet_analyze(packet):
    return convert_data(packet.data)

def color_mapping(input_stack):
    saturation = np.ones(np.shape(input_stack))
    intensity = np.ones(np.shape(input_stack))
    input_stack /= np.max(input_stack)
    input_stack = (1 - input_stack) * 0.6
    input_stack = np.dstack([input_stack, saturation, intensity])
    input_stack = matplotlib.colors.hsv_to_rgb(input_stack)
    input_stack *= 255
    return input_stack

# capture single full rotation, then execute method over captured data
def capture_full_rotation(method, filename=None):
    if filename is None:
        capture = sniffing(queue_size=10)
        if capture.connection_check(udp_port=data_port) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    laser_order = np.argsort(laser_angle)[::-1]
    while True:
        if keyboard.is_pressed('f1'):
            break
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < azimuth_head_threshold and head_found is False:
            head_found = True
            head = np.argmin(data.azimuth)
            azimuth_stack = data.azimuth[head:]
            distance_stack = data.distance[:, head:]
            reflectivity_stack = data.reflectivity[:, head:]
            count_flag = 0
            continue
        if capture.myqueue.full() is True:
            head_found = False
        if head_found is True:
            if np.max(data.azimuth) > azimuth_tail_threshold and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == data_block_num * 2 - 1:
                    head = data_block_num * 2
                azimuth_stack = myhstack(azimuth_stack, data.azimuth[:head])
                distance_stack = myhstack(distance_stack, data.distance[:, :head])
                distance_stack = distance_stack[laser_order, :]
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity[:, :head])
                reflectivity_stack = reflectivity_stack[laser_order, :]
                #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                method(azimuth_stack, distance_stack, reflectivity_stack)
                #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                azimuth_stack = data.azimuth[head:]
                distance_stack = data.distance[:, head:]
                reflectivity_stack = data.reflectivity[:, head:]
                count_flag = 0
            else:
                azimuth_stack = myhstack(azimuth_stack, data.azimuth)
                distance_stack = myhstack(distance_stack, data.distance)
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity)
                count_flag += 1
    return


# capture single full rotation, then execute method over captured data with yield option
def capture_full_rotation_yield(method, filename=None):
    if filename is None:
        capture = sniffing(queue_size=10)
        if capture.connection_check(udp_port=data_port) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    laser_order = np.argsort(laser_angle)[::-1]
    while True:
        if keyboard.is_pressed('f1'):
            break
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < azimuth_head_threshold and head_found is False:
            head_found = True
            head = np.argmin(data.azimuth)
            azimuth_stack = data.azimuth[head:]
            distance_stack = data.distance[:, head:]
            reflectivity_stack = data.reflectivity[:, head:]
            count_flag = 0
            continue
        if capture.myqueue.full() is True:
            head_found = False
        if head_found is True:
            if np.max(data.azimuth) > azimuth_tail_threshold and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == data_block_num * 2 - 1:
                    head = data_block_num * 2
                azimuth_stack = myhstack(azimuth_stack, data.azimuth[:head])
                distance_stack = myhstack(distance_stack, data.distance[:, :head])
                distance_stack = distance_stack[laser_order, :]
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity[:, :head])
                reflectivity_stack = reflectivity_stack[laser_order, :]
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                yield method(azimuth_stack, distance_stack, reflectivity_stack)
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                azimuth_stack = data.azimuth[head:]
                distance_stack = data.distance[:, head:]
                reflectivity_stack = data.reflectivity[:, head:]
                count_flag = 0
            else:
                azimuth_stack = myhstack(azimuth_stack, data.azimuth)
                distance_stack = myhstack(distance_stack, data.distance)
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity)
                count_flag += 1
    return

# capture single full rotation, then enqueue azimuth, distance, reflectivity data -- recommended for threading
def capture_full_rotation_queue(a_queue, d_queue, r_queue, filename=None):
    if filename is None:
        capture = sniffing(queue_size=10)
        if capture.connection_check(udp_port=data_port) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    packet_count = 0
    laser_order = np.argsort(laser_angle)[::-1]
    while True:
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < azimuth_head_threshold and head_found is False:
            head_found = True
            head = np.argmin(data.azimuth)
            azimuth_stack = data.azimuth[head:]
            distance_stack = data.distance[:, head:]
            reflectivity_stack = data.reflectivity[:, head:]
            count_flag = 0
            continue
        if capture.myqueue.full() is True:
            head_found = False
        if head_found is True:
            if np.max(data.azimuth) > azimuth_tail_threshold and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == data_block_num * 2 - 1:
                    head = data_block_num * 2
                azimuth_stack = myhstack(azimuth_stack, data.azimuth[:head])
                distance_stack = myhstack(distance_stack, data.distance[:, :head])
                distance_stack = distance_stack[laser_order, :]
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity[:, :head])
                reflectivity_stack = reflectivity_stack[laser_order, :]
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                a_queue.put(azimuth_stack)
                d_queue.put(distance_stack)
                r_queue.put(reflectivity_stack)
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                azimuth_stack = data.azimuth[head:]
                distance_stack = data.distance[:, head:]
                reflectivity_stack = data.reflectivity[:, head:]
                count_flag = 0
            else:
                azimuth_stack = myhstack(azimuth_stack, data.azimuth)
                distance_stack = myhstack(distance_stack, data.distance)
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity)
                count_flag += 1
        packet_count += 1

def capture_full_rotation_thread(method, filename=None):
    queues = init_queue(1)
    work = threading.Thread(target=capture_full_rotation_queue, args=(queues[0], queues[1], queues[2], filename))
    work.setDaemon(True)
    work.start()
    while True:
        if keyboard.is_pressed('esc'):
            queues[0].task_done()
            queues[1].task_done()
            queues[2].task_done()
            return
        azimuth, distance, reflectivity = queues[0].get(), queues[1].get(), queues[2].get()
        method(azimuth, distance, reflectivity)

def init_queue(maxsize):
    a_queue = queue.Queue(maxsize=maxsize)
    d_queue = queue.Queue(maxsize=maxsize)
    r_queue = queue.Queue(maxsize=maxsize)
    return a_queue, d_queue, r_queue

# method for capture_full_rotation & capture_full_rotation_yield -- visualize as 2d image
def plane_vis(azimuth_stack, distance_stack, reflectivity_stack, brightness=0.1, noise_reduction=False):
    temp = distance_stack
    distance_stack *= brightness
    if noise_reduction is True:
        distance_stack = medfilt2d(distance_stack, 3)
    distance_stack = cv2.resize(distance_stack, ((np.size(distance_stack, 1) // 100) * 100, channel_num * 10))
    cv2.imshow('LIDAR 2d plane visualization', distance_stack)
    cv2.waitKey(1)
    return azimuth_stack, temp, reflectivity_stack

# method for capture_full_rotation & capture_full_rotation_yield -- visualize as 3d point cloud

prev = None
def cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, mode=None):
    global prev
    azimuth_stack = np.tile(azimuth_stack, (16, 1))
    channel_stack = np.tile(np.sort(laser_angle)[::-1], (np.size(azimuth_stack, 1), 1)).transpose()
    x, y, z = sphere_to_cart(distance_stack, channel_stack, azimuth_stack)
    xyz = np.hstack([x.reshape([-1, 1]), y.reshape([-1, 1]), z.reshape([-1, 1])])
    hold = False
    block = False
    if keyboard.is_pressed('f3'):
        hold = True
    if keyboard.is_pressed('f4'):
        block = True
    if keyboard.is_pressed('f5'):
        vtkv.plotxyz(prev)
        return
    if mode is None:
        vtkv.plotxyz(xyz, color='y', hold=hold, block=block)
        prev = xyz
    elif mode =='intensity':
        reflectivity_stack = color_mapping(reflectivity_stack)
        rgb = reflectivity_stack.reshape(-1, 3)
        xyzrgb = np.hstack([xyz, rgb])
        vtkv.plotxyzrgb(xyzrgb, hold=hold, block=block)
        prev = xyz
    elif mode == 'azimuth':
        azimuth_stack = color_mapping(azimuth_stack)
        rgb = azimuth_stack.reshape(-1, 3)
        xyzrgb = np.hstack([xyz, rgb])
        vtkv.plotxyzrgb(xyzrgb, hold=hold, block=block)
        prev = xyz
    # print(np.mean(x))
    return x, y, z

# use this method if you want to crop certain fov, or you can make your own method with this
def fov_crop(azimuth_stack, distance_stack, reflectivity_stack, start=350, end=10):
    if start > end:
        start = np.where(azimuth_stack > start)
        end = np.where(azimuth_stack < end)
        fov = np.concatenate([end[0], start[0]], axis=None)
    else:
        fov = np.where((azimuth_stack > start) & (azimuth_stack < end))
        fov = fov[0]

    return azimuth_stack[fov], distance_stack[:, fov], reflectivity_stack[:, fov]

def fov_distance_sensing(azimuth_stack, distance_stack, reflectivity_stack, start=350, end=10, min_dist=1.6):
    sensitivity = 0.85
    close = False

    _, roi, _ = fov_crop(azimuth_stack, distance_stack, reflectivity_stack, start, end)
    if np.size(roi) == 0:
        return close
    if np.count_nonzero(roi) / np.size(roi) < sensitivity:
        close = True
    elif np.min(roi[np.nonzero(roi)]) < min_dist:
        close = True
    return close

# fov stack must have (-1, 3) shape, each row must have start angle, end angle, and distance
def multiple_fov_alarm(azimuth_stack, distance_stack, reflectivity_stack, fov_stack, sound=False):
    targets=[]
    if type(fov_stack) == list:
        fov_stack = np.array(fov_stack)
    fov_num = np.size(fov_stack, 0)
    for i in range(0, fov_num):
        targets.append(fov_distance_sensing(azimuth_stack, distance_stack, reflectivity_stack, *fov_stack[i, :]))

    if sound is True:
        global alarm_count
        alarm_count += 1
        if (True in targets) is True and alarm_count > 10:
            for i in range(0, fov_num):
                if targets[i] is True:
                    winsound.Beep(1000 * (i+1), 50)
            alarm_count = 0
    return targets

# example of customized method -- fov alarm and plane, cloud visualization at the same time
def my_method(azimuth_stack, distance_stack, reflectivity_stack):
    # fov_stack_ = [[350, 10, 1.7], [110, 120, 2.1], [60, 70, 1.5]]
    # targets = multiple_fov_alarm(azimuth_stack, distance_stack, reflectivity_stack, fov_stack_, sound=True)
    cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, 'intensity')
    plane_vis(azimuth_stack, distance_stack, reflectivity_stack, brightness=0.01, noise_reduction=True)

    # print("'\r{0}".format(targets), end='')
    return

prev_mac_block = np.zeros([16,116])
def my_method2(azimuth_stack, distance_stack, reflectivity_stack):
    # fov_stack_ = [[350, 10, 1.7], [110, 120, 2.1], [60, 70, 1.5]]
    # targets = multiple_fov_alarm(azimuth_stack, distance_stack, reflectivity_stack, fov_stack_, sound=False)
    # cloud_vis_v2(azimuth_stack, distance_stack, reflectivity_stack)
    plane_vis(azimuth_stack, distance_stack, reflectivity_stack, noise_reduction=False, brightness=0.001)
    # plane_vis(azimuth_stack, distance_stack*10, reflectivity_stack)
    # cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, mode='intensity')
    global prev_mac_block
    # print(targets, end='\r')
    distance_stack = distance_stack * 255 / np.max(distance_stack)
    distance_stack = distance_stack.astype('uint8')
    if np.sum(prev_mac_block) == 0:
        prev_mac_block = distance_stack[:16, :16+100]
        prev_mac_block = cv2.Canny(prev_mac_block,100,200)
    else:
        mac_block = distance_stack[:16, :16+100]
        mac_block = cv2.Canny(mac_block,100,200)
        patch = prev_mac_block[:8, :8]
        diff = np.zeros([9,9+100])
        for i in range(0, 9):
            for j in range(0, 9+100):
                diff[i,j] = np.sum(patch - mac_block[i:i+8, j:j+8])
        print(np.argmin(diff)%9, np.argmin(diff)//9)
        cv2.imshow('fdf',np.concatenate([prev_mac_block, mac_block, abs(mac_block - prev_mac_block)]))
        cv2.waitKey(1)
        prev_mac_block = mac_block
if __name__ == '__main__':
    print('main')

    # ----------- exec_method_while_sniffing_yield example ------------------
    # for data_ in exec_method_while_sniffing_yield(packet_analyze, packet_count=1000):
    #      if np.max(data_.azimuth) > 359:
    #         print(data_.azimuth)
    # ------------------------------------------------------------------------

    # ----------- capture_full_rotation examples -----------------------------
    # capture_full_rotation(multiple_fov_alarm_with_sound)

    # capture_full_rotation(plane_vis, 'velodyne_2018-08-27_13-28-05-028528.mcap')
    # capture_full_rotation(plane_vis, 'leftside.mcap')

    # capture_full_rotation(cloud_vis)

    # capture_full_rotation(my_method)
    # -------------------------------------------------------------------------

    # ----------- capture_full_rotation_yield example -------------------------
    # for targets_ in capture_full_rotation_yield(lambda azimuth, distance, reflectivity:
    #                                             fov_crop(azimuth, distance, reflectivity, 10, 20)):
    #     print(targets_[0])

    # fov_stack_ = [[350, 10, 1.7], [110, 120, 2.1], [60, 70, 1.5]]
    # for targets_ in capture_full_rotation_yield(lambda azimuth, distance, reflectivity:
    #                                             multiple_fov_alarm(azimuth, distance, reflectivity, fov_stack_)):
    #     print(targets_, end='\r')
    # -------------------------------------------------------------------------

    # ----------- threading example -------------------------------------------
    # queues = init_queue(10)
    # work = threading.Thread(target=capture_full_rotation_queue, args=queues)
    # work.start()
    # fov_stack_ = [[350, 10, 1.7], [110, 120, 2.1], [60, 70, 1.5]]
    # while True:
    #     azimuth, distance, reflectivity = queues[0].get(), queues[1].get(), queues[2].get()
    #     cloud_vis(azimuth, distance, reflectivity)
    #     plane_vis(azimuth, distance, reflectivity)
    #     targets = multiple_fov_alarm(azimuth, distance, reflectivity, fov_stack_, sound=False)
    #     print(targets, end='\r')
    # -------------------------------------------------------------------------

    # ----------- capture_full_rotation_thread example ------------------------
    capture_full_rotation_thread(my_method, '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap')
    # capture_full_rotation_thread(my_method, 'leftside.mcap')
    # capture_full_rotation_thread(my_method2)
    # -------------------------------------------------------------------------
