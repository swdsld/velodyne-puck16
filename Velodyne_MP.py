import Myshark_MP
import keyboard
import winsound
import matplotlib
import cv2
import numpy as np
import vtk_visualizer as vtkv
from types import SimpleNamespace
from scipy.signal import medfilt2d
from multiprocessing import Process, Queue

INTERFACE_ADDRESS = "192.168.1.77"
DATA_PORT = 2368  # vlp 16 udp data port
DATA_PACKET_LEN = 1248  # vlp 16 data packet length
POSITION_PORT = 8308  # vlp 16 upd position port
POSITION_PACKET_LEN = 554  # vlp 16 position packet length
CHANNEL_NUM = 16
DATA_BLOCK_NUM = 12
BLOCK_LENGTH = 200
LASER_ANGLE = np.array([-15, 1, -13, 3, -11, 5, -9, 7, -7, 9, -5, 11, -3, 13, -1, 15])
AZIMUTH_HEAD_THRESHOLD = 0.4
AZIMUTH_TAIL_THRESHOLD = 359.5
MAXIMUM_DISTANCE = 100  # 100 meter distance
ALARM_COUNT = 0
GRID_SIZE = 800

# just capture and enqueue packets
def sniffing(interface_address=INTERFACE_ADDRESS, udp_port=DATA_PORT, queue_size=30):
    capture = Myshark_MP.LiveCapture(interface_address, queue_size)
    worker = Process(target=capture.sniff_continuously, args=(udp_port,))
    worker.start()
    # worker.join()
    return capture

# capture packets, then execute method packet by packet
def exec_method_while_sniffing(method, interface_address=INTERFACE_ADDRESS, packet_count=float('inf'), udp_port=DATA_PORT, queue_size=50):
    capture = Myshark_MP.LiveCapture(interface_address, queue_size)
    worker = Process(target=capture.sniff_continuously, args=(udp_port,))
    worker.start()
    # worker.join()
    #method should only have 1 argument, packet
    count = 0
    while count < packet_count:
        if keyboard.is_pressed('f1'):
            break
        method(capture.myqueue.get())
        count += 1
    return

# capture packets, then execute method packet py packet with yield option
def exec_method_while_sniffing_yield(method, interface_address=INTERFACE_ADDRESS, packet_count=float('inf'), udp_port=DATA_PORT, queue_size=50):
    capture = Myshark_MP.LiveCapture(interface_address, queue_size)
    worker = Process(target=capture.sniff_continuously, args=(udp_port,))
    worker.start()
    # worker.join()
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
    return int(azimuth, CHANNEL_NUM) / 100

def get_distance_reflectivify(channel_data):
    # distance = int(channel_data[2:4] + channel_data[:2], 16) * 2  # mm
    distance = int(channel_data[2:4] + channel_data[:2], CHANNEL_NUM) / 500  # m
    reflectivity = int(channel_data[4:], CHANNEL_NUM)
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
    for i in range(0, DATA_BLOCK_NUM):
        if i == DATA_BLOCK_NUM - 1:
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
    data = split_by_length(data, BLOCK_LENGTH)
    azimuth = np.zeros(DATA_BLOCK_NUM * 2)
    azimuth_ = [data[i][4:8] for i in range(0, DATA_BLOCK_NUM)]
    azimuth[0::2] = [get_azimuth(x) for x in azimuth_]
    azimuth = azimuth_interpolation(azimuth)
    distance_reflectivity = [split_by_length(data[i][8:], 6) for i in range(0, DATA_BLOCK_NUM)]
    distance_reflectivity = np.reshape(distance_reflectivity, [DATA_BLOCK_NUM * 2, CHANNEL_NUM])
    # idx = 0
    dist_reflect_stack = []
    for channel_data in distance_reflectivity:
        temp = [get_distance_reflectivify(channel_data[i]) for i in range(0, CHANNEL_NUM)]
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
        if capture.connection_check(udp_port=DATA_PORT) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark_MP.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    laser_order = np.argsort(LASER_ANGLE)[::-1]
    while True:
        if keyboard.is_pressed('f1'):
            break
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < AZIMUTH_HEAD_THRESHOLD and head_found is False:
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
            if np.max(data.azimuth) > AZIMUTH_TAIL_THRESHOLD and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == DATA_BLOCK_NUM * 2 - 1:
                    head = DATA_BLOCK_NUM * 2
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
        if capture.connection_check(udp_port=DATA_PORT) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark_MP.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    laser_order = np.argsort(LASER_ANGLE)[::-1]
    while True:
        if keyboard.is_pressed('f1'):
            break
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < AZIMUTH_HEAD_THRESHOLD and head_found is False:
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
            if np.max(data.azimuth) > AZIMUTH_TAIL_THRESHOLD and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == DATA_BLOCK_NUM * 2 - 1:
                    head = DATA_BLOCK_NUM * 2
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
def capture_full_rotation_queue(queues, filename=None):
    if filename is None:
        capture = sniffing(queue_size=10)
        if capture.connection_check(udp_port=DATA_PORT) is False:
            print('LIDAR is not connected, please check connection')
            return
        print('LIDAR detected')
    else:
        print('loading data from mcap file')
        capture = Myshark_MP.FileCapture(filename)
        capture.load_packets()
    azimuth_stack = np.array([])
    distance_stack = np.array([])
    reflectivity_stack = np.array([])
    head_found = False
    count_flag = 0
    packet_count = 0
    laser_order = np.argsort(LASER_ANGLE)[::-1]
    while True:
        packet = capture.myqueue.get()
        data = packet_analyze(packet)
        if np.min(data.azimuth) < AZIMUTH_HEAD_THRESHOLD and head_found is False:
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
            if np.max(data.azimuth) > AZIMUTH_TAIL_THRESHOLD and count_flag != 0:
                head = np.argmin(data.azimuth)
                if np.argmax(data.azimuth) == DATA_BLOCK_NUM * 2 - 1:
                    head = DATA_BLOCK_NUM * 2
                azimuth_stack = myhstack(azimuth_stack, data.azimuth[:head])
                distance_stack = myhstack(distance_stack, data.distance[:, :head])
                distance_stack = distance_stack[laser_order, :]
                reflectivity_stack = myhstack(reflectivity_stack, data.reflectivity[:, :head])
                reflectivity_stack = reflectivity_stack[laser_order, :]
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                queues[0].put(azimuth_stack)
                queues[1].put(distance_stack)
                queues[2].put(reflectivity_stack)
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

def method_queue(method, queues_in, queue_out):
    while True:
        if keyboard.is_pressed('esc'):
            break
        azimuth_stack, distance_stack, reflectivity_stack = queues_in[0].get(), queues_in[1].get(), queues_in[2].get()
        return_val = method(azimuth_stack, distance_stack, reflectivity_stack)
        if queue_out.full() is False:
            queue_out.put(return_val)

def capture_full_rotation_multiprocess(method, filename=None):
    queues_in = init_queue(1)
    work = Process(target=capture_full_rotation_queue, args=(queues_in, filename))
    work.start()

    queue_out = Queue(1)
    work2 = Process(target=method_queue, args=(method, queues_in, queue_out))
    work2.start()

    return work, work2, queue_out

def init_queue(maxsize):
    a_queue = Queue(maxsize=maxsize)
    d_queue = Queue(maxsize=maxsize)
    r_queue = Queue(maxsize=maxsize)
    return a_queue, d_queue, r_queue

# method for capture_full_rotation & capture_full_rotation_yield -- visualize as 2d image
def plane_vis(azimuth_stack, distance_stack, reflectivity_stack, brightness=0.1, noise_reduction=False):
    temp = distance_stack
    distance_stack *= brightness
    if noise_reduction is True:
        distance_stack = medfilt2d(distance_stack, 3)
    distance_stack = cv2.resize(distance_stack, (round(np.size(distance_stack, 1), -2), CHANNEL_NUM * 10))
    cv2.imshow('LIDAR 2d plane visualization', distance_stack)
    cv2.waitKey(1)
    return distance_stack

# method for capture_full_rotation & capture_full_rotation_yield -- visualize as 3d point cloud

prev = None
def cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, mode=None, visualization=True):
    global prev
    azimuth_stack = np.tile(azimuth_stack, (CHANNEL_NUM, 1))
    channel_stack = np.tile(np.sort(LASER_ANGLE)[::-1], (np.size(azimuth_stack, 1), 1)).transpose()
    x, y, z = sphere_to_cart(distance_stack, channel_stack, azimuth_stack)
    p_cloud = np.hstack([x.reshape([-1, 1]), y.reshape([-1, 1]), z.reshape([-1, 1])])
    hold = False
    block = False
    if keyboard.is_pressed('f3'):
        hold = True
    if keyboard.is_pressed('f4'):
        block = True
    if keyboard.is_pressed('f5'):
        if prev.shape[1] == 6:
            vtkv.plotxyzrgb(prev)
        else:
            vtkv.plotxyz(prev)
        return
    if mode is None:
        prev = p_cloud
    elif mode =='intensity':
        reflectivity_stack = color_mapping(reflectivity_stack)
        rgb = reflectivity_stack.reshape(-1, 3)
        p_cloud = np.hstack([p_cloud, rgb])
        prev = p_cloud
    elif mode == 'azimuth':
        azimuth_stack = color_mapping(azimuth_stack)
        rgb = azimuth_stack.reshape(-1, 3)
        p_cloud = np.hstack([p_cloud, rgb])
        prev = p_cloud
    if visualization is True:
        if p_cloud.shape[1] == 6:
            vtkv.plotxyzrgb(p_cloud, hold=hold, block=block)
        else:
            vtkv.plotxyz(p_cloud, hold=hold, block=block)
    return p_cloud

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
    sensitivity = 0.8
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
        global ALARM_COUNT
        ALARM_COUNT += 1
        if (True in targets) is True and ALARM_COUNT > 10:
            for i in range(0, fov_num):
                if targets[i] is True:
                    winsound.Beep(1000 * (i+1), 50)
            ALARM_COUNT = 0
    return targets

def occupancy_grid(azimuth, distance, reflectivity, grid_size=GRID_SIZE):
    cell_size = MAXIMUM_DISTANCE * 2 / grid_size
    azimuth = np.tile(azimuth, (CHANNEL_NUM, 1))
    channel_stack = np.tile(np.sort(LASER_ANGLE)[::-1], (np.size(azimuth, 1), 1)).transpose()
    x, y, z = sphere_to_cart(distance, channel_stack, azimuth)
    x = x.reshape(-1)
    y = y.reshape(-1)
    z = z.reshape(-1)

    idx = np.where((x != 0) & (y != 0) & (z != 0))

    x = x[idx]
    y = y[idx]
    z = z[idx]

    x_ = ((x + MAXIMUM_DISTANCE) / cell_size).astype(int)
    y_ = ((y + MAXIMUM_DISTANCE) / cell_size).astype(int)
    xyz = np.vstack([x_, y_, z]).transpose()
    xyz = xyz[np.all(xyz < grid_size, axis=1)]

    uniq_x = np.unique(xyz[:, 0])
    grid = np.zeros((grid_size, grid_size))

    for tx in uniq_x:
        uniq_idx = np.where(xyz[:, 0] == tx)
        uniq_xyz = xyz[uniq_idx[0], :]
        uniq_y = np.unique(uniq_xyz[:, 1])
        if len(uniq_xyz[:, 1]) == len(uniq_y):
            continue
        else:
            for ty in uniq_y:
                ty_idx = np.where((uniq_xyz[:, 1] == ty))
                if ty_idx[0].size == 1:
                    continue
                else:
                    z_ = uniq_xyz[ty_idx, 2]
                    grid[int(tx), int(ty)] = np.max(z_) - np.min(z_)

    return grid

def object_candidate(occup_grid, filter_size, iteration, threshold, bound, visualization=False):
    if bound == 'down':
        occup_grid[np.where(occup_grid >= threshold)] = 0
        occup_grid[np.where(occup_grid != 0)] = 1
    elif bound == 'up':
        occup_grid[np.where(occup_grid < threshold)] = 0
        occup_grid[np.where(occup_grid >= threshold)] = 1
    occup_grid_dilated = cv2.dilate(np.uint8(occup_grid), np.ones((filter_size, filter_size)), iterations=iteration)
    occup_grid_dilated = cv2.connectedComponentsWithStats(np.uint8(occup_grid_dilated), connectivity=8)
    bbox = occup_grid_dilated[2][np.where(occup_grid_dilated[2][:, 4] > pow((1 + iteration * (filter_size - 1)), 2) * 2)]
    centroid = occup_grid_dilated[3][np.where(occup_grid_dilated[2][:, 4] > pow((1 + iteration * (filter_size - 1)), 2) * 2)] - [GRID_SIZE/2, GRID_SIZE/2]
    shortest = np.argmin(np.linalg.norm(centroid[1:, :], axis=1))
    count = 0
    for bbox_ in bbox[1:, :]:
        occup_grid = cv2.rectangle(occup_grid, (bbox_[0], bbox_[1]), (bbox_[0] + bbox_[2], bbox_[1] + bbox_[3]), color=1, thickness=3 if count == shortest else 1)
        count += 1
    occup_grid = cv2.circle(occup_grid, (int(GRID_SIZE / 2), int(GRID_SIZE / 2)), 3, 2, thickness=4)
    if visualization is True:
        cv2.imshow('LIDAR Object Detection', occup_grid)
        cv2.waitKey(1)
        print("\rdist: {0}".format(np.min(np.linalg.norm(centroid[1:, :], axis=1)) / 3), end='')
    return bbox, centroid

def object_localization(azimuth_stack, distance_stack, reflectivity_stack):
    occup_grid = occupancy_grid(azimuth_stack, distance_stack, reflectivity_stack, grid_size=GRID_SIZE)
    cloud_vis(azimuth_stack, distance_stack, reflectivity_stack)
    return object_candidate(occup_grid, 4, 2, 0.1, 'up', True)

# example of customized method -- fov alarm and plane, cloud visualization at the same time
def my_method(azimuth_stack, distance_stack, reflectivity_stack):

    fov_stack_ = [[350, 10, 1.7], [110, 120, 2.1], [60, 70, 1.5]]
    targets = multiple_fov_alarm(azimuth_stack, distance_stack, reflectivity_stack, fov_stack_, sound=True)
    cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, 'azimuth')
    plane_vis(azimuth_stack, distance_stack, reflectivity_stack, brightness=0.1, noise_reduction=True)
    print("'\r{0}".format(targets), end='')
    return 0

def my_method2(azimuth_stack, distance_stack, reflectivity_stack):

    fov_stack_ = [[315, 45, 3], [45, 135, 3], [135, 225, 3], [225, 315, 3]]
    targets = multiple_fov_alarm(azimuth_stack, distance_stack, reflectivity_stack, fov_stack_, sound=True)
    cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, 'intensity')
    plane_vis(azimuth_stack, distance_stack, reflectivity_stack, brightness=0.01, noise_reduction=True)
    print("'\r{0}".format(targets), end='')

    return 0

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
    #
    # capture_full_rotation(cloud_vis)
    # capture_full_rotation(plane_vis)
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
    # capture_full_rotation_thread(my_method, '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap')
    # capture_full_rotation_thread(my_method, 'leftside.mcap')
    # q = Queue(1)
    # work1, work2, q = capture_full_rotation_multiprocess(my_method2, '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap')
    work1, work2, q = capture_full_rotation_multiprocess(my_method)
    # work1, work2, q = capture_full_rotation_multiprocess(object_detection2,'rightside.mcap')
    # -------------------------------------------------------------------------
