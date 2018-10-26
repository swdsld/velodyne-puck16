import Velodyne_MP
import keyboard
import numpy as np
import cv2
import time
from multiprocessing import Process, Queue
import vtk_visualizer as vtkv

GRID_SIZE = 600
FILTER_SIZE = 4
ITERATION = 2

def occupancy_grid(qin_x, qin_y, qin_z, queue_out, grid_size, threshold=None, updown=None):
    cell_size = Velodyne_MP.MAXIMUM_DISTANCE * 2 / GRID_SIZE
    print('occupancy_grid')

    while True:
        x = qin_x.get()
        y = qin_y.get()
        z = qin_z.get()

        x_ = ((x + Velodyne_MP.MAXIMUM_DISTANCE) / cell_size).astype(int)
        y_ = ((y + Velodyne_MP.MAXIMUM_DISTANCE) / cell_size).astype(int)
        xyz = np.vstack([x_, y_, z]).transpose()
        xyz = xyz[np.all(xyz < GRID_SIZE, axis=1)]

        uniq_x = np.unique(xyz[:, 0])
        grid = np.zeros((GRID_SIZE, GRID_SIZE))

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

        if threshold is not None:
            if updown == 'down':
                grid[np.where(grid >= threshold)] = 0
                grid[np.where(grid != 0)] = 1
            elif updown == 'up':
                grid[np.where(grid < threshold)] = 0
                grid[np.where(grid >= threshold)] = 1

        queue_out.put(grid)

if __name__ == '__main__':
    filename = '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap'
    # filename = 'rightside.mcap'
    # filename = None
    queues = Velodyne_MP.init_queue(1)
    work = Process(target=Velodyne_MP.capture_full_rotation_queue, args=(queues[0], queues[1], queues[2], filename))
    work.start()

    queue_ = Queue()
    queues_ = Velodyne_MP.init_queue(1)
    work2 = Process(target=occupancy_grid, args=(queues_[0], queues_[1], queues_[2], queue_, GRID_SIZE, 0.1, 'up'))
    work2.start()

    while True:
        time_ = time.time()
        if keyboard.is_pressed('esc'):
            break
        azimuth, distance, reflectivity = queues[0].get(), queues[1].get(), queues[2].get()
        # ------------------------------------------------------------------------------------
        azimuth = np.tile(azimuth, (16, 1))
        channel_stack = np.tile(np.sort(Velodyne_MP.LASER_ANGLE)[::-1], (np.size(azimuth, 1), 1)).transpose()
        x, y, z = Velodyne_MP.sphere_to_cart(distance, channel_stack, azimuth)
        x = x.reshape(-1)
        y = y.reshape(-1)
        z = z.reshape(-1)

        x_ = x[np.where((x != 0) & (y != 0) & (z != 0))]
        y_ = y[np.where((x != 0) & (y != 0) & (z != 0))]
        z_ = z[np.where((x != 0) & (y != 0) & (z != 0))]

        queues_[0].put(x_)
        queues_[1].put(y_)
        queues_[2].put(z_)

        res = queue_.get()
        vtkv.plotxyz(np.hstack([x.reshape([-1, 1]), y.reshape([-1, 1]), z.reshape([-1, 1])]))
        res_ = cv2.dilate(np.uint8(res), np.ones((FILTER_SIZE, FILTER_SIZE)), iterations=ITERATION)
        res_ = cv2.connectedComponentsWithStats(np.uint8(res_), connectivity=8)
        bbox = res_[2][np.where(res_[2][:, 4] > (1 + ITERATION * (FILTER_SIZE - 1)))]
        centroid = res_[3][np.where(res_[2][:, 4] > (1 + ITERATION * (FILTER_SIZE - 1)))] - [GRID_SIZE/2, GRID_SIZE/2]
        shortest = np.argmin(np.linalg.norm(centroid[1:, :], axis=1))
        print(np.min(np.linalg.norm(centroid[1:, :], axis=1)) / 3)
        count = 0
        for bbox_ in bbox[1:, :]:
            res = cv2.rectangle(res, (bbox_[0], bbox_[1]), (bbox_[0] + bbox_[2], bbox_[1] + bbox_[3]), color=1, thickness=3 if count == shortest else 1)
            count += 1
        res = cv2.circle(res, (int(GRID_SIZE / 2), int(GRID_SIZE / 2)), 3, 2, thickness=4)
        cv2.imshow('fd', res)
        cv2.waitKey(1)
        # print(time.time() - time_)
        # ------------------------------------------------------------------------------------
