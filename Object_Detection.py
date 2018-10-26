import Velodyne_MP
import keyboard
import numpy as np
import cv2
import time
import functools
import vtk_visualizer as vtkv

FILTER_SIZE = 4
ITERATION = 2

vtk_obj = vtkv.VTKVisualizerControl()

def object_localization(azimuth_stack, distance_stack, reflectivity_stack):
    occup_grid = Velodyne_MP.occupancy_grid(azimuth_stack, distance_stack, reflectivity_stack, grid_size=Velodyne_MP.GRID_SIZE)
    xyz = Velodyne_MP.cloud_vis(azimuth_stack, distance_stack, reflectivity_stack, mode='intensity', visualization=False)
    bbox, centroid = Velodyne_MP.object_candidate(occup_grid, FILTER_SIZE, ITERATION, 0.1, 'up', True)
    bbox = bbox.astype(np.float64)
    vtk_obj.AddColoredPointCloudActor(xyz)
    residue = (FILTER_SIZE - 1) * ITERATION + 1
    residue /= 2
    for bbox_ in bbox[1:, :]:
        box_idx = np.array([bbox_[1] + residue, bbox_[1] + bbox_[3] - residue, bbox_[0] + residue, bbox_[0] + bbox_[2] - residue, -4, 10])
        box_idx /= (Velodyne_MP.GRID_SIZE /
                    Velodyne_MP.MAXIMUM_DISTANCE) / 2
        box_idx[:4] -= 100
        vtk_obj.AddBox(box_idx)
    vtk_obj.Render()
    vtk_obj.RemoveAllActors()

    return 0

if __name__ == '__main__':
    filename = '2014-11-10-10-36-54_Velodyne-VLP_10Hz-County Fair.mcap'
    # filename = 'rightside.mcap'
    # filename = None
    # my_method = functools.partial(Velodyne_MP.occupancy_grid, grid_size=Velodyne_MP.GRID_SIZE, threshold=0.1, updown='up')
    work1, work2, queue_out = Velodyne_MP.capture_full_rotation_multiprocess(object_localization, filename)

