import math
import numpy as np
from PIL import Image
import pybullet as p
import pybullet_data
import streamlit as st


def create_city_buildings(client_id):
    buildings = [
        (-8, -5, 6, 6, 35, [0.4, 0.4, 0.5, 1.0]),
        (0, -6, 8, 8, 40, [0.6, 0.6, 0.7, 1.0]),
        (8, -4, 5, 5, 30, [0.45, 0.45, 0.55, 1.0]),
        (-10, 4, 5, 5, 18, [0.7, 0.6, 0.5, 1.0]),
        (6, 5, 4, 4, 12, [0.6, 0.7, 0.5, 1.0]),
    ]
    for x, y, w, d, h, color in buildings:
        half = [w / 2, d / 2, h / 2]
        col = p.createCollisionShape(p.GEOM_BOX, halfExtents=half, physicsClientId=client_id)
        vis = p.createVisualShape(p.GEOM_BOX, halfExtents=half, rgbaColor=color, physicsClientId=client_id)
        p.createMultiBody(
            baseMass=0.0,
            baseCollisionShapeIndex=col,
            baseVisualShapeIndex=vis,
            basePosition=[x, y, h / 2],
            physicsClientId=client_id,
        )


def create_drones(client_id, count, radius, altitude):
    drones = []
    for i in range(count):
        theta = (2 * math.pi * i) / max(count, 1)
        x = radius * math.cos(theta)
        y = radius * math.sin(theta)
        col = p.createCollisionShape(p.GEOM_SPHERE, radius=0.6, physicsClientId=client_id)
        vis = p.createVisualShape(p.GEOM_SPHERE, radius=0.6, rgbaColor=[0.1, 0.8, 0.1, 1.0], physicsClientId=client_id)
        body = p.createMultiBody(
            baseMass=1.0,
            baseCollisionShapeIndex=col,
            baseVisualShapeIndex=vis,
            basePosition=[x, y, altitude],
            physicsClientId=client_id,
        )
        drones.append([body, theta])
    return drones


def simulate_and_render(num_drones, orbit_radius, altitude, steps, speed):
    client_id = p.connect(p.DIRECT)
    try:
        p.setAdditionalSearchPath(pybullet_data.getDataPath())
        p.setGravity(0, 0, -9.8, physicsClientId=client_id)
        p.loadURDF("plane.urdf", physicsClientId=client_id)

        create_city_buildings(client_id)
        drones = create_drones(client_id, num_drones, orbit_radius, altitude)

        for _ in range(steps):
            for drone in drones:
                drone[1] += speed
                x = orbit_radius * math.cos(drone[1])
                y = orbit_radius * math.sin(drone[1])
                p.resetBasePositionAndOrientation(
                    drone[0], [x, y, altitude], [0, 0, 0, 1], physicsClientId=client_id
                )
            p.stepSimulation(physicsClientId=client_id)

        width = 640
        height = 360
        view = p.computeViewMatrixFromYawPitchRoll(
            cameraTargetPosition=[0, 0, 12],
            distance=80,
            yaw=45,
            pitch=-35,
            roll=0,
            upAxisIndex=2,
        )
        proj = p.computeProjectionMatrixFOV(
            fov=60,
            aspect=width / height,
            nearVal=0.1,
            farVal=200,
        )
        _, _, rgba, _, _ = p.getCameraImage(
            width=width,
            height=height,
            viewMatrix=view,
            projectionMatrix=proj,
            renderer=p.ER_TINY_RENDERER,
        )
        frame = np.reshape(rgba, (height, width, 4))[:, :, :3]
        return Image.fromarray(frame.astype(np.uint8))
    finally:
        p.disconnect(client_id)


def main():
    st.set_page_config(page_title="Drone Swarm Simulation", layout="wide")
    st.title("Drone Swarm Simulation (Headless Preview)")
    st.write(
        "This Streamlit app renders a headless snapshot of a drone swarm scene. "
        "It uses PyBullet in DIRECT mode, which is safe for Hugging Face Spaces."
    )

    with st.sidebar:
        st.header("Render Settings")
        num_drones = st.slider("Number of drones", min_value=1, max_value=12, value=6)
        orbit_radius = st.slider("Orbit radius", min_value=10, max_value=60, value=35)
        altitude = st.slider("Altitude", min_value=5, max_value=60, value=25)
        steps = st.slider("Simulation steps", min_value=1, max_value=240, value=60)
        speed = st.slider("Orbit speed", min_value=0.01, max_value=0.2, value=0.05)
        render = st.button("Render frame")

    if render:
        with st.spinner("Rendering frame..."):
            image = simulate_and_render(num_drones, orbit_radius, altitude, steps, speed)
        st.image(image, caption="Drone swarm snapshot", use_container_width=True)
    else:
        st.info("Adjust settings on the left, then click 'Render frame'.")


if __name__ == "__main__":
    main()
