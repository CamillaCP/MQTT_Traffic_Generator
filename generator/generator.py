import pandas as pd
import numpy as np
import paho.mqtt.client as mqtt
import random
import time
import threading
import argparse
import base64
import os
import signal
import subprocess

from scapy.all import *
from scapy.contrib.mqtt import MQTT, MQTTPublish, MQTTConnect, MQTTSubscribe, MQTTDisconnect


# MQTT Broker settings, including broker address and port number
broker_address = 'test.mosquitto.org'
port = 1883
client_lock = threading.Lock() # Lock for safe access to MQTT clients in multi-threading
running = True  # Global flag to indicate whether the application is running
mqtt_clients = []  # Global list to track all instantiated MQTT clients


def signal_handler(sig, frame):
    """Handle interrupt signals like SIGINT for graceful shutdown."""
    global running
    print("Signal received. Shutting down gracefully...")
    running = False # Set running to False to stop all processes
    shutdown()  # Call the shutdown function


def shutdown():
    """Shutdown function to gracefully disconnect all clients and stop the capture process if running."""
    global mqtt_clients, capture_process
    print("Initiating graceful shutdown...")

    # Gracefully disconnect all MQTT clients
    with client_lock:
        for client in mqtt_clients:
            client_id = client._client_id.decode() if client._client_id else 'Unnamed'
            if client.is_connected():  # Check if client is connected before disconnecting
                print(f"Disconnecting MQTT client {client_id}...")
                client.disconnect()  # Send the DISCONNECT packet to the broker
                time.sleep(1)  # Small delay to ensure the DISCONNECT message is sent
                client.loop_stop()
            else:
                print(f"MQTT client {client_id} is not connected. Skipping disconnection.")

        # Clear the list of clients
        mqtt_clients.clear()

    # Gracefully terminate the capture process if it is still running
    if capture_process and capture_process.poll() is None:
        print("Terminating tshark subprocess...")
        capture_process.terminate()
        capture_process.wait()
        print("tshark terminated.")

    print("Graceful shutdown complete. Exiting program.")


def create_mqtt_client(client_id=None):
    """Create and start a new MQTT client with a specified client_id."""
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id)
    client.on_message = on_message  # Set up the on_message handler
    client.connect(broker_address, port=port) # Connect to the MQTT Broker
    client.loop_start() # Start the loop for continuous operation
    client.enable_logger() # Enable logging for debugging purposes
    return client


def start_mqtt_client(client_id=None):
    """Start a new MQTT client and add it to the global list."""
    global client_lock, mqtt_clients
    with client_lock:
        client = create_mqtt_client(client_id)
        mqtt_clients.append(client)  # Add the client to the global list for tracking
        return client  # Return the client to be used by the caller


def publish_message(client, topic, qos, payload):
    """Publish a message to a specific topic using a given client with the given QoS and payload."""
    with client_lock:
        if client is None:
            print(f"MQTT client not initialized. Failed to publish message to topic {topic}.")
            return
        result = client.publish(topic, payload, qos)
        status = result[0] # Check the status of the publish operation
        if status == 0:
            print(f"Sent {payload} to topic {topic} using client {client._client_id.decode()}")
        else:
            print(f"Failed to send message to topic {topic}")


def subscribe_to_topic(client, topic, qos):
    """Subscribe to a specified topic using a given client with the given QoS level."""
    with client_lock:
        if client is None:
            print(f"MQTT client not initialized. Failed to subscribe to topic {topic}.")
            return
        client.subscribe(topic, qos)
        print(f"Subscribed to topic {topic} with QoS {qos} using client {client._client_id.decode()}")


def on_message(client, userdata, message):
    """Handle incoming messages from subscribed topics."""
    print(f"Received message {message.payload.decode()} from topic {message.topic} using client {client._client_id.decode()}")


def covert_publish(client, topic, message, payload, qos, method):
    """Publish covert messages by encoding them in the topic name based on the given method."""
    attack_bits = ''.join(format(ord(char), '08b') for char in message) # Convert covert message to binary

    for chunk in attack_bits:
        # Stop if the program is no longer running
        if not running:
            break
        new_topic = embed_message(topic, chunk, method=method) # Embed covert bit in the topic based on the method
        publish_message(client, new_topic, qos, payload)
        time.sleep(1) # Small delay for covert channel timing


def embed_message(current_topic, message_chunk, method):
    """Embed a covert message chunk into the topic name using the specified method."""
    last_topic_name = current_topic.split('/')[-1] # Extract the last level of the topic name
    split_topics = current_topic.split('/') # Split the topic by levels
    attack_bit = message_chunk # Bit of covert data to embed

    # If the selected embedding method is the letter casing, the casing of the first letter of the last level of the
    # topic name is modulated to exchange the secret information.
    if method == 'case':
        first_char = last_topic_name[0]
        # Uppercase first letter for binary '1'
        if attack_bit == '1':
            modified_last_topic = first_char.upper() + last_topic_name[1:]
        # Lowercase first letter for binary '0'
        else:
            modified_last_topic = first_char.lower() + last_topic_name[1:]
        split_topics[-1] = modified_last_topic

    # If the selected embedding method is the ID modulation, an ID is added to the last level of the topic name
    # according to the secret bit to embed
    elif method == 'id':
        id_number = int(attack_bit) + 1  # Convert the covert bit to a number (1 or 2)
        modified_last_topic = last_topic_name + str(id_number)  # Append the ID to the topic last level
        split_topics[-1] = modified_last_topic

    return '/'.join(split_topics) # Reassemble the modified topic


def periodic_publisher(client, row):
    """Function to handle periodic publishing of messages using a specific client with the specified period."""
    global running
    topic = row['Topic']
    qos = int(row['QoS'])
    payload = row['Payload']
    period = float(row['Period'])
    device_type = row['DeviceType'].strip().lower()
    covert_message = row['HiddenMessage'] if pd.notna(row['HiddenMessage']) else None
    embedding_method = row.get('EmbeddingMethod', 'case').strip().lower()
    print(f"Starting periodic publisher for topic {topic} with period {period} using client {client._client_id.decode()}")

    while running:
        if device_type == 'counterfeit' and covert_message:
            covert_publish(client, topic, covert_message, payload, qos, embedding_method)
        else:
            publish_message(client, topic, qos, payload)
        time.sleep(period) # Delay of period before the next publish cycle to publish at regular intervals


def event_publisher(client, row):
    """Function to handle event-driven publishing of messages using a specific client by publishing at randomized
     time intervals based on a specified distribution."""
    global running
    topic = row['Topic']
    qos = int(row['QoS'])
    payload = row['Payload']
    min_range = float(row['MinRange']) if pd.notna(row['MinRange']) else None
    max_range = float(row['MaxRange']) if pd.notna(row['MaxRange']) else None
    distribution = row.get('Distribution', 'uniform').lower()
    device_type = row['DeviceType'].strip().lower()
    covert_message = row['HiddenMessage'] if pd.notna(row['HiddenMessage']) else None
    embedding_method = row.get('EmbeddingMethod', 'case').strip().lower()

    print(f"Starting event publisher for topic {topic} with range {min_range}-{max_range} using client {client._client_id.decode()}")

    while running:
        # Calculate the delay (period) based on the selected distribution
        if distribution == 'uniform' and min_range is not None and max_range is not None:
            period = np.random.uniform(min_range, max_range)
        elif distribution == 'exponential' and min_range is not None and max_range is not None:
            scale = (max_range - min_range) / 2
            period = np.random.exponential(scale) + min_range
            period = min(max(period, min_range), max_range)
        elif distribution == 'normal' and min_range is not None and max_range is not None:
            mean = (min_range + max_range) / 2
            stddev = (max_range - min_range) / 4
            period = np.random.normal(mean, stddev)
            period = min(max(period, min_range), max_range)
        else:
            print(f"Unknown or incomplete distribution for topic {topic}, defaulting to uniform.")
            period = np.random.uniform(min_range, max_range) if min_range is not None and max_range is not None else 1

        if device_type == 'counterfeit' and covert_message:
            covert_publish(client, topic, covert_message, payload, qos, embedding_method)
        else:
            publish_message(client, topic, qos, payload)
        time.sleep(period)


def start_publishers_and_subscribers(data):
    """Start publishers and subscribers based on the provided CSV data."""
    for index, row in data.iterrows():
        role = row['Role'].strip().lower()
        if role == 'dos_attack':
            start_dos_attack(row)
        else:
            topic = row['Topic']
            qos = int(row['QoS']) if pd.notna(row['QoS']) else 0

            # Start a new MQTT client for each row in the CSV
            client_id = f"client_{index}"
            client = start_mqtt_client(client_id)  # Create and start a new MQTT client

            if role == 'publisher':
                if row['Type'] == 'periodic':
                    threading.Thread(target=periodic_publisher, args=(client, row)).start()
                elif row['Type'] == 'event':
                    threading.Thread(target=event_publisher, args=(client, row)).start()
            elif role == 'subscriber':
                subscribe_to_topic(client, topic, qos)


def start_dos_attack(row):
    """Function to handle the generation of high-frequency traffic to simulate a DoS attack."""
    # Number of clients for the DoS simulation, defaulting to 1 if not specified
    num_clients = int(row['NumClients']) if pd.notna(row['NumClients']) else 1
    topic = row['Topic']
    qos = int(row['QoS'])
    payload = row['Payload']
    # Set the interval (in seconds) between each message publish by each client, if not specified, default to 1 sec
    publish_interval = float(row['Period']) if pd.notna(row['Period']) else 1
    # Set the total duration (in seconds) for the DoS attack, after this duration clients will stop publishing messages
    duration = float(row['Duration']) if pd.notna(row['Duration']) else 10
    end_time = time.time() + duration # End time for the DoS attack based on the current time and the duration

    # Function to be executed by each DoS client thread
    def attack_client(client_id):
        """Function to handle the message publishing for a single DoS client.
        Each client will repeatedly publish messages to the specified topic
        until the end time is reached or the global 'running' flag is set to False.
        """
        client = start_mqtt_client(client_id)

        # Keep publishing messages until the end time is reached or 'running' is set to False
        while running and time.time() < end_time:
            publish_message(client, topic, qos, payload)
            time.sleep(publish_interval)

    # Spawn multiple threads for each DoS client based on 'num_clients' to simulate concurrent traffic
    for i in range(num_clients):
        # Each thread runs the 'attack_client' function with a unique client ID.
        threading.Thread(target=attack_client, args=(f"dos_client_{i}",)).start()
    print(
        f"Started DoS attack wih {num_clients} clients on topic '{topic}' every {publish_interval} seconds for {duration} seconds.")


def replay_pcap(file_path):
    """Replay MQTT traffic from a given PCAP file."""
    packets = rdpcap(file_path) # Read packets from the PCAP file
    last_time = None # For calculating the delay between packets
    client_id = None
    client_initialized = False
    client = None

    for packet in packets:
        # Stop if the program is interrupted
        if not running:
            break
        if MQTT in packet:
            current_time = packet.time

            # Handle MQTTConnect packets to establish connections
            if MQTTConnect in packet:
                client_id = packet[MQTTConnect].clientId.decode('utf-8')
                print(f"Initializing MQTT client with ID {client_id}")
                client = start_mqtt_client(client_id)
                client_initialized = True

            # Handle MQTTPublish packets to publish messages to topics
            elif MQTTPublish in packet and client_initialized:
                mqtt_packet = packet[MQTTPublish]
                topic = mqtt_packet.topic.decode('utf-8')
                qos = packet[MQTT].QOS
                payload = mqtt_packet.value.decode('utf-8', errors='ignore')

                print(f"Replaying publish to topic '{topic}' with payload '{payload}'")
                publish_message(client, topic, qos, payload)

            # Handle MQTTSubscribe packets to subscribe to topics
            elif MQTTSubscribe in packet and client_initialized:
                mqtt_packet = packet[MQTTSubscribe]
                for topic_sub in mqtt_packet.topics:
                    topic = topic_sub[0].decode('utf-8')
                    qos = topic_sub[1]
                    print(f"Replaying subscription to topic '{topic}' with QoS '{qos}'")
                    subscribe_to_topic(client, topic, qos)

            # Handle MQTTDisconnect packets to terminate connections
            elif MQTTDisconnect in packet and client_initialized:
                print(f"Disconnecting MQTT client {client_id}")
                client.disconnect()
                client_initialized = False
                client = None

            # Introduce delay based on packet timestamps for realistic replay based on empiric distribution
            if last_time is not None:
                delay = float(current_time - last_time)
                time.sleep(delay)
            last_time = current_time


def start_ui_config(configs):
    """Start publishers and subscribers based on the provided configurations from the UI."""
    data = pd.DataFrame(configs)
    start_publishers_and_subscribers(data)


if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description="MQTT Traffic Generator with Covert Channels and Replay")
    parser.add_argument('--csv', type=str, help='Path to the CSV file to use for traffic simulation')
    parser.add_argument('--pcap', type=str, help='Path to the PCAP file to use for traffic replay')

    args = parser.parse_args()

    if args.csv and args.pcap:
        print("Please specify only one input: either a CSV or a PCAP file.")
        exit(1)

    # Start tshark in a subprocess to capture all generated traffic
    capture_process = subprocess.Popen(
        ['tshark', '-i', 'any', '-f', f'tcp port {port}', '-w', 'generated_traffic.pcap'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    time.sleep(2) # Allow time for tshark to initialize

    # Load CSV or PCAP file based on user input
    if args.csv:
        if not os.path.exists(args.csv):
            print(f"CSV file '{args.csv}' not found.")
            exit(1)
        data = pd.read_csv(args.csv).fillna({'EmbeddingMethod': 'case'})
        start_publishers_and_subscribers(data)

    elif args.pcap:
        if not os.path.exists(args.pcap):
            print(f"PCAP file '{args.pcap}' not found.")
            exit(1)
        threading.Thread(target=replay_pcap, args=(args.pcap,)).start()

    else:
        print("Please specify either a CSV or a PCAP file.")
        exit(1)

    # Main loop to keep the script running until interrupted
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Interrupted by user")

    # Properly stop the MQTT clients and tshark subprocess
    shutdown()