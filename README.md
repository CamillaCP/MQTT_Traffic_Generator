# MQTT-traffic-generator 

This project is an MQTT (Message Queuing Telemetry Transport) traffic generator with two main modes of operation, namely **Manual Configuration** and **Empirical Distribution Mode**, that also supports the establishment of network covert channels exploiting MQTT topic names and the simulation of DoS (Denial of Service) attacks towards the MQTT broker. 

## Modes of Operation

1. **Manual Configuration Mode**, that enables the user to manually configure the necessary MQTT traffic parameters for the generation process. The user can specify a variety of configuration options, including client roles, topic names, message payload, Quality of Service (QoS) levels, and timing behaviors. The configuration options are saved to a CSV file, that is then used by the generator to simulate MQTT traffic according to these specifications.

2. **Empirical Distribution Mode**, that enables the user to specify an existing PCAP file to be used for MQTT traffic replay. The replay covers all recorded MQTT interactions, including message timing, providing a highly accurate simulation of realistic, previously captured data.

## Features

- _UI for Custom Configuration_: Define and save MQTT traffic configurations through a graphical interface, with access to both modes of operation. This allows users to configure MQTT traffic parameters directly, as well as specifying the existing PCAP file for traffic replay.
- _Simulation of Counterfeit Nodes_: Embed hidden messages within MQTT topic names using two distinct covert channel techniques, namely the modulation of the letter casing or the insertion of a counterfeit ID, as well as the possibility to simulate a DoS attack targeting the MQTT broker.
- _Support for Both Event-Driven and Periodic Publishing_: Set publishing intervals for event-driven or periodic messages, with customizable delay distributions (i.e., uniform, exponential, and normal).
- _Traffic Capture_: Automatically captures all generated traffic using `tshark` and saves it to a PCAP file.

## Configuration Options

The following options can be defined and saved in a CSV file through the UI. The saved configurations are used by the generator to simulate or replay MQTT traffic.

### General Options
- _Mode_: The mode of operation for the tool. As mentioned, the available modes are:
  - **Manual Configuration**
  - **Empirical Distribution Mode**, that only requires the specification of the path of the PCAP file containing the previously captured MQTT traffic.
- _Role_: The role of the MQTT client. The options are:
  - **Publisher**: Sends messages to a specified topic.
  - **Subscriber**: Listens to a specified topic for incoming messages.
  - **DoS_Attack**: Allows for the simulation of a DoS attack through the instantiation of a large number of Publisher nodes. 
 
### Publisher-specific Options
These options only apply when _Role_ is set to **Publisher**.
- _Topic_: The MQTT Topic Name where messages will be published.
- _QoS_: The level of Quality of Service (i.e., 0, 1, or 2) for the message published on the given topic.
- _Payload_: The message content that the publisher will send to the topic.
- _Type_: The publishig behavior of the publisher, that can be chosen between:
  - **Periodic**: Messages are sent at regular intervals specified by the _Period_ option. 
  - **Event**: Messages are sent at randomized intervals between the specified _MinRange_ and _MaxRange_ time intervals, determined by the probability distribution specified in the _Distribution_ setting (i.e., uniform, exponential, or normal).
- _DeviceType_: Specifies the type of device generating the traffic. The options are:
  - **Legit**: A regular, non-counterfeit MQTT client.
  - **Counterfeit** : A compromised client embedding covert messages within MQTT topic names. If the current client is counterfeit, the _HiddenMessage_ to embed within the topic name and the _EmbeddingMethod_ to exploit must also be specified. The two currently supported methods for secret message embedding are **Case**, that encodes the covert message by changing the letter casing of the first letter of the last level of the topic, and **ID**, that appends a numeric identifier based on the covert message bits to the last level of the topic name.
 
### Subscriber-specific Options
These options only apply when _Role_ is set to **Subscriber**.
- _Topic_: The MQTT Topic Filter to which the subscriber will listen for any incoming message.
- _QoS_: The level of Quality of Service (i.e., 0, 1, or 2) for the message received on the given topic.

### DoS_Attack-specific Options
These options only apply when _Role_ is set to **DoS_Attack**.
- _Topic_: The MQTT Topic Name that will be used by the Publisher devices.
- _QoS_: The level of Quality of Service (i.e., 0, 1, or 2) for the messages that will be published on the given topic.
- _Payload_: The message content that the set of Publisher nodes will send to the topic.
- _Type_: The publishig behavior of the nodes, that is set to **Periodic** for this role, as messages will be sent at regular intervals specified by the _Period_ option.
- _NumClients_: The number of Publisher devices to be instantiated to realize the DoS attack simulation.
- _Duration_: The duration of the DoS attack. 

### Example Configuration (CSV)

Below is an example of a CSV configuration file for **Manual Configuration Mode**:

| Topic           | Type     | QoS | Payload   | Period | MinRange | MaxRange | Distribution | DeviceType | HiddenMessage | EmbeddingMethod | NumClients | Duration | Role |      
|------------------|---------|-----|-----------------|--------|----------|----------|--------------|------------|---------------|-----------------|----------|----------|------------|
| home/kitchen/temperature    |  periodic | 1   | {"temp":22.5}  | 10      |          |          |              | legit      |               |                 |         |                | publisher |
| home/garden/motion | event | 0   | {"motion":yes} | 2        | 8        | normal       |  |      |             |                |         |    publisher        |
| home/kitchen/temperature   |   | 1   |                 |         |          |          |              |            |               |                 | subscriber  |
| home/kitchen/humidity    | periodic | 2   | {"humidity":25.5%} | 4      |          |          |              | counterfeit      |   secret            |    case             |        |                | publisher  |
| home/kitchen/humidity    | periodic | 2   | {"humidity":25.5%} | 4      |          |          |              | counterfeit      |   secret            |    case             |        |                | publisher  
| home/garden/light  | periodic | 2   | {"light_status": off} | 0.05      |          |          |              | counterfeit      |              |                 |  500      |       10         | dos_attack  | 



## Dependencies

The following libraries are needed to run the MQTT traffic generator.

- Scapy: ``` pip3 install scapy ```
- Numpy: ``` pip3 install numpy ```
- Pandas: ``` pip3 install pandas ```
- Paho-MQTT: ``` pip3 install paho-mqtt ```

**Note**: Additionally, `tshark` is required for capturing network traffic. Install `tshark` separately:
```
$ sudo apt-get install tshark
```

## Usage

The traffic generator can be used through the graphical user interface or by running it directly from the command line.

### Option 1: Using the UI

The `ui_generator.py` script allows for interactive configuration of the MQTT traffic generation parameters. These configurations are saved to a CSV file, and the generation process can be directly started and stopped through the relative buttons. 

To launch the UI:
```
$ python3 ui_generator.py
```

### Option 2: Running the Traffic Generator via Command Line

The `generator.py` script can alternatively be used directly from the comman line, either using a CSV configuration file or replaying traffic from a PCAP file. 

To generate traffic using a CSV configuration file:
```
$ python3 generator.py [-h HELP] [--csv CSV]
```
where ```--csv CSV```  specifies the path to the CSV file to use for traffic simulation.

To replay traffic based on an empirical distribution using a PCAP traffic capture:
```
$ python3 generator.py [-h HELP] [--pcap PCAP]
```
where ```--pcap PCAP```  specifies the path to the PCAP file to use for traffic replay.







