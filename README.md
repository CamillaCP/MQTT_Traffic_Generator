# MQTT-traffic-generator 

This project is an MQTT (Message Queuing Telemetry Transport) traffic generator with two main modes of operation, namely **Manual Configuration** and **Empirical Distribution Mode**, that also supports the establishment of network covert channels exploiting MQTT topic names. 

## Modes of Operation

1. **Manual Configuration Mode**, that enables the user to manually configure the necessary MQTT traffic parameters for the generation process. The user can specify a variety of configuration options, including client roles, topic names, message payload, Quality of Service (QoS) levels, and timing behaviors. The configuration options are saved to a CSV file, that is then used by the generator to simulate MQTT traffic according to these specifications.

2. **Empirical Distribution Mode**, that enables the user to specify an existing PCAP file to be used for MQTT traffic replay. The replay covers all recorded MQTT interactions, including message timing, providing a highly accurate simulation of realistic, previously captured data.

## Features

- _UI for Custom Configuration_: Define and save MQTT traffic configurations through a graphical interface, with access to both modes of operation. This allows users to configure MQTT traffic parameters directly, as well as specifying the existing PCAP file for traffic replay.
- _Simulation of Counterfeit Nodes for Covert Channels_: Embed hidden messages within MQTT topic names using two distinct covert channel techniques, namely the modulation of the letter casing or the insertion of a counterfeit ID.
- _Support for Both Event-Driven and Periodic Publishing_: Set publishing intervals for event-driven or periodic messages, with customizable delay distributions (i.e., uniform, exponential, and normal).
- _Traffic Capture_: Automatically captures all generated traffic using `tshark` and saves it to a PCAP file.
