# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install required system packages, including tshark
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Set permissions for tshark to run without root (optional)
RUN groupadd wireshark && usermod -a -G wireshark root \
    && chmod +x /usr/bin/dumpcap

COPY generator.py /app/generator.py

RUN pip install --no-cache-dir pandas numpy paho-mqtt scapy

# Expose MQTT port
# EXPOSE 1883

