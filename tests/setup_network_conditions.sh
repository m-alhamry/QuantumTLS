#!/bin/bash
# Simulate 5% packet loss
sudo tc qdisc add dev lo root netem loss 5%
# Add 100ms latency
sudo tc qdisc change dev lo root netem delay 100ms
# Limit bandwidth to 1Mbps
sudo tc qdisc change dev lo root netem rate 1mbit