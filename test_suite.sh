#!/bin/bash 
#pip install -r requirements.txt

mkdir -p traces/test_no_congestion_no_rerouting
#NS_LOG="" ./ns3 run "scratch/combined-frr.cc --tcp_senders=1 --policy_threshold=50 --dir=traces/test_no_congestion_no_rerouting/ --seed=1 --bandwidth_primary=5KBps --bandwidth_access=2KBps --bandwidth_udp_access=2KBps"
pytest . 
