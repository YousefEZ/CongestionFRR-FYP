#!/bin/bash

one_band_experiment() 
{
  local test_variable=$1 
  local test_value=$2 
  local policy_threshold=$3 
  local dir="traces/$test_variable/$test_value/$policy_threshold"
  local seed="434324" 
  mkdir -p "$dir/frr/$seed/1"
  mkdir -p "$dir/baseline-udp/$seed/1"

  NS_LOG="" ./ns3 run "scratch/combined-frr.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/frr/$seed/1/ --seed=$seed"
  NS_LOG="" ./ns3 run "scratch/combined-baseline-udp.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/baseline-udp/$seed/1/ --seed=$seed"
}


bandwidth_vals=("1Mbps" "1.2Mbps" "1.4Mbps" "1.6Mbps" "1.8Mbps" "2.0Mbps" "2.2Mbps" "2.4Mbps" "2.6Mbps" "2.8Mbps" "3.0Mbps" "3.2Mbps" "3.4Mbps" "3.6Mbps" "3.8Mbps" "4.0Mbps" "4.2Mbps" "4.4Mbps" "4.6Mbps" "4.8Mbps" "5.0Mbps")
# bandwidth_vals=("2.4Mbps" "2.6Mbps" "2.8Mbps" "3.0Mbps" "3.2Mbps" "3.4Mbps" "3.6Mbps" "3.8Mbps" "4.0Mbps" "4.2Mbps" "4.4Mbps" "4.6Mbps" "4.8Mbps" "5.0Mbps")
#bandwidth_vals=("3.47Mbps" "3.471Mbps" "3.472Mbps" "3.473Mbps" "3.474Mbps" "3.475Mbps" "3.476Mbps")
for bandwidth_val in "${bandwidth_vals[@]}"; do
  echo "Bandwidth Primary value: $bandwidth_val"
  one_band_experiment "bandwidth_primary" "$bandwidth_val" "50" 
done
