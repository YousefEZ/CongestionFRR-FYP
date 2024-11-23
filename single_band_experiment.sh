#!/bin/bash

one_band_experiment() 
{
  local test_variable=$1 
  local test_value=$2 
  local policy_threshold=$3 
  local dir="traces/$test_variable/$test_value/$policy_threshold"
  local seed="234729"
  local run="1"
  mkdir -p "$dir/frr/$seed$run/1"
  mkdir -p "$dir/frr-no-udp/$seed$run/1"
  mkdir -p "$dir/baseline-udp/$seed$run/1"
  mkdir -p "$dir/baseline-no-udp/$seed$run/1"

  NS_LOG="FRRQueue=info|prefix_time" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/frr/$seed$run/1/ --seed=$seed --run=$run --enable-rerouting --enable-udp" 2> $dir/frr/$seed$run/1/debug.log
  NS_LOG="FRRQueue=info|prefix_time" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/frr-no-udp/$seed$run/1/ --seed=$seed --run=$run --enable-rerouting" 2> $dir/frr/$seed$run/1/debug.log
  NS_LOG="" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/baseline-udp/$seed$run/1/ --seed=$seed --run=$run --enable-udp" 
  NS_LOG="" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/baseline-no-udp/$seed$run/1/ --seed=$seed --run=$run"
  #NS_LOG="FRRQueue=info|prefix_time" ./ns3 run "scratch/combined-frr.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/frr/$seed/1/ --seed=$seed" 2> $dir/frr/$seed/1/debug.log
  #NS_LOG="" ./ns3 run "scratch/combined-baseline-udp.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/baseline-udp/$seed/1/ --seed=$seed"
  #NS_LOG="" ./ns3 run "scratch/combined-baseline-no-udp.cc --$test_variable=$test_value --tcp_senders=1 --dir=$dir/baseline-no-udp/$seed/1/ --seed=$seed"
}


#bandwidth_vals=("2.0Mbps")
# from 3.0 KBps to 7.0 KBps in increments of 0.25 KBps 
#

bandwidth_vals=("3.0KBps" "3.25KBps" "3.5KBps" "3.75KBps" "4.0KBps" "4.25KBps" "4.5KBps" "4.75KBps" "5.0KBps" "5.25KBps" "5.5KBps" "5.75KBps" "6.0KBps" "6.25KBps" "6.5KBps" "6.75KBps" "7.0KBps")

for bandwidth_val in "${bandwidth_vals[@]}"; do
  echo "Bandwidth Primary value: $bandwidth_val"
  one_band_experiment "bandwidth_primary" "$bandwidth_val" "50" 
done
