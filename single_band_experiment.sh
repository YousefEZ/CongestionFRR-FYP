#!/bin/bash

one_band_experiment() 
{
  local test_variable=$1 
  local test_value=$2 
  local policy_threshold=$3 
  local dir="traces/$test_variable/" 
  local seed="743821"
  
  for run in {1..20}; do
    local frr="$dir/frr/$seed$run/$test_value/"
    local frr_no_udp="$dir/frr-no-udp/$seed$run/$test_value/"
    local baseline_udp="$dir/baseline-udp/$seed$run/$test_value/"
    local baseline_no_udp="$dir/baseline-no-udp/$seed$run/$test_value/"
    mkdir -p $frr 
    mkdir -p $frr_no_udp
    mkdir -p $baseline_no_udp
    mkdir -p $baseline_udp
     
    # FRRQueue=info|prefix_time
    NS_LOG="" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$frr --seed=$seed --run=$run --enable-rerouting --enable-udp" # 2> $frr/debug.log 
    # NS_LOG="FRRQueue=info|prefix_time" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$frr_no_udp --seed=$seed --run=$run --enable-rerouting" 2> $frr_no_udp/debug.log
    NS_LOG="" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$baseline_udp --seed=$seed --run=$run --enable-udp" 
    # NS_LOG="" ./ns3 run "scratch/simulation.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$baseline_no_udp --seed=$seed --run=$run"
    wait 
  done 
  #NS_LOG="FRRQueue=info|prefix_time" ./ns3 run "scratch/combined-frr.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/frr/$seed/1/ --seed=$seed" 2> $dir/frr/$seed/1/debug.log
  #NS_LOG="" ./ns3 run "scratch/combined-baseline-udp.cc --$test_variable=$test_value --tcp_senders=1 --policy_threshold=$policy_threshold --dir=$dir/baseline-udp/$seed/1/ --seed=$seed"
  #NS_LOG="" ./ns3 run "scratch/combined-baseline-no-udp.cc --$test_variable=$test_value --tcp_senders=1 --dir=$dir/baseline-no-udp/$seed/1/ --seed=$seed"
}


#bandwidth_vals=("2.0Mbps")
# from 3.0 KBps to 7.0 KBps in increments of 0.25 KBps 
#

bandwidth_vals=("3.0KBps" "3.25KBps" "3.5KBps" "3.75KBps" "4.0KBps" "4.25KBps" "4.5KBps" "4.75KBps" "5.0KBps" "5.25KBps" "5.5KBps" "5.75KBps" "6.0KBps" "6.25KBps" "6.5KBps" "6.75KBps" "7.0KBps" "7.25KBps" "7.5KBps" "7.75KBps" "8.0KBps" "8.25KBps" "8.5KBps" "8.75KBps" "9.0KBps" "9.25KBps" "9.5KBps" "9.75KBps" "10.0KBps")

for bandwidth_val in "${bandwidth_vals[@]}"; do
  echo "Bandwidth Primary value: $bandwidth_val"
  one_band_experiment "bandwidth_primary" "$bandwidth_val" "50" 
done
