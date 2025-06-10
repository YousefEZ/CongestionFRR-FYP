# CongestionFRR


This is the implementation and tools to evaluate fast rerouting as a congestion control approach at the data plane level. It assesses effectiveness of fast rerouting by proactively mitigating congestion by dynamically directing network traffic through alternative paths. It uses the ns-3 simulator, and can test various scenarios such as different bandwidths, delays, and congestion levels to assess the performance impacts. Documentation, analysis tools, and simulation scripts are provided


## ⚙️ Dependencies

- [Docker](https://docs.docker.com/engine/install/)
- [docker-compose](https://docs.docker.com/compose/install/)
- [Python3](https://www.python.org/)
- [Poetry](https://python-poetry.org/docs/)


## :rocket: to run the simulator on an experiment

Run the following command to spawn a shell 

```bash
docker compose run shell
```

Then run an experiment using the following within the docker container


```bash
poetry run simulate --config experiments/basic_test.json
```

where the configuration stored in basic_test.json will be executed.

## :test_tube: experiments

to add new experiments you will need to have a defined base setting in a json file, similar to experiments/base_setting.json that outlines the default values for the simulation.

You will then need to define the actual experiment such as the one in experiments/basic_test.json that will override the base settings, and iterate over them as it changes the variables. The conditions field specify what options to run on as well such as with fast rerouting or with congestion. You also need to specify the directory to store the results in.

If you want to override the default settings but not vary it, then use the overwrite_settings field with a JSON object. 

Results will be stored in the directory you specified and in the form of $directory/$option/$seed/$variable


where:

- option: is the set of conditions involved like frr_congested
- seed: is the seed_run combination
- variable: is the value the variable is set on for example 3Mbps



## :bar_chart: Results


After generating the results from the simulations, you will then use the analysis tool to be able to analyze the results. The analysis tool is split into 3 subcomponents:

- Sequence Plotting
- Bytes In Flight
- Metric Analysis


To first setup, you need to make sure you have [poetry](https://python-poetry.org/docs/) installed in the **local environment**, which you can do via pip. 

```bash
python3 -m pip install poetry
```

after you have done that you install, and activate the poetry shell (in **local env**)


```bash
python3 -m poetry install && python3 -m poetry shell
```


### :mag_right: Sequence Plotting

The sequence plotting tool used generates a stevensons sequence plot of the results. This is useful for visualizing the results of the simulation and understanding the performance of the system. It also includes specific labelling of packets such as whether its an out of order packet or a spurious retransmission. You can specify 

```bash
python3 analysis sequence -d <path_to_dir> --option <option> --value <value> --seed <seed> --sender <traffic_sender_number> --sender-seq --sender-ack --receiver-ack
```

- option should be like `frr` or `no_frr_congested`
- value should be the variable that you are fixing against
- seed should be the seed + run, so if the seed is 743281 and the run is 15 then it would be 74328115
- sender which is used if you have multiple flows otherwise defaults to 0 (the first sender)
- the other flags --sender-seq, --sender-ack, --receiver-ack is to control which sequence plots to display and the labelling for the packets


### :airplane: Bytes in Flight

This tool allows for visualizing the numbre of bytes in Flight as well as the congestion window size, and the "true" bytes in flight, which is basically accounting for dropped packets by checking if it was ever received by the receiver or not. 
The usage of this subtool is similar to that of the sequence plotting 


### :bar_chart: Metric Analysis 

This is the main tool that is used to analyze how effective the FRR scheme is when varying it under different variables, there are a lot of metrics available to be extracted. Use the following command to navigate through it 

```bash
python3 analysis graph -d <path_to_dir> <metric> <graph_type> 
```


where metric is something like time, and the graph_type can be plot. To see all the different options that are available, you can use the following command 


```bash 
python3 analysis graph --help 
```

and this will tell you all the available metrics that you can use. To see what type of graphs you can make you can use the following


```bash
python3 analysis graph -d traces/delay time --help 
```

if you want to compare metrics against one another you can use `against`, which allows you to form a scatter graph 

```bash 
python3 analysis graph -d traces/delay --output outputs/time_vs_spurious time against spurious_retransmissions scatter
```


## ⚙️ Settings

Here we will discuss all the potential settings that you can change for the experiments. First of all there is a **base settings** which are the set of default settings that a collection of experiments will depend and overwrite upon, the default one is in [**experiments/base_setting.json**](https://github.com/YousefEZ/CongestionFRR-FYP/blob/master/experiments/base_setting.json). You can expand the available set by adding more command parameters in [**src/simulation**](https://github.com/YousefEZ/CongestionFRR-FYP/blob/master/src/simulation.cc), and then expand the [**Settings**](https://github.com/YousefEZ/CongestionFRR-FYP/blob/master/analysis/generator.py#L15) BaseModel to include them, **which also contains the list of settings that can be set and overwritten**. For the **available fast rerouting options** refer [here](https://github.com/YousefEZ/CongestionFRR-FYP/blob/master/src/simulation.cc#L117) (for now is 3 "RerouteHead", "ReroutePerFlow", "SafeRerouteHead"). All the other settings patch into ns3 such as the Congestion Control Algorithm can be seen [here](https://www.nsnam.org/docs/models/html/tcp.html#congestion-control-algorithmshttps://www.nsnam.org/docs/models/html/tcp.html#congestion-control-algorithms)

Once you have defined the default settings in a json file, you can begin to refer to them in the **experiments** file, which will contain the following fields

- **overwrite_settings**: contains one field called *base_settings* which should contain the path to the default settings, and then any fields that you want to overwrite
- **variables**: this is a list of things that you want to test on, and each element in the list is an object containing two fields, the name e.g. bandwidth_primary, and the values such as \["3.0Mbps", "4.0Mbps"\]
- **conditions**: is an object containing the conditions you want to execute the experiments upon, you can define multiple, and each one will contain
  - **fast_rerouting**: bool on whether to enable fast_rerouting
  - **congestion**: bool on whether to enable udp traffic
  - **enable_router_pcap**: bool on whether to create pcap for each router in the topology
  - **enable_udp_pcap**: bool on whether to create pcap for udp source
  - **enable_logging**: bool on whether to log (required for some metric analysis)
- **directory**: is the path where you want to store the results, this should be **within the traces/ directory** so that it can appear outside of the docker container
- **seed**: is the seed in which the simulation should be run
- **number_of_runs**: is the number of runs for the simulation (if randomness is included, if no randomness needed then set to 1)

An example of this can be seen in [experiments/basic_test.json](https://github.com/YousefEZ/CongestionFRR-FYP/blob/master/experiments/basic_test.json)


## 📝 Examples

### ⏲️ Time Plot

```bash
python3 analysis graph -d traces/bandwidth_alternate --output outputs/alternate.png time plot
```

![alternate_bandwidth](https://github.com/user-attachments/assets/46e5de0c-79a0-4538-a455-d1448f3ba077)

### 🃏 CDF

```bash
python3 analysis graph --directory traces/basic/bandwidth_primary --option frr --output output/bandwidth_cdf_congested.png time cdf --variable "3Mbps"
```

![CDF_Baseline_UDP](https://github.com/user-attachments/assets/713335f4-4add-4239-aa78-bf163181cdd7)


### ⚡Scatter Plot

```bash
python3 analysis correlation --directory traces/bandwidth_alternate --option frr --output cor.png rto_wait_time against spurious_retransmissions_reordered scatter
```

![cor_spurious_against_rto_times](https://github.com/user-attachments/assets/3ec2a6d4-7a6a-4cc2-85ee-3396ee1bdcc5)



### 🔗 Sequence Plotting


This will load the sequence plot and can be viewed via localhost (link will appear)

```bash
python3 analysis sequence -d traces/basic/bandwidth_primary --option no_frr_congested --value "3Mbps" --seed 74328132 --sender 0 --sender-seq --sender-ack --receiver-ack
```









