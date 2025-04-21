# CongestionFRR
Congestion Fast Rerouting

place simulations to run in the src/ folder

## ⚙️ Dependencies

- [Docker](https://docs.docker.com/engine/install/)
- [docker-compose](https://docs.docker.com/compose/install/)



## :rocket: to run the simulator on an experiment

Run the following command to spawn a shell 

```bash
docker compose run shell
```

Then run an experiment using the following


```bash
poetry run simulate --config experiments/basic_test.json
```

where the configuration stored in basic_test.json will be executed.

## :test_tube: experiments

to add new experiments you will need to have a defined base setting in a json file, similar to experiments/base_setting.json that outlines the default values for the simulation.

You will then need to define the actual experiment such as the one in experiments/basic_test.json that will override the base settings, and iterate over them as it changes the variables. The conditions field specify what options to run on as well such as with fast rerouting or with congestion. You also need to specify the directory to store the results in.

If you want to override the default settings but not vary it, then use the overwrite_settings field with a JSON object. 


## :bar_chart: Results


After generating the results from the simulations, you will then use the analysis tool to be able to analyze the results. The analysis tool is split into 3 subcomponents:

- Sequence Plotting
- Bytes In Flight
- Metric Analysis


To first setup, you need to make sure you have [poetry](https://python-poetry.org/docs/) installed, which you can do via pip. 

```bash
python3 -m pip install poetry
```

after you have done that you install, and activate the poetry shell 


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


