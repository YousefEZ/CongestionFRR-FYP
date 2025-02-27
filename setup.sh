#!/bin/bash
cp user_src/* scratch/

poetry install 
poetry shell
./ns3 build

if [ $? -ne 0 ]; then
	echo "ns3 build failed"
	exit 1
fi

/bin/bash
