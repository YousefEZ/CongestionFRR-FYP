# Use Ubuntu as the base image FROM ubuntu:latest
FROM ubuntu:latest

# Set the working directory in the container
WORKDIR /usr/workspace

# Install curl and other necessary utilities
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get install -y tar && \
    apt-get install -y python3 python3-pip && \
    apt-get clean

# sys dependencies
RUN apt-get install -y g++ python3 cmake ninja-build git
RUN apt-get install -y python3-scapy python3-hypothesis python3-pytest


# recommendations
RUN apt-get install -y ccache gdb valgrind

# python dependencies
RUN apt install -y python3-dev pkg-config python3-setuptools python3-poetry
# RUN python3 -m pip install cppyy==2.4.2

# Download the tar file
ADD https://www.nsnam.org/release/ns-allinone-3.43.tar.bz2 /usr/workspace

# Unpack the tar file
RUN tar xfj /usr/workspace/ns-allinone-3.43.tar.bz2

# Building the application
COPY libs/tcp-tx-buffer.cc /usr/workspace/ns-allinone-3.43/ns-3.43/src/internet/model/tcp-tx-buffer.cc
WORKDIR /usr/workspace/ns-allinone-3.43
RUN ./build.py


WORKDIR /usr/workspace/ns-allinone-3.43/ns-3.43
RUN ./ns3 configure --build-profile=debug --out=build/debug

RUN ./ns3 build 

# Copy the script into the container
COPY setup.sh /usr/workspace/ns-allinone-3.43/ns-3.43/setup.sh

COPY pyproject.toml /usr/workspace/ns-allinone-3.43/ns-3.43/pyproject.toml

RUN poetry install --directory=/usr/workspace/ns-allinone-3.43/ns-3.43/ --no-root 

RUN chmod u+x /usr/workspace/ns-allinone-3.43/ns-3.43/setup.sh

ENTRYPOINT ["/usr/workspace/ns-allinone-3.43/ns-3.43/setup.sh"]
