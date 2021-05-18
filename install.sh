#!/bin/sh
sudo apt-get update
sudo apt-get install -y vim libssl-dev build-essential cmake uuid-dev git python3-pip
mkdir Workspace
cd Workspace
git clone -b sub_master https://github.com/socar-rane/aws-iot-device-sdk-embedded-C.git --recurse-submodules
cd aws-iot-device-sdk-embedded-C
mkdir build
cd build
cmake ..
make
make mqtt_demo_mutual_auth