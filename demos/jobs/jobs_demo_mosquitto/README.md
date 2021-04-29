# AWS IoT Fleet Provisioning Source code using Mosquitto library

## Overview

기존의 AWS IoT Device SDK는 cmake 기반으로 만들어져있어 크로스 컴파일링이 번거롭습니다.
따라서 크로스 컴파일도 쉬우면서 Mosquitto 라이브러리를 사용하는 Fleet Provisioning 코드를 만들었습니다.
라이브러리는 간단하게 libmosquitto와 coreJSON 라이브러리를 사용하여 구현했습니다. 

## Mosquitto 라이브러리 설치하기

```sh
sudo apt-get install -y curl libmosquitto-dev
```

## Fleet Provisioning 코드 다운로드 및 실행 방법
```sh
# Workspace 디렉토리 생성 후 진입
mkdir ~/Workspace

cd ~/Workspace

# 소스코드 git clone 
git clone -b sub_master https://github.com/socar-rane/aws-iot-device-sdk-embedded-C.git --recurse-submodules

# 프로젝트 경로 진입
cd aws-iot-device-sdk-embedded-C/

# Cmake Build 디렉토리 생성
mkdir build

# Makefile 생성
cd build && cmake ..

# 전체 프로젝트 빌드
make

# jobs_demo_mosquitto만 빌드하는 방법
make jobs_demo_mosquitto

cd bin

# Claim 인증서를 certificates 디렉토리에 복사
cp <Claim 인증서 경로> ~/Workspace/aws-iot-device-sdk-embedded-C/build/bin/certificates/

# Fleet Provisioning 실행
./jobs_demo_mosquitto -n <Client ID> -h <Endpoint Address> --cafile <AmazonRootCA1.crt 파일 경로> --certfile <Certificate 파일 경로> --keyfile <Private 인증서 파일 경로> -m 3
```

## Fleet Provisioning 실행방법

```sh
./jobs_demo_mosquitto -n <Client ID> -h <Endpoint Address> --cafile <AmazonRootCA1.crt 파일 경로> --certfile <Certificate 파일 경로> --keyfile <Private 인증서 파일 경로> -m 3

옵션 설명

-n / --name     : 클라이언트 ID 
-h / --host     : Endpoint Address
-p / --port     : MQTT Port
-f / --cafile   : AmazonRootCA1.crt 파일 경로 (파일명 포함)
-k / --keyfile  : Private Key 파일 경로 (파일명 포함)
-t / --topic    : Publish / Subscribe 할 Topic 문자열
-M / --message  : Publish Payload 메시지 문자열
-m / --mode     : <1 : Publish / 2 : Subscribe / 3 : Fleet Provisioning>
-l / --loop     : Publish 메시지를 전송할 횟수 (0 : Forever / not 0 : Loop count)
```


## Publish / Subscribe 전송방법

```sh
# Publish Forever
./jobs_demo_mosquitto -n <Client ID> -h <Endpoint Address> --cafile <AmazonRootCA1.crt 파일 경로> --certfile <Certificate 파일 경로> --keyfile <Private 인증서 파일 경로> -m 1 -M <Publish Payload Message> -t <Publish Topic> -l 0

# Publish 5 Times
./jobs_demo_mosquitto -n <Client ID> -h <Endpoint Address> --cafile <AmazonRootCA1.crt 파일 경로> --certfile <Certificate 파일 경로> --keyfile <Private 인증서 파일 경로> -m 1 -M <Publish Payload Message> -t <Publish Topic> -l 5

# Subscribe and wait message

# Publish 5 Times
./jobs_demo_mosquitto -n <Client ID> -h <Endpoint Address> --cafile <AmazonRootCA1.crt 파일 경로> --certfile <Certificate 파일 경로> --keyfile <Private 인증서 파일 경로> -m 2 -M -t <Subscribe Topic>
```






# ------- 아래 문서는 잠시 보류합니다!!! ----------

```sh
# Workspace 디렉토리 생성 후 진입
mkdir ~/Workspace

cd ~/Workspace

# 소스코드 git clone 
git clone -b sub_master https://github.com/socar-rane/aws-iot-device-sdk-embedded-C.git --recurse-submodules

# coreJSON 라이브러리 경로 진입
cd aws-iot-device-sdk-embedded-C/libraries/standard/coreJSON

# gcc를 사용하여 컴파일
gcc -I source/include -c source/core_json.c

# libcore_json.so 정적 라이브러리 생성
ar rc libcore_json.so core_json.o
```

## Fleet Provisioning 소스코드 컴파일하기

```sh
# aws 디렉토리 진입
cd ~/Workspace/aws-iot-device-sdk-embedded-C/

# provisioning 디렉토리 진입 
cd demos/jobs/jobs_demo_mosquitto

# core_json 헤더파일 복사
cp ../../../libraries/standard/coreJSON/source/include/core_json.h .

# /usr/lib/arm-linux-gnueabihf는 라즈베리파이 환경 기준 mosquitto 라이브러리 경로입니다.
# 다른 환경에서 사용할 경우 mosquitto 라이브러리 경로를 입력하시면 됩니다.
gcc jobs_demo_mosquitto.c -L ~/Workspace/aws-iot-device-sdk-embedded-C/libraries/standard/coreJSON -lcore_json -L/usr/lib/arm-linux-gnueabihf/ -lmosquitto -o provisioning

./provisioning <options>
```























































































































































```
This demonstration downloads files from URLs received via AWS IoT Jobs.
Details are available in the usage function at the top of jobs_demo.c.

This demo is intended for Linux platforms with the GCC toolchain,
curl, and libmosquitto installed.  To build this demo, run make.

To install curl and libmosquitto on a Debian or Ubuntu host, run:

    apt install curl libmosquitto-dev

libmosquitto 1.4.10 or any later version of the first major release is required to run this demo.
For ALPN support, build the latest version of the first major release of libmosquitto (1.6.12).
To do this, go to the libmosquitto directory,
and follow the instructions in compiling.txt within the submodule.
