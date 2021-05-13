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

# 프로비저닝 템플릿 이름 변경
vi demos/jobs/jobs_demo_mosquitto/demo_config.h
#define PRODUCTION_TEMPLATE "INSERT YOUR TEMPLATE NAME"
#<INSERT YOUR TEMPLATE NAME>을 프로비저닝 템플릿 이름으로 변경해주세요!

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

# 실행 방법은 아래를 참고하세요
```

## jobs_demo_mosquitto 실행방법

```sh
./jobs_demo_mosquitto 

옵션 설명

-c / --cert     : Certificate ID
-d / --path     : 인증서가 저장된 Path (Ex: ./certificates)
-f / --fleet    : Fleet Provisioning Template Name
-h / --host     : Endpoint Address
-l / --loop     : Publish 메시지를 전송할 횟수 (0 : Forever / not 0 : Loop count)
-m / --mode     : <1 : Publish / 2 : Subscribe / 3 : Fleet Provisioning>
-M / --message  : Publish Payload 메시지 문자열
-N / --mdn      : MDN 번호
-t / --topic    : Publish / Subscribe 할 Topic 문자열

1. Publish 방법

./jobs_demo_mosquitto -c <Certificate ID> -d <인증서 경로> -h <Endpoint Address> -m 1 -M "{\"test\":\"publish\"}" -N <mdn number> -t <Publish Topic> -l <loop count>

2. Subscribe 방법

./jobs_demo_mosquitto -c <Certificate ID> -d <인증서 경로> -h <Endpoint Address> -m 2 -N <mdn number> -t <Subscribe Topic> 

3. Fleet Provisioning 방법

./jobs_demo_mosquitto -c <Certificate ID> -d <인증서 경로> -h <Endpoint Address> -m 3-f <Provisioning Template Name> -N <MDN Number>

4. UpDownstream 방법

./jobs_demo_mosquitto -c <Certificate ID> -d <인증서 경로> -h <Endpoint Address> -m 4 -N <MDN Number>
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
