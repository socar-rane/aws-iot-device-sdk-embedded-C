
# AWS IoT Device SDK for Embedded C (feat. MS팀 라네)

## Overview

AWS IoT Device SDK for Embedded C는 C언어 기반의 AWS IoT Core와 통신할 수 있는 소스코드입니다. MQTT client, HTTP client, JSON Parser, AWS IoT Device Shadow, AWS IoT Jobs, AWS IoT Device Defender 라이브러리가 함께 포함되어 있습니다. 브랜치는 main, sub_master, v4_deprecated로 나뉘지만 현재 프로비저닝 코드가 포함된 브랜치는 sub_master 브랜치입니다. [AWS IoT Core](https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html) 개발 가이드를 참고하여 개발했으며 추가적으로 참고할 사항이 있을 경우 이 링크를 참고하시면 됩니다.

### License

The C-SDK libraries are licensed under the [MIT open source license](LICENSE).

### Features

C-SDK는 다양한 AWS IoT 서비스에 쉽게 접근할 수 있습니다. C-SDK는 [AWS IoT Core](https://docs.aws.amazon.com/iot/latest/developerguide/what-is-aws-iot.html)와 함께 테스트를 진행했습니다. 사물, 정책, 인증서, 플릿 프로비저닝 템플릿 등 MQTT에 관련된 사항들이 있으니 문서를 참고하여 사전 설정을 마쳐야합니다. 이러한 작업들을 수행하기 위하여 아래 라이브러리가 포함되어 있습니다. 

#### coreMQTT

[coreMQTT](https://github.com/FreeRTOS/coreMQTT) 라이브러리는 브로커와 MQTT connection을 제공하고 TLS 세션 또는 암호화되지 않은 채널의 연결을 허용합니다. 이 MQTT connection은 MQTT Topic을 Publish하거나 Subscribe할 수 있습니다. mqtt_demo_mutual_auth는 coreMQTT를 기반으로 작성된 코드이므로 coreMQTT 라이브러리를 필수적으로 사용합니다. 

#### coreJSON

MQTT 통신을 할 때 기본적으로 Payload는 JSON 형태로 송/수신하게 됩니다. C 기반 JSON 라이브러리인 coreJSON 라이브러리를 사용하여 JSON Payload를 다룹니다. FreeRTOS에 포함된 coreJSON 라이브러리는 JSON Payload의 Validation 체크가 가능하며, Key를 기반으로 Value를 추출할 수 있습니다. 본 데모에서는 Certificate Key와 Private Key를 추출할 때 사용하였습니다.

## Branches

### sub_master branch

[sub_master](https://github.com/socar-rane/aws-iot-device-sdk-embedded-C/tree/sub_master) 브랜치는 Fleet Provisioning 코드가 포함된 버전의 라이브러리입니다. 본 코드는 Python Fleet Provisioning 코드를 리빌드하였습니다. 사용법은 '라네와 함께하는 AWS 프로비저닝 코드 만들기'를 참조해주세요.

## Getting Started

### Cloning

#### demo_config.h 수정 방법

install.sh 스크립트 실행 전 demos/mqtt/mqtt_demo_mutual_auth/demo_config.h를 수정하셔야 합니다.
demo_config.h에는 AWS IoT Core를 사용하기 위한 기본 설정 정보가 포함되어 있습니다.
수정 항목에 대한 내용은 아래와 같습니다.

```c
// AWS IoT Endpoint 주소를 입력하세요.
// 사물 - 상호작용 탭에서 Endpoint 주소를 확인할 수 있습니다.
#define AWS_IOT_ENDPOINT        "INSERT YOUR ENDPOINT ADDRESS"

// 인증서 파일을 저장한 경로를 지정하세요. 기본은 ./certificates입니다.
#define CERTFILE_PATH           "certificates"

// Provisioining Template 이름을 설정하세요.
// Fleet Provisioning Template 생성 시 사용한 Provisioning 이름을 작성하면 됩니다.
#define PRODUCTION_TEMPLATE     "INSERT YOUR PROVISIONING TEMPLATE NAME"
```

#### 리눅스 환경 구축방법

install.sh 스크립트는 Git Repository 최상위 디렉토리에 포함되어 있습니다.
install.sh 스크립트를 복사하여 아무 디렉토리에 붙여넣기 하고, chmod 755 install.sh로 권한을 변경한 뒤 스크립트를 실행하면 됩니다.
스크립트에 포함된 내용은 아래와 같습니다.

```sh
#!/bin/sh
# 패키지 업데이트
sudo apt-get update

# 필수 패키지 설치
sudo apt-get install -y vim libssl-dev build-essential cmake uuid-dev git python3-pip 

# Workspace 디렉토리 생성
mkdir Workspace

# Workspace 디렉토리 생성 후 소스코드 다운로드
cd Workspace

# git clone 명령어 실행 시 꼭 branch를 sub_master로 설정해주시고, --recurse-submodules 옵션을 사용하세요.
git clone -b sub_master https://github.com/socar-rane/aws-iot-device-sdk-embedded-C.git --recurse-submodules

# 소스코드 디렉토리 진입 후 cmake 빌드 디렉토리 생성
cd aws-iot-device-sdk-embedded-C
mkdir build
cd build

# cmake 실행
cmake ..

# make 실행
make

# Fleet Provisioning 예제 빌드
make mqtt_demo_mutual_auth
```

스크립트 실행이 완료되면 aws-iot-device-sdk-embedded-c/build/bin/ 디렉토리에 실행파일이 생성됩니다.
build/bin/certificates/ 디렉토리에 클레임 인증서를 붙여넣기 하세요. 

### Building and Running Demos

#### Build a single demo

* C SDK 루트 디렉토리로 이동합니다.
* cmake를 실행하여 Makefile을 생성합니다. : `cmake -S. -Bbuild && cd build`
* 데모 이름을 선택하기 위해 `make help | grep demo`를 실행합니다.

```
defender_demo
http_demo_basic_tls
http_demo_mutual_auth
http_demo_plaintext
http_demo_s3_download
http_demo_s3_download_multithreaded
http_demo_s3_upload
jobs_demo_mosquitto
mqtt_demo_basic_tls
mqtt_demo_mutual_auth
mqtt_demo_plaintext
mqtt_demo_serializer
mqtt_demo_subscription_manager
ota_demo_core_http
ota_demo_core_mqtt
pkcs11_demo_management_and_rng
pkcs11_demo_mechanisms_and_digests
pkcs11_demo_objects
pkcs11_demo_sign_and_verify
shadow_demo_main
```
* 빌드 가능한 패키지를 확인하였으면 `demo_name`을 패키지 이름으로 변경하여 `make demo_name`을 실행합니다.
* 빌드가 완료되면 `build/bin` 디렉토리에 실행파일이 생성됩니다.