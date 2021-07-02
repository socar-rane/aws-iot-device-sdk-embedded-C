#ifndef DEMO_CONFIG_H
#define DEMO_CONFIG_H

/**
 * @brief Client가 Broker에게 Control Packet을 전송하기 위한 Keep Alive Second 설정
 * 최대 1200Sec로 제한됨. Keep Alive Second 이상 응답이 없을 경우 Broker는 연결을 중단함.
 */
#define MQTT_KEEP_ALIVE         ( 120U )

/**
 * @brief MQTT 명령 전송 시 QoS 레벨 설정
 */
#define MQTT_QOS                ( 1 )

/**
 * @brief mosquitto_loop를 호출하여 Connect / Subscribe 응답을 요청할 횟수
 */
#define MAX_LOOPS               ( 50U )

/**
 * @brief Connect / Subscribe 전송 시 mosquitto_loop 응답을 기다리는 시간
 */
#define MQTT_SHORT_WAIT_TIME    ( 500U )

/**
 * @brief Subscribe 전송 후 응답을 기다리는 시간
 */
#define MQTT_WAIT_TIME          ( 1U * 1000U )

#define EVENT_SHADOW_NAME "rane_shadow"
#define TRIP_SHADOW_NAME "trip_shadow"

/// @brief Shadow Update Publish Topic
#define SHADOW_UPDATE_TOPIC "$aws/things/%s/shadow/name/%s/update"
/// @brief Shadow Update Delta Topic
#define SHADOW_UPDATE_DELTA_TOPIC "$aws/things/%s/shadow/name/%s/update/delta"
/// @brief Shadow Update Documents Topic
#define SHADOW_UPDATE_DOCU_TOPIC "$aws/things/%s/shadow/name/%s/update/documents"
/// @brief Shadow Update Accept Subscribe Topic
#define SHADOW_UPDATE_ACCEPT_TOPIC "$aws/things/%s/shadow/name/%s/update/accepted"
/// @brief Shadow Update Reject Subscribe Topic
#define SHADOW_UPDATE_REJECT_TOPIC "$aws/things/%s/shadow/name/%s/update/rejected"

/// @brief Shadow Get Publish Topic
#define SHADOW_GET_TOPIC "$aws/things/%s/shadow/name/%s/get"
/// @brief Shadow Get Accept Subscribe Topic
#define SHADOW_GET_ACCEPT_TOPIC "$aws/things/%s/shadow/name/%s/get/accepted"
/// @brief Shadow Get Reject Subscribe Topic
#define SHADOW_GET_REJECT_TOPIC "$aws/things/%s/shadow/name/%s/get/rejected"

/// @brief Provisioning Accept Topic
#define TEMPLATE_ACCEPT_TOPIC "$aws/provisioning-templates/%s/provision/json/accepted"
/// @brief Provisioning Reject Topic
#define TEMPLATE_REJECT_TOPIC "$aws/provisioning-templates/%s/provision/json/rejected"

/// @brief Create Certificate Accept Topic
#define CERTIFICATE_ACCEPT_TOPIC "$aws/certificates/create/json/accepted"
/// @brief Create Certificate Reject Topic
#define CERTIFICATE_REJECT_TOPIC "$aws/certificates/create/json/rejected"
/// @brief Create Certificate Topic (Publish)
#define PROVISIONING_CERT_CREATE_TOPIC "$aws/certificates/create/json"
/// @brief Fleet Provisioning Topic (Publish)
#define PROVISIONING_TEMPLATE_TOPIC "$aws/provisioning-templates/%s/provision/json"

/// @brief STS Upstream Topic
#define DEVICE_UPSTREAM_TOPIC "$aws/rules/sts/%s/report"
/// @brief STS Downstream Topic
#define DEVICE_DOWNSTREAM_TOPIC "sts/%s/control"

/// @brief Certificate file prefix
#define CERTFILE_PREFIX "%s-certificate.pem.crt"
/// @brief Private Key file prefix
#define KEYFILE_PREFIX "%s-private.pem.key"

#define TEMPLATE_ACC_LENGTH ((uint16_t) (sizeof(TEMPLATE_ACCEPT_TOPIC) - 1))
#define TEMPLATE_RJT_LENGTH ((uint16_t) (sizeof(TEMPLATE_REJECT_TOPIC) - 1))
#define CERTIFICATE_ACC_LENGTH ((uint16_t) (sizeof(CERTIFICATE_ACCEPT_TOPIC) - 1))
#define CERTIFICATE_RJT_LENGTH ((uint16_t) (sizeof(CERTIFICATE_REJECT_TOPIC) - 1))
#define PROVISIONING_CC_LENGTH ((uint16_t) (sizeof(PROVISIONING_CERT_CREATE_TOPIC) - 1))
#define PROVISIONING_TT_LENGTH ((uint16_t) (sizeof(PROVISIONING_TEMPLATE_TOPIC) - 1))

///@brief CAN Frame data index
#define P_IDS 7
#define RPM 3
#define SPEED 6
#define TPS 5
#define APS 6
#define TURN_HOOD 2 // 08
#define HOOD 2 // 02
#define TURN_SIDE 7 // 40
#define TRUNK_SEATBELT 1// 10 04
#define HAZARD 4 // 02
#define HEADLAMP 3 // 80
#define SHIFTER 1
#define COOLANT 1
#define FOOTBRAKE 4 // 02 ON / 01 OFF

#define RANE_CAN_TEST 0
#define DEBUG 0

#endif /* ifndef DEMO_CONFIG_H */
