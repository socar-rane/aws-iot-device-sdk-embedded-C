/*
 * AWS IoT Device SDK for Embedded C 202103.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef DEMO_CONFIG_H
#define DEMO_CONFIG_H

/**
 * @brief The client must send a control packet at least
 * this often in seconds, or the broker will close the connection.
 */
#define MQTT_KEEP_ALIVE         ( 120U )

/**
 * @brief Require acknowledgements of MQTT publish operations.
 */
#define MQTT_QOS                ( 1 )

/**
 * @brief Give up after this many calls to mqtt_loop without progress,
 * used only for connect and subscribe.
 */
#define MAX_LOOPS               ( 50U )

/**
 * @brief Maximum duration in milliseconds of one mqtt_loop,
 * used only for connect and subscribe.
 */
#define MQTT_SHORT_WAIT_TIME    ( 500U )

/**
 * @brief Maximum duration in milliseconds of one mqtt_loop,
 * used after subscribe.
 */
#define MQTT_WAIT_TIME          ( 1U * 1000U )

/**
 * @brief Maximum interval in seconds for pollinv and updateinv command line arguments.
 * (arbitrarily chosen to be a week; must be less than LONG_MAX)
 */
#define INTERVAL_MAX            ( 60U * 60U * 24U * 7U )

/**
 * @brief Parent directory to contain download directories and files.
 */
#define DESTINATION_PREFIX      "/tmp"

/**
 * @brief How to invoke the download program, i.e., curl.
 *
 * As written, this curl command limits the download rate
 * to 10 KB per second.  The slow rate provides an opportunity
 * to observe updates, and test job cancellation.
 */
#define CURL( url ) \
    execl( "/usr/bin/curl", "curl", "-OLsSN", "--limit-rate", "10k", url, NULL )

#define CERTFILE_PATH   "certificates"
//#define PRE_TEMPLATE_PATH "$aws/provisioning-templates/" PRODUCTION_TEMPLATE
#define TEMPLATE_ACCEPT_TOPIC "$aws/provisioning-templates/%s/provision/json/accepted"
#define TEMPLATE_REJECT_TOPIC "$aws/provisioning-templates/%s/provision/json/rejected"
#define CERTIFICATE_ACCEPT_TOPIC "$aws/certificates/create/json/accepted"
#define CERTIFICATE_REJECT_TOPIC "$aws/certificates/create/json/rejected"
//#define PRODUCTION_TEMPLATE "INSERT YOUR PROVISIONING TEMPLATE NAME"

#define PROVISIONING_CERT_CREATE_TOPIC "$aws/certificates/create/json"
#define PROVISIONING_TEMPLATE_TOPIC "$aws/provisioning-templates/%s/provision/json"

#define DEVICE_UPSTREAM_TOPIC "$aws/rules/sts/%s/report"
#define DEVICE_DOWNSTREAM_TOPIC "sts/%s/control"

#define CERTFILE_PREFIX "%s-certificate.pem.crt"
#define KEYFILE_PREFIX "%s-private.pem.key"

#define TEMPLATE_ACC_LENGTH ((uint16_t) (sizeof(TEMPLATE_ACCEPT_TOPIC) - 1))
#define TEMPLATE_RJT_LENGTH ((uint16_t) (sizeof(TEMPLATE_REJECT_TOPIC) - 1))
#define CERTIFICATE_ACC_LENGTH ((uint16_t) (sizeof(CERTIFICATE_ACCEPT_TOPIC) - 1))
#define CERTIFICATE_RJT_LENGTH ((uint16_t) (sizeof(CERTIFICATE_REJECT_TOPIC) - 1))
#define PROVISIONING_CC_LENGTH ((uint16_t) (sizeof(PROVISIONING_CERT_CREATE_TOPIC) - 1))
#define PROVISIONING_TT_LENGTH ((uint16_t) (sizeof(PROVISIONING_TEMPLATE_TOPIC) - 1))

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

#endif /* ifndef DEMO_CONFIG_H */
