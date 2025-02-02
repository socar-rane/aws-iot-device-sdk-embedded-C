/*
   ^_ * AWS IoT Device SDK for Embedded C 202103.00
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

/*
 * Demo for showing the use of MQTT APIs to establish an MQTT session,
 * subscribe to a topic, publish to a topic, receive incoming publishes,
 * unsubscribe from a topic and disconnect the MQTT session.
 *
 * A mutually authenticated TLS connection is used to connect to the AWS IoT
 * MQTT message broker in this example. Define ROOT_CA_CERT_PATH for server
 * authentication in the client. Client authentication can be achieved in either
 * of the 2 different ways mentioned below.
 * 1. Define CLIENT_CERT_PATH and CLIENT_PRIVATE_KEY_PATH in demo_config.h
 *    for client authentication to be done based on the client certificate
 *    and client private key. More details about this client authentication
 *    can be found in the link below.
 *    https://docs.aws.amazon.com/iot/latest/developerguide/client-authentication.html
 * 2. Define CLIENT_USERNAME and CLIENT_PASSWORD in demo_config.h for client
 *    authentication to be done using a username and password. More details about
 *    this client authentication can be found in the link below.
 *    https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
 *    An authorizer setup needs to be done, as mentioned in the above link, to use
 *    username/password based client authentication.
 *
 * The example is single threaded and uses statically allocated memory;
 * it uses QOS1 and therefore implements a retransmission mechanism
 * for Publish messages. Retransmission of publish messages are attempted
 * when a MQTT connection is established with a session that was already
 * present. All the outgoing publish messages waiting to receive PUBACK
 * are resent in this demo. In order to support retransmission all the outgoing
 * publishes are stored until a PUBACK is received.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
/* POSIX includes. */
#include <unistd.h>
#include <pthread.h>
#include <uuid/uuid.h>
/* Include Demo Config as the first non-system header. */
#include "demo_config.h"

/* MQTT API headers. */
#include "core_mqtt.h"
#include "core_mqtt_state.h"
#include "core_json.h"
/* OpenSSL sockets transport implementation. */
#include "openssl_posix.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* Clock for timer. */
#include "clock.h"

/**
 * These configuration settings are required to run the mutual auth demo.
 * Throw compilation error if the below configs are not defined.
 */
#define UUID_STR "1234567-abcde-fghij-klmno-1234567abc-TLS350"
#define UUID_FILE_PATH "/proc/sys/kernel/random/uuid"

#ifndef AWS_IOT_ENDPOINT
#error "Please define AWS IoT MQTT broker endpoint(AWS_IOT_ENDPOINT) in demo_config.h."
#endif
#ifndef ROOT_CA_CERT_PATH
#error "Please define path to Root CA certificate of the MQTT broker(ROOT_CA_CERT_PATH) in demo_config.h."
#endif
#ifndef CLIENT_IDENTIFIER
#error "Please define a unique client identifier, CLIENT_IDENTIFIER, in demo_config.h."
#endif

/* The AWS IoT message broker requires either a set of client certificate/private key
 * or username/password to authenticate the client. */
#ifndef CLIENT_USERNAME
//#ifndef CLIENT_CERT_PATH
//#error "Please define path to client certificate(CLIENT_CERT_PATH) in demo_config.h."
//#endif
#ifndef EX_CERTID
#error "Please define path to client cert id(EX_CERTID) in demo_config.h."
#endif
#else

/* If a username is defined, a client password also would need to be defined for
 * client authentication. */
#ifndef CLIENT_PASSWORD
#error "Please define client password(CLIENT_PASSWORD) in demo_config.h for client authentication based on username/password."
#endif

/* AWS IoT MQTT broker port needs to be 443 for client authentication based on
 * username/password. */
#if AWS_MQTT_PORT != 443
#error "Broker port, AWS_MQTT_PORT, should be defined as 443 in demo_config.h for client authentication based on username/password."
#endif
#endif /* ifndef CLIENT_USERNAME */

/**
 * Provide default values for undefined configuration settings.
 */
#ifndef AWS_MQTT_PORT
#define AWS_MQTT_PORT    ( 8883 )
#endif

#ifndef NETWORK_BUFFER_SIZE
#define NETWORK_BUFFER_SIZE    ( 4096U )
#endif

#ifndef OS_NAME
#define OS_NAME    "Ubuntu"
#endif

#ifndef OS_VERSION
#define OS_VERSION    "18.04 LTS"
#endif

#ifndef HARDWARE_PLATFORM_NAME
#define HARDWARE_PLATFORM_NAME    "Posix"
#endif

/**
 * @brief Length of MQTT server host name.
 */
#define AWS_IOT_ENDPOINT_LENGTH         ( ( uint16_t ) ( sizeof( AWS_IOT_ENDPOINT ) - 1 ) )

/**
 * @brief Length of client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH        ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) protocol name for AWS IoT MQTT.
 *
 * This will be used if the AWS_MQTT_PORT is configured as 443 for AWS IoT MQTT broker.
 * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
 * in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
#define AWS_IOT_MQTT_ALPN               "\x0ex-amzn-mqtt-ca"

#define TOPIC_LENGTH		9

/**
 * @brief Length of ALPN protocol name.
 */
#define AWS_IOT_MQTT_ALPN_LENGTH        ( ( uint16_t ) ( sizeof( AWS_IOT_MQTT_ALPN ) - 1 ) )

/**
 * @brief This is the ALPN (Application-Layer Protocol Negotiation) string
 * required by AWS IoT for password-based authentication using TCP port 443.
 */
#define AWS_IOT_PASSWORD_ALPN           "\x04mqtt"

/**
 * @brief Length of password ALPN.
 */
#define AWS_IOT_PASSWORD_ALPN_LENGTH    ( ( uint16_t ) ( sizeof( AWS_IOT_PASSWORD_ALPN ) - 1 ) )


/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                  ( 1000U )


/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define MQTT_EXAMPLE_TOPIC                  CLIENT_IDENTIFIER "/Rane/topic"

/**
 * @brief Length of client MQTT topic.
 */
#define MQTT_EXAMPLE_TOPIC_LENGTH           ( ( uint16_t ) ( sizeof( MQTT_EXAMPLE_TOPIC ) - 1 ) )

/**
 * @brief The MQTT message published in this example.
 */
#define MQTT_EXAMPLE_MESSAGE                "Hello World!"

/**
 * @brief The length of the MQTT message published in this example.
 */
#define MQTT_EXAMPLE_MESSAGE_LENGTH         ( ( uint16_t ) ( sizeof( MQTT_EXAMPLE_MESSAGE ) - 1 ) )

/**
 * @brief Maximum number of outgoing publishes maintained in the application
 * until an ack is received from the broker.
 */
#define MAX_OUTGOING_PUBLISHES              ( 5U )

/**
 * @brief Invalid packet identifier for the MQTT packets. Zero is always an
 * invalid packet identifier as per MQTT 3.1.1 spec.
 */
#define MQTT_PACKET_ID_INVALID              ( ( uint16_t ) 0U )

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS        ( 500U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 *  between two Control Packets.
 *
 *  It is the responsibility of the Client to ensure that the interval between
 *  Control Packets being sent does not exceed the this Keep Alive value. In the
 *  absence of sending any other Control Packets, the Client MUST send a
 *  PINGREQ Packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    ( 60U )

/**
 * @brief Delay between MQTT publishes in seconds.
 */
#define DELAY_BETWEEN_PUBLISHES_SECONDS     ( 1U )

/**
 * @brief Number of PUBLISH messages sent per iteration.
 */
#define MQTT_PUBLISH_COUNT_PER_LOOP         ( 5U )

/**
 * @brief Delay in seconds between two iterations of subscribePublishLoop().
 */
#define MQTT_SUBPUB_LOOP_DELAY_SECONDS      ( 5U )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS      ( 500 )

/**
 * @brief The MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING                      "?SDK=" OS_NAME "&Version=" OS_VERSION "&Platform=" HARDWARE_PLATFORM_NAME "&MQTTLib=" MQTT_LIB

/**
 * @brief The length of the MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING_LENGTH               ( ( uint16_t ) ( sizeof( METRICS_STRING ) - 1 ) )


#ifdef CLIENT_USERNAME

/**
 * @brief Append the username with the metrics string if #CLIENT_USERNAME is defined.
 *
 * This is to support both metrics reporting and username/password based client
 * authentication by AWS IoT.
 */
#define CLIENT_USERNAME_WITH_METRICS    CLIENT_USERNAME METRICS_STRING
#endif

// Topic Identifier
enum
{
	TEMPLATE_REJECT,        // Provisioning Template Reject Topic
	CERTIFICATE_REJECT,     // Create Certificate Reject Topic
	TEMPLATE_ACCEPT,        // Provisioning Template Accept Topic
	CERTIFICATE_ACCEPT,     // Create Certificate Accept Topic
	MQTT_EX,                // MQTT Example Topic
	OPENWORLD,              // Create New Session Example Topic
	PROVISIONING_CC,        // Provisioning Create Certificate Topic
	PROVISIONING_TT,         // Provisioning Template Topic
    USER_PUBSUB
};

// MQTT Message Identifier
enum
{
	EX_IDENTIFIER = 1,      // Example Identifier
	CC_IDENTIFIER,          // Create Certificate Identifier
    NEW_IDENTIFIER          // New Session Identifier
};

// MQTT Progress Identifier
enum
{
    SET_COMPLETE,           // Set Complete Flag
    SET_IN_PROGRESS,        // Set In Progress Flag
    SET_FAILED,             // Set Failed Flag
    RESERVED                // Reserved
};

// Option Flag Identifier
enum
{
    OPT_C,
    OPT_CL,
    OPT_F,
    OPT_M,
    OPT_P,
    OPT_S,
    OPT_T
};

/**
 * @brief Initialize Topic name
 */

char TopicFilter[TOPIC_LENGTH][256] = {
	TEMPLATE_REJECT_TOPIC,
	CERTIFICATE_REJECT_TOPIC,
	TEMPLATE_ACCEPT_TOPIC,
	CERTIFICATE_ACCEPT_TOPIC,
	MQTT_EXAMPLE_TOPIC,
	"openworld",
	PROVISIONING_CERT_CREATE_TOPIC,
	PROVISIONING_TEMPLATE_TOPIC,
    ""
};

/**
 * @brief Initialize Topic name length
 */

uint16_t TopicFilterLength[TOPIC_LENGTH] = {
	TEMPLATE_RJT_LENGTH,
	CERTIFICATE_RJT_LENGTH,
	TEMPLATE_ACC_LENGTH,
	CERTIFICATE_RJT_LENGTH,
	MQTT_EXAMPLE_TOPIC_LENGTH,
	sizeof("openworld")-1,
	PROVISIONING_CC_LENGTH,
	PROVISIONING_TT_LENGTH,
    0
};

/**
 * @brief Publish Payload Message Array 
 */

char MqttExMessage[4][1024] = {
	"{}",
	"{}",
    "{\"service_response\":\"##### RESPONSE FROM PREVIOUSLY FORBIDDEN TOPIC #####\"}",
    "{}"
};

/**
 * @brief Publish Payload Message Length Array
 */ 
uint16_t MqttExMessageLength[4] = {0, };

/// @brief Option Flag
uint8_t optFlag[7] = {0,};

/// @brief Endpoint Device UUID
char uuidStr[64] = {0,};

/// @brief New Session Client Identifier 
char deviceUUID[128] = {0,};

/// @brief default Certificate ID
char defCertfileId[12] = {0,};

/// @brief Global Certificate ID
char gCertificateId[16] = {0,};

/// @brief Create Certificate Parsing query Key
char queryCertificate[4][64] = 
{
	"certificateId",
	"certificatePem",
	"privateKey",
	"certificateOwnershipToken"
};

/// @brief Client Session Present Flag
bool *gSessionPresent;

/// @brief Global Loop Flag
int gLoop = 1;

/// @brief Set in progress Flag
int set_in_progress = 0;

/*-----------------------------------------------------------*/

/**
 * @brief Structure to keep the MQTT publish packets until an ack is received
 * for QoS1 publishes.
 */
typedef struct PublishPackets
{
	/**
	 * @brief Packet identifier of the publish packet.
	 */
	uint16_t packetId;

	/**
	 * @brief Publish info of the publish packet.
	 */
	MQTTPublishInfo_t pubInfo;
} PublishPackets_t;

/*-----------------------------------------------------------*/

/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker;
 * it is used to match received Subscribe ACK to the transmitted subscribe.
 */
static uint16_t globalSubscribePacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker;
 * it is used to match received Unsubscribe ACK to the transmitted unsubscribe
 * request.
 */
static uint16_t globalUnsubscribePacketIdentifier = 0U;

/**
 * @brief Array to keep the outgoing publish messages.
 * These stored outgoing publish messages are kept until a successful ack
 * is received.
 */
static PublishPackets_t outgoingPublishPackets[ MAX_OUTGOING_PUBLISHES ] = { 0 };

/**
 * @brief Array to keep subscription topics.
 * Used to re-subscribe to topics that failed initial subscription attempts.
 */
static MQTTSubscribeInfo_t pGlobalSubscriptionList[TOPIC_LENGTH];

/**
 * @brief The network buffer must remain valid for the lifetime of the MQTT context.
 */
static uint8_t buffer[ NETWORK_BUFFER_SIZE ];

/**
 * @brief Status of latest Subscribe ACK;
 * it is updated every time the callback function processes a Subscribe ACK
 * and accounts for subscription to a single topic.
 */
static MQTTSubAckStatus_t globalSubAckStatus = MQTTSubAckFailure;

/*-----------------------------------------------------------*/

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext
{
	OpensslParams_t * pParams;
};

NetworkContext_t gNetworkContext = { 0 };

/*-----------------------------------------------------------*/

/**
 * @brief Unsubscribe Fleet Provisioning Topics
 * 
 * @param[in] InmqttContext Input MQTT Connection Information
 */
static int unsubscribeFleetTopic(MQTTContext_t *InmqttContext);

/**
 * @brief Convert JSON to Cert file functions
 * 
 * @param[in] inStr Input JSON String
 * @param[in] inStrLength Input JSON String length
 * @param[in] fp cert file descripter
 */

static int JSONtoCertFile(char *inStr, int inStrLength, FILE *fp);

/**
 * @brief 
 * 
 */

void assemble_certificates(char *pBuffer, size_t pBufferLength);

/**
 * @brief The random number generator to use for exponential backoff with
 * jitter retry logic.
 *
 * @return The generated random number.
 */
static uint32_t generateRandomNumber();

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext, int flag );

/**
 * @brief A function that connects to MQTT broker,
 * subscribes a topic, publishes to the same
 * topic MQTT_PUBLISH_COUNT_PER_LOOP number of times, and verifies if it
 * receives the Publish message back.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in,out] pClientSessionPresent Pointer to flag indicating if an
 * MQTT session is present in the client.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on success.
 */
static int subscribePublishLoop( MQTTContext_t * pMqttContext,
		bool * pClientSessionPresent );

/**
 * @brief The function to handle the incoming publishes.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] packetIdentifier Packet identifier of the incoming publish.
 */
static void handleIncomingPublish( MQTTContext_t *pMqttContext, 
		MQTTPublishInfo_t * pPublishInfo,
		uint16_t packetIdentifier );

/**
 * @brief The application callback function for getting the incoming publish
 * and incoming acks reported from MQTT library.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pDeserializedInfo Deserialized information from the incoming packet.
 */
static void eventCallback( MQTTContext_t * pMqttContext,
		MQTTPacketInfo_t * pPacketInfo,
		MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Initializes the MQTT library.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pNetworkContext The network context pointer.
 *
 * @return EXIT_SUCCESS if the MQTT library is initialized;
 * EXIT_FAILURE otherwise.
 */
static int initializeMqtt( MQTTContext_t * pMqttContext,
		NetworkContext_t * pNetworkContext );

/**
 * @brief Sends an MQTT CONNECT packet over the already connected TCP socket.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] createCleanSession Creates a new MQTT session if true.
 * If false, tries to establish the existing session if there was session
 * already present in broker.
 * @param[out] pSessionPresent Session was already present in the broker or not.
 * Session present response is obtained from the CONNACK from broker.
 *
 * @return EXIT_SUCCESS if an MQTT session is established;
 * EXIT_FAILURE otherwise.
 */
static int establishMqttSession( MQTTContext_t * pMqttContext,
		bool createCleanSession,
		bool * pSessionPresent, int flag );

/**
 * @brief Close an MQTT session by sending MQTT DISCONNECT.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if DISCONNECT was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int disconnectMqttSession( MQTTContext_t * pMqttContext );

/**
 * @brief Sends an MQTT SUBSCRIBE to subscribe to #MQTT_EXAMPLE_TOPIC
 * defined at the top of the file.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if SUBSCRIBE was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int subscribeToTopic( MQTTContext_t * pMqttContext, int tnum );

/**
 * @brief Sends an MQTT UNSUBSCRIBE to unsubscribe from
 * #MQTT_EXAMPLE_TOPIC defined at the top of the file.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if UNSUBSCRIBE was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int unsubscribeFromTopic( MQTTContext_t * pMqttContext, int tnum );

/**
 * @brief Sends an MQTT PUBLISH to #MQTT_EXAMPLE_TOPIC defined at
 * the top of the file.
 *
 * @param[in] pMqttContext MQTT context pointer.
 *
 * @return EXIT_SUCCESS if PUBLISH was successfully sent;
 * EXIT_FAILURE otherwise.
 */
static int publishToTopic( MQTTContext_t * pMqttContext, int tnum, int mnum );

/**
 * @brief Function to get the free index at which an outgoing publish
 * can be stored.
 *
 * @param[out] pIndex The output parameter to return the index at which an
 * outgoing publish message can be stored.
 *
 * @return EXIT_FAILURE if no more publishes can be stored;
 * EXIT_SUCCESS if an index to store the next outgoing publish is obtained.
 */
static int getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex );

/**
 * @brief Function to clean up an outgoing publish at given index from the
 * #outgoingPublishPackets array.
 *
 * @param[in] index The index at which a publish message has to be cleaned up.
 */
static void cleanupOutgoingPublishAt( uint8_t index );

/**
 * @brief Function to clean up all the outgoing publishes maintained in the
 * array.
 */
static void cleanupOutgoingPublishes( void );

/**
 * @brief Function to clean up the publish packet with the given packet id.
 *
 * @param[in] packetId Packet identifier of the packet to be cleaned up from
 * the array.
 */
static void cleanupOutgoingPublishWithPacketID( uint16_t packetId );

/**
 * @brief Function to resend the publishes if a session is re-established with
 * the broker. This function handles the resending of the QoS1 publish packets,
 * which are maintained locally.
 *
 * @param[in] pMqttContext MQTT context pointer.
 */
static int handlePublishResend( MQTTContext_t * pMqttContext );

/**
 * @brief Function to update variable globalSubAckStatus with status
 * information from Subscribe ACK. Called by eventCallback after processing
 * incoming subscribe echo.
 *
 * @param[in] Server response to the subscription request.
 */
static void updateSubAckStatus( MQTTPacketInfo_t * pPacketInfo );

/**
 * @brief Function to handle resubscription of topics on Subscribe
 * ACK failure. Uses an exponential backoff strategy with jitter.
 *
 * @param[in] pMqttContext MQTT context pointer.
 */
static int handleResubscribe( MQTTContext_t * pMqttContext, int tnum);

/*-----------------------------------------------------------*/

static bool getSessionPresent()
{
	return *gSessionPresent;
}

static int registerThing(char *token, size_t tokenLength)
{
	JSONStatus_t jsonResult;

	char parseToken[1024] = {0,};
	strncpy(parseToken, token, sizeof(char)*tokenLength);
	sprintf(MqttExMessage[1], "{\"certificateOwnershipToken\":\"%s\",\"parameters\":{\"SerialNumber\":\"%s\"}}",parseToken, uuidStr);
	MqttExMessageLength[1] = strlen(MqttExMessage[1]);

	jsonResult = JSON_Validate(MqttExMessage[1], MqttExMessageLength[1]);

	if(jsonResult == JSONSuccess)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}

static int JSONtoCertFile(char *inStr, int inStrLength, FILE *fp)
{
	char fileBuffer[NETWORK_BUFFER_SIZE] = {0,};
	strncpy(fileBuffer, inStr, sizeof(char)*inStrLength);
	char tempPtr[2048] = {0,};
	char *ptr = strstr(fileBuffer, "\\");
	int tPtrSize = 0, i = 0;
	tPtrSize = strlen(fileBuffer) - strlen(ptr);
	
	while(ptr != NULL)
	{
		memset(tempPtr, 0, sizeof(tempPtr));
		if(i == 0)
		{
			tPtrSize = strlen(fileBuffer) - strlen(ptr);
			strncpy(tempPtr, fileBuffer, tPtrSize);
			i = tPtrSize;
		}
		else
		{
			tPtrSize = strlen(fileBuffer) - i - strlen(ptr) - 2;
			strncpy(tempPtr, fileBuffer + i + 2, tPtrSize);
			i = tPtrSize + i + 2;
		}
		ptr = strstr(ptr+1, "\\");
		fprintf(fp, "%s\n", tempPtr);
	}
	
	return 0;
}

static uint32_t generateRandomNumber()
{
	return( rand() );
}

// MQTT 브로커에 연결을 시도하는 함수.

static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext, int flag )
{
	int returnStatus = EXIT_SUCCESS;
	BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
	OpensslStatus_t opensslStatus = OPENSSL_SUCCESS;
	BackoffAlgorithmContext_t reconnectParams;
	ServerInfo_t serverInfo;
	OpensslCredentials_t opensslCredentials;
	uint16_t nextRetryBackOff;

    char privatefilePath[50] = {0,}, certfilePath[50] = {0,};


	/* Initialize information to connect to the MQTT broker. */
	// AWS IoT 엔드포인트 주소
	serverInfo.pHostName = AWS_IOT_ENDPOINT;
	// 이건 자동계산됨
	serverInfo.hostNameLength = AWS_IOT_ENDPOINT_LENGTH;
	// Default : 8883 / SOCAR GUEST 계정 사용 시 443 포트 사용
	serverInfo.port = AWS_MQTT_PORT;

	// TLS 세션 구축을 위한 Credential 초기화
	memset( &opensslCredentials, 0, sizeof( OpensslCredentials_t ) );
	// pRootCaPaht : AmazonCARoot Cert 파일
	opensslCredentials.pRootCaPath = ROOT_CA_CERT_PATH;

	/* If #CLIENT_USERNAME is defined, username/password is used for authenticating
	 * the client. */
#ifndef CLIENT_USERNAME
	// 사물 생성시 발급받은 인증서 경로
    switch(flag)
    {
        case EX_IDENTIFIER:
            if(optFlag[OPT_C] != 1)
            {
                memset(defCertfileId, 0, sizeof(defCertfileId));
                strcpy(defCertfileId, EX_CERTID);
            }
            sprintf(certfilePath, "%s/%s-certificate.pem.crt", CERTFILE_PATH, EX_CERTID);
            sprintf(privatefilePath, "%s/%s-private.pem.key", CERTFILE_PATH, EX_CERTID);
        break;
        case NEW_IDENTIFIER:
            if(strlen(gCertificateId) != 0)
            {
                LogInfo(("new certificateId : %s\n", gCertificateId));
                sprintf(certfilePath, "%s/%s-certificate.pem.crt", CERTFILE_PATH, gCertificateId);
                sprintf(privatefilePath, "%s/%s-private.pem.key", CERTFILE_PATH, gCertificateId);
            }
        break;
    }

    opensslCredentials.pClientCertPath = certfilePath;
    // 사물 생성시 발급받은 Private Key 경로
    opensslCredentials.pPrivateKeyPath = privatefilePath;
	
#endif

	/* AWS IoT requires devices to send the Server Name Indication (SNI)
	 * extension to the Transport Layer Security (TLS) protocol and provide
	 * the complete endpoint address in the host_name field. Details about
	 * SNI for AWS IoT can be found in the link below.
	 * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html */

	opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;

	// 8883 포트로 인증이 불가능할 경우 443 포트로 ALPN 프로토콜을 사용
	if( AWS_MQTT_PORT == 443 )
	{
		/* Pass the ALPN protocol name depending on the port being used.
		 * Please see more details about the ALPN protocol for the AWS IoT MQTT
		 * endpoint in the link below.
		 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
		 *
		 * For username and password based authentication in AWS IoT,
		 * #AWS_IOT_PASSWORD_ALPN is used. More details can be found in the
		 * link below.
		 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
		 */
#ifdef CLIENT_USERNAME
		opensslCredentials.pAlpnProtos = AWS_IOT_PASSWORD_ALPN;
		opensslCredentials.alpnProtosLen = AWS_IOT_PASSWORD_ALPN_LENGTH;
#else
		opensslCredentials.pAlpnProtos = AWS_IOT_MQTT_ALPN;
		opensslCredentials.alpnProtosLen = AWS_IOT_MQTT_ALPN_LENGTH;
#endif
	}

	/* Initialize reconnect attempts and interval */
	// 브로커에 연결 실패 시 재시도 하는 횟수와 재시도 주기를 설정하는 함수.
	// reconnectParams Context에 아래 정의된 Value를 대입해줌.
	BackoffAlgorithm_InitializeParams( &reconnectParams,
			CONNECTION_RETRY_BACKOFF_BASE_MS,
			CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
			CONNECTION_RETRY_MAX_ATTEMPTS );

	/* Attempt to connect to MQTT broker. If connection fails, retry after
	 * a timeout. Timeout value will exponentially increase until maximum
	 * attempts are reached.
	 */
	do
	{
		/* Establish a TLS session with the MQTT broker. This example connects
		 * to the MQTT broker as specified in AWS_IOT_ENDPOINT and AWS_MQTT_PORT
		 * at the demo config header. */
		// 
		LogInfo( ( "Establishing a TLS session to %.*s:%d.",
					AWS_IOT_ENDPOINT_LENGTH,
					AWS_IOT_ENDPOINT,
					AWS_MQTT_PORT ) );
		// MQTT 브로커 서버에 연결하여 Openssl 인증 진행
		opensslStatus = Openssl_Connect( pNetworkContext,
				&serverInfo,
				&opensslCredentials,
				TRANSPORT_SEND_RECV_TIMEOUT_MS,
				TRANSPORT_SEND_RECV_TIMEOUT_MS );

		// Openssl_Connect 실패 시 재시도
		if( opensslStatus != OPENSSL_SUCCESS )
		{
			/* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
			backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

			if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
			{
				LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
				returnStatus = EXIT_FAILURE;
			}
			else if( backoffAlgStatus == BackoffAlgorithmSuccess )
			{
				LogWarn( ( "Connection to the broker failed. Retrying connection "
							"after %hu ms backoff.",
							( unsigned short ) nextRetryBackOff ) );
				Clock_SleepMs( nextRetryBackOff );
			}
		}
	} while( ( opensslStatus != OPENSSL_SUCCESS ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex )
{
	int returnStatus = EXIT_FAILURE;
	uint8_t index = 0;

	assert( outgoingPublishPackets != NULL );
	assert( pIndex != NULL );

	for( index = 0; index < MAX_OUTGOING_PUBLISHES; index++ )
	{
		/* A free index is marked by invalid packet id.
		 * Check if the the index has a free slot. */
		if( outgoingPublishPackets[ index ].packetId == MQTT_PACKET_ID_INVALID )
		{
			returnStatus = EXIT_SUCCESS;
			break;
		}
	}

	/* Copy the available index into the output param. */
	*pIndex = index;

	return returnStatus;
}
/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishAt( uint8_t index )
{
	assert( outgoingPublishPackets != NULL );
	assert( index < MAX_OUTGOING_PUBLISHES );

	/* Clear the outgoing publish packet. */
	( void ) memset( &( outgoingPublishPackets[ index ] ),
			0x00,
			sizeof( outgoingPublishPackets[ index ] ) );
}

/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishes( void )
{
	assert( outgoingPublishPackets != NULL );

	/* Clean up all the outgoing publish packets. */
	( void ) memset( outgoingPublishPackets, 0x00, sizeof( outgoingPublishPackets ) );
}

/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishWithPacketID( uint16_t packetId )
{
	uint8_t index = 0;

	assert( outgoingPublishPackets != NULL );
	assert( packetId != MQTT_PACKET_ID_INVALID );

	/* Clean up all the saved outgoing publishes. */
	for( ; index < MAX_OUTGOING_PUBLISHES; index++ )
	{
		if( outgoingPublishPackets[ index ].packetId == packetId )
		{
			cleanupOutgoingPublishAt( index );
			LogInfo( ( "Cleaned up outgoing publish packet with packet id %u.\n\n",
						packetId ) );
			break;
		}
	}
}

/*-----------------------------------------------------------*/

static int handlePublishResend( MQTTContext_t * pMqttContext )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus = MQTTSuccess;
	uint8_t index = 0U;
	MQTTStateCursor_t cursor = MQTT_STATE_CURSOR_INITIALIZER;
	uint16_t packetIdToResend = MQTT_PACKET_ID_INVALID;
	bool foundPacketId = false;

	assert( pMqttContext != NULL );
	assert( outgoingPublishPackets != NULL );

	/* MQTT_PublishToResend() provides a packet ID of the next PUBLISH packet
	 * that should be resent. In accordance with the MQTT v3.1.1 spec,
	 * MQTT_PublishToResend() preserves the ordering of when the original
	 * PUBLISH packets were sent. The outgoingPublishPackets array is searched
	 * through for the associated packet ID. If the application requires
	 * increased efficiency in the look up of the packet ID, then a hashmap of
	 * packetId key and PublishPacket_t values may be used instead. */
	packetIdToResend = MQTT_PublishToResend( pMqttContext, &cursor );

	while( packetIdToResend != MQTT_PACKET_ID_INVALID )
	{
		foundPacketId = false;

		for( index = 0U; index < MAX_OUTGOING_PUBLISHES; index++ )
		{
			if( outgoingPublishPackets[ index ].packetId == packetIdToResend )
			{
				foundPacketId = true;
				outgoingPublishPackets[ index ].pubInfo.dup = true;

				LogInfo( ( "Sending duplicate PUBLISH with packet id %u.",
							outgoingPublishPackets[ index ].packetId ) );
				mqttStatus = MQTT_Publish( pMqttContext,
						&outgoingPublishPackets[ index ].pubInfo,
						outgoingPublishPackets[ index ].packetId );

				if( mqttStatus != MQTTSuccess )
				{
					LogError( ( "Sending duplicate PUBLISH for packet id %u "
								" failed with status %s.",
								outgoingPublishPackets[ index ].packetId,
								MQTT_Status_strerror( mqttStatus ) ) );
					returnStatus = EXIT_FAILURE;
					break;
				}
				else
				{
					LogInfo( ( "Sent duplicate PUBLISH successfully for packet id %u.\n\n",
								outgoingPublishPackets[ index ].packetId ) );
				}
			}
		}

		if( foundPacketId == false )
		{
			LogError( ( "Packet id %u requires resend, but was not found in "
						"outgoingPublishPackets.",
						packetIdToResend ) );
			returnStatus = EXIT_FAILURE;
			break;
		}
		else
		{
			/* Get the next packetID to be resent. */
			packetIdToResend = MQTT_PublishToResend( pMqttContext, &cursor );
		}
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static void handleIncomingPublish( MQTTContext_t *pMqttContext, MQTTPublishInfo_t * pPublishInfo,
		uint16_t packetIdentifier )
{
	int returnStatus, i = 0;

	assert( pPublishInfo != NULL );
	char payloadBuffer[NETWORK_BUFFER_SIZE] = {0,};

	/* Process incoming Publish. */
	LogInfo( ( "Incoming QOS : %d.", pPublishInfo->qos ) );

	/* Verify the received publish is for the topic we have subscribed to. */
	for(i = 0 ; i < TOPIC_LENGTH ; i++)
	{
		if( ( pPublishInfo->topicNameLength == TopicFilterLength[i] ) &&
				( 0 == strncmp( TopicFilter[i],
						pPublishInfo->pTopicName,
						pPublishInfo->topicNameLength ) ) )
		{
			strncpy(payloadBuffer, (const char *) pPublishInfo->pPayload, pPublishInfo->payloadLength);
			LogInfo( ( "Incoming Publish Topic Name: %.*s matches subscribed topic.\n"
						"Incoming Publish message Packet Id is %u.\n"
						"Incoming Publish Message : %.*s.\n\n",
						pPublishInfo->topicNameLength,
						pPublishInfo->pTopicName,
						packetIdentifier,
						( int ) pPublishInfo->payloadLength,
						payloadBuffer));
						//( const char * ) pPublishInfo->pPayload ) );
			if( i == CERTIFICATE_ACCEPT )
			{
				assemble_certificates(payloadBuffer, pPublishInfo->payloadLength);
				publishToTopic(pMqttContext, PROVISIONING_TT, 1);
			}

			else if (i == TEMPLATE_ACCEPT)
			{
                unsubscribeFleetTopic(pMqttContext);
                set_in_progress = SET_IN_PROGRESS;
				returnStatus = disconnectMqttSession( pMqttContext );

				if(returnStatus != EXIT_SUCCESS)
				{
					returnStatus = disconnectMqttSession( pMqttContext );
				}

				if(returnStatus == EXIT_SUCCESS)
				{
					MQTTStatus_t mqttStatus;
					MQTTConnectInfo_t connectInfo = {0, };
					JSONStatus_t jsonResult;
                    bool mqttSessionEstablished = false;
					bool pSessionPresent, brokerSessionPresent, createCleanSession = false;
					char *value, tQuery[24];
					strcpy(tQuery, "thingName");
					size_t valueLength, queryLength = strlen(tQuery);

					jsonResult = JSON_Validate(payloadBuffer, pPublishInfo->payloadLength);
					if(jsonResult == JSONSuccess)
					{
						jsonResult = JSON_Search(payloadBuffer, pPublishInfo->payloadLength, tQuery, queryLength,
						&value, &valueLength);

						pSessionPresent = getSessionPresent();

						sprintf(deviceUUID, "%s-Prod", uuidStr);

                        returnStatus = connectToServerWithBackoffRetries(&gNetworkContext, NEW_IDENTIFIER);

                        if(returnStatus == EXIT_FAILURE)
                        {
                            set_in_progress = SET_FAILED;
                            LogError(("Failed to connect new openssl session.\n"));
                        }
                        else
                        {
                            createCleanSession = ( pSessionPresent == true ) ? false : true;
                            returnStatus = establishMqttSession(pMqttContext, createCleanSession, &brokerSessionPresent, CC_IDENTIFIER);
                            
                            if(returnStatus == EXIT_SUCCESS)
                            {
                                mqttSessionEstablished = true;
                                pSessionPresent = true;

                                if(brokerSessionPresent == true)
                                {
                                    LogInfo( ( "An MQTT session with broker is re-established. "
                                                "Resending unacked publishes." ) );
                                    returnStatus = handlePublishResend(pMqttContext);
                                }
                                else
                                {
                                    LogInfo( ( "A clean MQTT connection is established."
                                                " Cleaning up all the stored outgoing publishes.\n\n" ) );

                                    /* Clean up the outgoing publishes waiting for ack as this new
                                    * connection doesn't re-establish an existing session. */
                                    cleanupOutgoingPublishes();
                                }

                                returnStatus = subscribeToTopic(pMqttContext, OPENWORLD);
                                mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

                                if(returnStatus == EXIT_SUCCESS && mqttStatus == MQTTSuccess)
                                {
                                    
                                    publishToTopic(pMqttContext, OPENWORLD, 2);
                                    set_in_progress = SET_COMPLETE;
                                }
                            }
                            else
                            {
                                set_in_progress = SET_FAILED;
                                LogInfo(("Failed to connect to MQTT broker.\n"));
                            }
                        }
					}
                    else
                    {
                        LogInfo(("JSON Validation Failed\n"));
                    }
				}
                else
                {
                    set_in_progress = SET_FAILED;   
                    LogError(("Disconnect previouse connection failed\n"));
                }
			}
			
			break;
		}
		else
		{
			LogInfo( ( "Incoming Publish Topic Name: %.*s does not match subscribed topic.",
						pPublishInfo->topicNameLength,
						pPublishInfo->pTopicName ) );
		}
	}
}

void assemble_certificates(char *pBuffer, size_t pBufferLength)
{
	char tempId[16], certificateId[16] = {0,};
	char certFileName[36] = {0,}, privateFileName[36] = {0,};
	char payloadBuffer[NETWORK_BUFFER_SIZE];
	
	int convertResult = 0;
	JSONStatus_t jsonResult;
	size_t valueLength;
	size_t queryLength = strlen(queryCertificate[0]);
	char *value;

	LogInfo(("Input JSON String : %s / Length : %d\n", pBuffer, pBufferLength));

	strncpy(payloadBuffer, pBuffer, sizeof(char)*pBufferLength);

	jsonResult = JSON_Validate(pBuffer, pBufferLength);

	if(jsonResult == JSONSuccess)
	{
		jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[0], queryLength,
			&value, &valueLength);

		if(jsonResult == JSONSuccess)
		{
			char save = value[valueLength];
			value[valueLength] = '\0';
			strncpy(tempId, value, sizeof(char) * 10);
			strcpy(certificateId, tempId);
			
			memset(payloadBuffer, 0, sizeof(char) * pBufferLength);
			strncpy(payloadBuffer, pBuffer, sizeof(char)*pBufferLength);

			// Cert Key Parsing
			queryLength = strlen(queryCertificate[1]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[1], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				certificateId[strlen(certificateId)] = '\0';
				sprintf(certFileName, "%s/%s-certificate.pem.crt", CERTFILE_PATH, certificateId);
				fp = fopen(certFileName, "w");
				
				convertResult = JSONtoCertFile(value, valueLength, fp);
				fclose(fp);
			}
			else
			{
				LogError(("JSON Search Error\n"));
			}

			// Private Key Parsing
			queryLength = strlen(queryCertificate[2]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[2], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				tempId[strlen(tempId)] = '\0';
				sprintf(privateFileName, "%s/%s-private.pem.key", CERTFILE_PATH, tempId);
                strcpy(gCertificateId, tempId);
				fp = fopen(privateFileName, "w");

				convertResult = JSONtoCertFile(value, valueLength, fp);
				fclose(fp);
			}

			queryLength = strlen(queryCertificate[3]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[3], queryLength,
				&value, &valueLength);

			// certificate Ownership Parsing
			if(jsonResult == JSONSuccess)
			{
				convertResult = registerThing(value, valueLength);
				
                if(convertResult != EXIT_SUCCESS)
                {
                    LogError(("Registration new service failed\n"));
                }
			}
		}
		else
		{
			LogError(("JSON Search Error\n"));
		}
	}
	else
	{
		LogError(("JSON Validation Error\n"));
	}
}

/*-----------------------------------------------------------*/

static void updateSubAckStatus( MQTTPacketInfo_t * pPacketInfo )
{
	uint8_t * pPayload = NULL;
	size_t pSize = 0;

	MQTTStatus_t mqttStatus = MQTT_GetSubAckStatusCodes( pPacketInfo, &pPayload, &pSize );

	/* MQTT_GetSubAckStatusCodes always returns success if called with packet info
	 * from the event callback and non-NULL parameters. */
	assert( mqttStatus == MQTTSuccess );

	/* Suppress unused variable warning when asserts are disabled in build. */
	( void ) mqttStatus;

	/* Demo only subscribes to one topic, so only one status code is returned. */
	globalSubAckStatus = pPayload[ 0 ];
}

/*-----------------------------------------------------------*/

static int handleResubscribe( MQTTContext_t * pMqttContext, int tnum )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus = MQTTSuccess;
	BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
	BackoffAlgorithmContext_t retryParams;
	uint16_t nextRetryBackOff = 0U;

	assert( pMqttContext != NULL );

	/* Initialize retry attempts and interval. */
	BackoffAlgorithm_InitializeParams( &retryParams,
			CONNECTION_RETRY_BACKOFF_BASE_MS,
			CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
			CONNECTION_RETRY_MAX_ATTEMPTS );

	do
	{
		/* Send SUBSCRIBE packet.
		 * Note: reusing the value specified in globalSubscribePacketIdentifier is acceptable here
		 * because this function is entered only after the receipt of a SUBACK, at which point
		 * its associated packet id is free to use. */
		mqttStatus = MQTT_Subscribe( pMqttContext,
				&pGlobalSubscriptionList[tnum],
				sizeof( pGlobalSubscriptionList[tnum] ) / sizeof( MQTTSubscribeInfo_t ),
				globalSubscribePacketIdentifier );

		if( mqttStatus != MQTTSuccess )
		{
			LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
			returnStatus = EXIT_FAILURE;
			break;
		}

		LogInfo( ( "SUBSCRIBE sent for topic %.*s to broker.\n\n",
					TopicFilterLength[tnum],
					TopicFilter[tnum] ) );

		/* Process incoming packet. */
		mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

		if( mqttStatus != MQTTSuccess )
		{
			LogError( ( "MQTT_ProcessLoop returned with status = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
			returnStatus = EXIT_FAILURE;
			break;
		}

		/* Check if recent subscription request has been rejected. globalSubAckStatus is updated
		 * in eventCallback to reflect the status of the SUBACK sent by the broker. It represents
		 * either the QoS level granted by the server upon subscription, or acknowledgement of
		 * server rejection of the subscription request. */
		if( globalSubAckStatus == MQTTSubAckFailure )
		{
			/* Generate a random number and get back-off value (in milliseconds) for the next re-subscribe attempt. */
			backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &retryParams, generateRandomNumber(), &nextRetryBackOff );

			if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
			{
				LogError( ( "Subscription to topic failed, all attempts exhausted." ) );
				returnStatus = EXIT_FAILURE;
			}
			else if( backoffAlgStatus == BackoffAlgorithmSuccess )
			{
				LogWarn( ( "Server rejected subscription request. Retrying "
							"connection after %hu ms backoff.",
							( unsigned short ) nextRetryBackOff ) );
				Clock_SleepMs( nextRetryBackOff );
			}
		}
	} while( ( globalSubAckStatus == MQTTSubAckFailure ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

	return returnStatus;
}

/*-----------------------------------------------------------*/

static void eventCallback( MQTTContext_t * pMqttContext,
		MQTTPacketInfo_t * pPacketInfo,
		MQTTDeserializedInfo_t * pDeserializedInfo )
{
	uint16_t packetIdentifier;

	assert( pMqttContext != NULL );
	assert( pPacketInfo != NULL );
	assert( pDeserializedInfo != NULL );

	/* Suppress unused parameter warning when asserts are disabled in build. */
	( void ) pMqttContext;

	packetIdentifier = pDeserializedInfo->packetIdentifier;

	/* Handle incoming publish. The lower 4 bits of the publish packet
	 * type is used for the dup, QoS, and retain flags. Hence masking
	 * out the lower bits to check if the packet is publish. */
	if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
	{
		assert( pDeserializedInfo->pPublishInfo != NULL );
		/* Handle incoming publish. */
		handleIncomingPublish( pMqttContext, pDeserializedInfo->pPublishInfo, packetIdentifier );
	}
	else
	{
		/* Handle other packets. */
		switch( pPacketInfo->type )
		{
			case MQTT_PACKET_TYPE_SUBACK:

				/* A SUBACK from the broker, containing the server response to our subscription request, has been received.
				 * It contains the status code indicating server approval/rejection for the subscription to the single topic
				 * requested. The SUBACK will be parsed to obtain the status code, and this status code will be stored in global
				 * variable globalSubAckStatus. */
				updateSubAckStatus( pPacketInfo );

				/* Check status of the subscription request. If globalSubAckStatus does not indicate
				 * server refusal of the request (MQTTSubAckFailure), it contains the QoS level granted
				 * by the server, indicating a successful subscription attempt. */
				if( globalSubAckStatus != MQTTSubAckFailure )
				{
				}
				/* Make sure ACK packet identifier matches with Request packet identifier. */
				assert( globalSubscribePacketIdentifier == packetIdentifier );
				break;

			case MQTT_PACKET_TYPE_UNSUBACK:
				/* Make sure ACK packet identifier matches with Request packet identifier. */
				assert( globalUnsubscribePacketIdentifier == packetIdentifier );
				break;

			case MQTT_PACKET_TYPE_PINGRESP:

				/* Nothing to be done from application as library handles
				 * PINGRESP. */
				LogWarn( ( "PINGRESP should not be handled by the application "
							"callback when using MQTT_ProcessLoop.\n\n" ) );
				break;

			case MQTT_PACKET_TYPE_PUBACK:
				LogInfo( ( "PUBACK received for packet id %u.\n\n",
							packetIdentifier ) );
				/* Cleanup publish packet when a PUBACK is received. */
				cleanupOutgoingPublishWithPacketID( packetIdentifier );
				break;

				/* Any other packet type is invalid. */
			default:
				LogError( ( "Unknown packet type received:(%02x).\n\n",
							pPacketInfo->type ) );
		}
	}
}

/*-----------------------------------------------------------*/

static int establishMqttSession( MQTTContext_t * pMqttContext,
		bool createCleanSession,
		bool * pSessionPresent, int flag )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;
	MQTTConnectInfo_t connectInfo = { 0 };

	assert( pMqttContext != NULL );
	assert( pSessionPresent != NULL );

	/* Establish MQTT session by sending a CONNECT packet. */

	/* If #createCleanSession is true, start with a clean session
	 * i.e. direct the MQTT broker to discard any previous session data.
	 * If #createCleanSession is false, directs the broker to attempt to
	 * reestablish a session which was already present. */

	
	connectInfo.cleanSession = createCleanSession;

	/* The client identifier is used to uniquely identify this MQTT client to
	 * the MQTT broker. In a production device the identifier can be something
	 * unique, such as a device serial number. */
	if(flag == EX_IDENTIFIER)
	{
		connectInfo.pClientIdentifier = uuidStr;
		connectInfo.clientIdentifierLength = strlen(uuidStr);
	}
	else if(flag == CC_IDENTIFIER)
	{
		connectInfo.pClientIdentifier = deviceUUID;
		connectInfo.clientIdentifierLength = strlen(deviceUUID);
	}

	/* The maximum time interval in seconds which is allowed to elapse
	 * between two Control Packets.
	 * It is the responsibility of the Client to ensure that the interval between
	 * Control Packets being sent does not exceed the this Keep Alive value. In the
	 * absence of sending any other Control Packets, the Client MUST send a
	 * PINGREQ Packet. */
	connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

	/* Use the username and password for authentication, if they are defined.
	 * Refer to the AWS IoT documentation below for details regarding client
	 * authentication with a username and password.
	 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
	 * An authorizer setup needs to be done, as mentioned in the above link, to use
	 * username/password based client authentication.
	 *
	 * The username field is populated with voluntary metrics to AWS IoT.
	 * The metrics collected by AWS IoT are the operating system, the operating
	 * system's version, the hardware platform, and the MQTT Client library
	 * information. These metrics help AWS IoT improve security and provide
	 * better technical support.
	 *
	 * If client authentication is based on username/password in AWS IoT,
	 * the metrics string is appended to the username to support both client
	 * authentication and metrics collection. */
#ifdef CLIENT_USERNAME
	connectInfo.pUserName = CLIENT_USERNAME_WITH_METRICS;
	connectInfo.userNameLength = strlen( CLIENT_USERNAME_WITH_METRICS );
	connectInfo.pPassword = CLIENT_PASSWORD;
	connectInfo.passwordLength = strlen( CLIENT_PASSWORD );
#else
	connectInfo.pUserName = METRICS_STRING;
	connectInfo.userNameLength = METRICS_STRING_LENGTH;
	/* Password for authentication is not used. */
	connectInfo.pPassword = NULL;
	connectInfo.passwordLength = 0U;
#endif /* ifdef CLIENT_USERNAME */

	/* Send MQTT CONNECT packet to broker. */
	mqttStatus = MQTT_Connect( pMqttContext, &connectInfo, NULL, CONNACK_RECV_TIMEOUT_MS, pSessionPresent );

	if( mqttStatus != MQTTSuccess )
	{
		returnStatus = EXIT_FAILURE;
		LogError( ( "Connection with MQTT broker failed with status %s.",
					MQTT_Status_strerror( mqttStatus ) ) );
	}
	else
	{
		LogInfo( ( "MQTT connection successfully established with broker.\n\n" ) );
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int disconnectMqttSession( MQTTContext_t * pMqttContext )
{
	MQTTStatus_t mqttStatus = MQTTSuccess;
	int returnStatus = EXIT_SUCCESS;

	assert( pMqttContext != NULL );

	/* Send DISCONNECT. */
	mqttStatus = MQTT_Disconnect( pMqttContext );

	if( mqttStatus != MQTTSuccess )
	{
		LogError( ( "Sending MQTT DISCONNECT failed with status=%s.",
					MQTT_Status_strerror( mqttStatus ) ) );
		returnStatus = EXIT_FAILURE;
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int subscribeToTopic( MQTTContext_t * pMqttContext, int tnum )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;

	assert( pMqttContext != NULL );

	globalSubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

	/* Send SUBSCRIBE packet. */
	mqttStatus = MQTT_Subscribe( pMqttContext,
			&pGlobalSubscriptionList[tnum],
			sizeof( pGlobalSubscriptionList[tnum] ) / sizeof( MQTTSubscribeInfo_t ),
			globalSubscribePacketIdentifier );

	if( mqttStatus != MQTTSuccess )
	{
		LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %s.",
					MQTT_Status_strerror( mqttStatus ) ) );
		returnStatus = EXIT_FAILURE;
	}
	else
	{
		LogInfo( ( "tnum : %d / SUBSCRIBE sent for topic %.*s to broker.\n\n",
					tnum,
					pGlobalSubscriptionList[tnum].topicFilterLength,
					pGlobalSubscriptionList[tnum].pTopicFilter ) );
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int unsubscribeFromTopic( MQTTContext_t * pMqttContext, int tnum )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;

	assert( pMqttContext != NULL );

	globalUnsubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

	/* Send UNSUBSCRIBE packet. */
	mqttStatus = MQTT_Unsubscribe( pMqttContext,
			&pGlobalSubscriptionList[tnum],
			sizeof( pGlobalSubscriptionList[tnum] ) / sizeof( MQTTSubscribeInfo_t ),
			globalUnsubscribePacketIdentifier );

	if( mqttStatus != MQTTSuccess )
	{
		LogError( ( "Failed to send UNSUBSCRIBE packet to broker with error = %s.",
					MQTT_Status_strerror( mqttStatus ) ) );
		returnStatus = EXIT_FAILURE;
	}
	else
	{
		LogInfo( ( "UNSUBSCRIBE sent for topic %.*s to broker.\n\n",
					TopicFilterLength[tnum],
					TopicFilter[tnum] ) );
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int publishToTopic( MQTTContext_t * pMqttContext, int tnum, int mnum )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus = MQTTSuccess;
	uint8_t publishIndex = MAX_OUTGOING_PUBLISHES;
    JSONStatus_t jsonResult;

	assert( pMqttContext != NULL );

	/* Get the next free index for the outgoing publish. All QoS1 outgoing
	 * publishes are stored until a PUBACK is received. These messages are
	 * stored for supporting a resend if a network connection is broken before
	 * receiving a PUBACK. */
	returnStatus = getNextFreeIndexForOutgoingPublishes( &publishIndex );

	if( returnStatus == EXIT_FAILURE )
	{
		LogError( ( "Unable to find a free spot for outgoing PUBLISH message.\n\n" ) );
	}
	else
	{
		/* This example publishes to only one topic and uses QOS1. */
		outgoingPublishPackets[ publishIndex ].pubInfo.qos = MQTTQoS1;
		outgoingPublishPackets[ publishIndex ].pubInfo.pTopicName = TopicFilter[tnum];
		outgoingPublishPackets[ publishIndex ].pubInfo.topicNameLength = TopicFilterLength[tnum];
		outgoingPublishPackets[ publishIndex ].pubInfo.pPayload = MqttExMessage[mnum];
		outgoingPublishPackets[ publishIndex ].pubInfo.payloadLength = MqttExMessageLength[mnum];

        jsonResult = JSON_Validate(MqttExMessage[mnum], MqttExMessageLength[mnum]);
		/* Get a new packet id. */
		outgoingPublishPackets[ publishIndex ].packetId = MQTT_GetPacketId( pMqttContext );

		/* Send PUBLISH packet. */
		mqttStatus = MQTT_Publish( pMqttContext,
				&outgoingPublishPackets[ publishIndex ].pubInfo,
				outgoingPublishPackets[ publishIndex ].packetId );

        if( jsonResult != JSONSuccess)
        {
            LogError( ( "Failed to validate JSON Message = %s.",
						MqttExMessage[mnum] ) );    
        }

		if( mqttStatus != MQTTSuccess)
		{
			LogError( ( "Failed to send PUBLISH packet to broker with error = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
			cleanupOutgoingPublishAt( publishIndex );
			returnStatus = EXIT_FAILURE;
		}
		else
		{
			LogInfo( ( "PUBLISH sent for topic %.*s to broker with packet ID %u.\n\n",
						TopicFilterLength[tnum],
						TopicFilter[tnum],
						outgoingPublishPackets[ publishIndex ].packetId ) );
		}
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/

static int initializeMqtt( MQTTContext_t * pMqttContext,
		NetworkContext_t * pNetworkContext )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;
	MQTTFixedBuffer_t networkBuffer;
	TransportInterface_t transport;

	assert( pMqttContext != NULL );
	assert( pNetworkContext != NULL );

	/* Fill in TransportInterface send and receive function pointers.
	 * For this demo, TCP sockets are used to send and receive data
	 * from network. Network context is SSL context for OpenSSL.*/
	transport.pNetworkContext = pNetworkContext;
	transport.send = Openssl_Send;
	transport.recv = Openssl_Recv;

	/* Fill the values for network buffer. */
	networkBuffer.pBuffer = buffer;
	networkBuffer.size = NETWORK_BUFFER_SIZE;

	/* Initialize MQTT library. */
	// MQTT_Init 함수 확인 결과 단순히 Context Value들이 NULL인지 체크하고 Callback 함수를 등록하는 과정을 거침

	mqttStatus = MQTT_Init( pMqttContext,
			&transport,
			Clock_GetTimeMs,
			eventCallback,
			&networkBuffer );

	if( mqttStatus != MQTTSuccess )
	{
		returnStatus = EXIT_FAILURE;
		LogError( ( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/
static int initSubscriptionList()
{
	int i = 0;
	int returnStatus = EXIT_SUCCESS;

	memset(pGlobalSubscriptionList, 0, sizeof(MQTTSubscribeInfo_t) * TOPIC_LENGTH);

	for(i = 0 ; i < TOPIC_LENGTH ; i++)
	{
		pGlobalSubscriptionList[i].qos = MQTTQoS1;
		pGlobalSubscriptionList[i].pTopicFilter = TopicFilter[i];
		pGlobalSubscriptionList[i].topicFilterLength = TopicFilterLength[i];
		LogInfo( ( "tnum : %d / SUBSCRIBE sent for topic %d %s to broker.\n\n",
		i,
		pGlobalSubscriptionList[i].topicFilterLength,
		pGlobalSubscriptionList[i].pTopicFilter ) );
	}

	
	return returnStatus;
}

static void initPublishMessage()
{
	int i = 0;

	for(i = 0 ; i < 3 ; i++)
		MqttExMessageLength[i] = strlen(MqttExMessage[i]);
}

static int subscribeFleetTopic(MQTTContext_t *InmqttContext, MQTTStatus_t *InmqttStatus)
{
	int i = 0;
	int returnStatus = EXIT_SUCCESS;
	
	for(i = 0 ; i < 4 ; i++)
	{
		if(returnStatus == EXIT_SUCCESS)
		{
			LogInfo( ( "Subscribing to the MQTT topic %.*s. Index : %d",
						TopicFilterLength[i],
						TopicFilter[i], i ) );
			returnStatus = subscribeToTopic( InmqttContext, i );
			*InmqttStatus = MQTT_ProcessLoop( InmqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

			if( *InmqttStatus != MQTTSuccess )
			{
				returnStatus = EXIT_FAILURE;
				LogError( ( "MQTT_ProcessLoop returned with status = %s.",
							MQTT_Status_strerror( *InmqttStatus ) ) );
			}
		}
		if( ( returnStatus == EXIT_SUCCESS ) && ( globalSubAckStatus == MQTTSubAckFailure ) )
		{
			LogInfo( ( "Server rejected initial subscription request. Attempting to re-subscribe to topic %.*s.",
						TopicFilterLength[i],
						TopicFilter[i] ) );
			returnStatus = handleResubscribe( InmqttContext, i );
		}
	}
	return returnStatus;
}

static int unsubscribeFleetTopic(MQTTContext_t *InmqttContext)
{
    int i = 0;
	int returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;

	for(i = 0 ; i < 4 ; i++)
	{
		if(returnStatus == EXIT_SUCCESS)
		{
			LogInfo( ( "Unsubscribe to the MQTT topic %.*s. Index : %d",
						TopicFilterLength[i],
						TopicFilter[i], i ) );
			returnStatus = unsubscribeFromTopic( InmqttContext, i );
            if(returnStatus == EXIT_SUCCESS)
            {
                mqttStatus = MQTT_ProcessLoop( InmqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

                if( mqttStatus != MQTTSuccess )
                {
                    returnStatus = EXIT_FAILURE;
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                                MQTT_Status_strerror( mqttStatus ) ) );
                }
            }
		}
	}
	return returnStatus;
}

static int subscribePublishLoop( MQTTContext_t * pMqttContext,
		bool * pClientSessionPresent )
{
	int returnStatus = EXIT_SUCCESS;
	bool mqttSessionEstablished = false, brokerSessionPresent;
	MQTTStatus_t mqttStatus = MQTTSuccess;
	uint32_t publishCount = 0;
	const uint32_t maxPublishCount = MQTT_PUBLISH_COUNT_PER_LOOP;
	bool createCleanSession = false;

	assert( pMqttContext != NULL );
	assert( pClientSessionPresent != NULL );

	/* A clean MQTT session needs to be created, if there is no session saved
	 * in this MQTT client. */
	createCleanSession = ( *pClientSessionPresent == true ) ? false : true;
	LogInfo(("pClientSessionPresent : %d\n", *pClientSessionPresent));
	LogInfo(("brokerSessionPresent : %d\n", brokerSessionPresent));
	/* Establish MQTT session on top of TCP+TLS connection. */
	LogInfo( ( "Creating an MQTT connection to %.*s.",
				AWS_IOT_ENDPOINT_LENGTH,
				AWS_IOT_ENDPOINT ) );

	/* Sends an MQTT Connect packet using the established TLS session,
	 * then waits for connection acknowledgment (CONNACK) packet. */
	returnStatus = establishMqttSession( pMqttContext, createCleanSession, &brokerSessionPresent, EX_IDENTIFIER );

	if( returnStatus == EXIT_SUCCESS )
	{
		/* Keep a flag for indicating if MQTT session is established. This
		 * flag will mark that an MQTT DISCONNECT has to be sent at the end
		 * of the demo, even if there are intermediate failures. */
		mqttSessionEstablished = true;

		/* Update the flag to indicate that an MQTT client session is saved.
		 * Once this flag is set, MQTT connect in the following iterations of
		 * this demo will be attempted without requesting for a clean session. */
		*pClientSessionPresent = true;

		/* Check if session is present and if there are any outgoing publishes
		 * that need to resend. This is only valid if the broker is
		 * re-establishing a session which was already present. */

		LogInfo(("pClientSessionPresent : %d\n", *pClientSessionPresent));
		LogInfo(("brokerSessionPresent : %d\n", brokerSessionPresent));
		if( brokerSessionPresent == true )
		{
			LogInfo( ( "An MQTT session with broker is re-established. "
						"Resending unacked publishes." ) );

			/* Handle all the resend of publish messages. */
			returnStatus = handlePublishResend( pMqttContext );
		}
		else
		{
			LogInfo( ( "A clean MQTT connection is established."
						" Cleaning up all the stored outgoing publishes.\n\n" ) );

			/* Clean up the outgoing publishes waiting for ack as this new
			 * connection doesn't re-establish an existing session. */
			cleanupOutgoingPublishes();
		}
	}

	if( returnStatus == EXIT_SUCCESS )
	{
		/* The client is now connected to the broker. Subscribe to the topic
		 * as specified in MQTT_EXAMPLE_TOPIC at the top of this file by sending a
		 * subscribe packet. This client will then publish to the same topic it
		 * subscribed to, so it will expect all the messages it sends to the broker
		 * to be sent back to it from the broker. This demo uses QOS1 in Subscribe,
		 * therefore, the Publish messages received from the broker will have QOS1. */
		LogInfo( ( "Subscribing to the MQTT topic %.*s.",
					MQTT_EXAMPLE_TOPIC_LENGTH,
					MQTT_EXAMPLE_TOPIC ) );
		returnStatus = subscribeToTopic( pMqttContext, 4 );
		mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

		if( mqttStatus != MQTTSuccess )
		{
			returnStatus = EXIT_FAILURE;
			LogError( ( "MQTT_ProcessLoop returned with status = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
		}
	}
#if 0
	if( returnStatus == EXIT_SUCCESS )
	{
		/* Process incoming packet from the broker. Acknowledgment for subscription
		 * ( SUBACK ) will be received here. However after sending the subscribe, the
		 * client may receive a publish before it receives a subscribe ack. Since this
		 * demo is subscribing to the topic to which no one is publishing, probability
		 * of receiving publish message before subscribe ack is zero; but application
		 * must be ready to receive any packet. This demo uses MQTT_ProcessLoop to
		 * receive packet from network. */

		mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

		if( mqttStatus != MQTTSuccess )
		{
			returnStatus = EXIT_FAILURE;
			LogError( ( "MQTT_ProcessLoop returned with status = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
		}

	}
#endif
	/* Check if recent subscription request has been rejected. globalSubAckStatus is updated
	 * in eventCallback to reflect the status of the SUBACK sent by the broker. */
	if( ( returnStatus == EXIT_SUCCESS ) && ( globalSubAckStatus == MQTTSubAckFailure ) )
	{
		/* If server rejected the subscription request, attempt to resubscribe to topic.
		 * Attempts are made according to the exponential backoff retry strategy
		 * implemented in retryUtils. */
		LogInfo( ( "Server rejected initial subscription request. Attempting to re-subscribe to topic %.*s.",
					MQTT_EXAMPLE_TOPIC_LENGTH,
					MQTT_EXAMPLE_TOPIC ) );
		returnStatus = handleResubscribe( pMqttContext, 4 );
	}

	if( returnStatus == EXIT_SUCCESS )
	{
		/* Publish messages with QOS1, receive incoming messages and
		 * send keep alive messages. */
		for( publishCount = 0; publishCount < maxPublishCount; publishCount++ )
		{
			LogInfo(("pClientSessionPresent : %d\n", *pClientSessionPresent));
			LogInfo(("brokerSessionPresent : %d\n", brokerSessionPresent));
			LogInfo( ( "Sending Publish to the MQTT topic %.*s.",
						MQTT_EXAMPLE_TOPIC_LENGTH,
						MQTT_EXAMPLE_TOPIC ) );
			//returnStatus = publishToTopic( pMqttContext );

			/* Calling MQTT_ProcessLoop to process incoming publish echo, since
			 * application subscribed to the same topic the broker will send
			 * publish message back to the application. This function also
			 * sends ping request to broker if MQTT_KEEP_ALIVE_INTERVAL_SECONDS
			 * has expired since the last MQTT packet sent and receive
			 * ping responses. */
			//mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

			/* For any error in #MQTT_ProcessLoop, exit the loop and disconnect
			 * from the broker. */
			if( mqttStatus != MQTTSuccess )
			{
				LogError( ( "MQTT_ProcessLoop returned with status = %s.",
							MQTT_Status_strerror( mqttStatus ) ) );
				returnStatus = EXIT_FAILURE;
				break;
			}

			LogInfo( ( "Delay before continuing to next iteration.\n\n" ) );

			/* Leave connection idle for some time. */
			sleep( DELAY_BETWEEN_PUBLISHES_SECONDS );
		}
	}

	if( returnStatus == EXIT_SUCCESS )
	{
		/* Unsubscribe from the topic. */
		LogInfo( ( "Unsubscribing from the MQTT topic %.*s.",
					MQTT_EXAMPLE_TOPIC_LENGTH,
					MQTT_EXAMPLE_TOPIC ) );
		returnStatus = unsubscribeFromTopic( pMqttContext, 4 );
	}

	if( returnStatus == EXIT_SUCCESS )
	{
		/* Process Incoming UNSUBACK packet from the broker. */
		mqttStatus = MQTT_ProcessLoop( pMqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );

		if( mqttStatus != MQTTSuccess )
		{
			returnStatus = EXIT_FAILURE;
			LogError( ( "MQTT_ProcessLoop returned with status = %s.",
						MQTT_Status_strerror( mqttStatus ) ) );
		}
	}

	/* Send an MQTT Disconnect packet over the already connected TCP socket.
	 * There is no corresponding response for the disconnect packet. After sending
	 * disconnect, client must close the network connection. */
	if( mqttSessionEstablished == true )
	{
		LogInfo( ( "Disconnecting the MQTT connection with %.*s.",
					AWS_IOT_ENDPOINT_LENGTH,
					AWS_IOT_ENDPOINT ) );

		if( returnStatus == EXIT_FAILURE )
		{
			/* Returned status is not used to update the local status as there
			 * were failures in demo execution. */
			( void ) disconnectMqttSession( pMqttContext );
		}
		else
		{
			returnStatus = disconnectMqttSession( pMqttContext );
		}
	}

	/* Reset global SUBACK status variable after completion of subscription request cycle. */
	globalSubAckStatus = MQTTSubAckFailure;

	return returnStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of demo.
 *
 * The example shown below uses MQTT APIs to send and receive MQTT packets
 * over the TLS connection established using OpenSSL.
 *
 * The example is single threaded and uses statically allocated memory;
 * it uses QOS1 and therefore implements a retransmission mechanism
 * for Publish messages. Retransmission of publish messages are attempted
 * when a MQTT connection is established with a session that was already
 * present. All the outgoing publish messages waiting to receive PUBACK
 * are resent in this demo. In order to support retransmission all the outgoing
 * publishes are stored until a PUBACK is received.
 */
void signal_handler(int signo)
{
    gLoop = 0;
}

void help()
{
    printf("Usage : ./mqtt_demo_mutual_auth [options] [message]\n");
    printf("options:\n");
    printf("-c, --cert <Certificate ID>\t\t\tCertificate ID를 설정합니다. (ex : abc123456)\n");
    printf("-C, --client <Client ID>\t\t\tClient Identifier를 설정합니다.\n");
    printf("-f, --fleet\t\t\tFleet Provisioning을 수행합니다.\n");
    printf("-h : 이 메시지를 출력합니다.\n");
    printf("-m, --message <JSON Payload>\t\t\tPublish Payload를 입력합니다.\n");
    printf("-p, --publish <1 : once / 2 : Loop>\t\t\tPublish 메시지를 전송합니다. -t 옵션을 사용하여 Topic을 입력해야합니다. (1 : 한 번 전송, 2 : 반복하여 전송)\n");
    printf("-s, --subscribe\t\t\tSubscribe 메시지를 전송합니다. -t 옵션을 사용하여 Topic을 입력해야합니다.\n");
    printf("-t, --topic <Topic Name>\t\t\tPublish / Subscribe할 Topic을 설정합니다.(ex : client/test/topic)\n");
    
}

void optionCheck()
{
    int count = 0, i = 0;

    for(i = 0 ; i < 7 ; i++)
    {
        if(optFlag[i] != 0)
            count++;
    }
    if(count == 0)
    {
        help();
        exit(0);
    }

    if(optFlag[OPT_S] == 1)
    {
        if(optFlag[OPT_P] != 0)
        {
            help();
            exit(0);
        }

        if(optFlag[OPT_T] != 1)
        {
            help();
            exit(0);
        }        
        
        if(optFlag[OPT_F] != 0)
        {
            help();
            exit(0);
        }
    }

    if(optFlag[OPT_P] > 0)
    {
        if(optFlag[OPT_T] != 1){
            help();
            exit(0);
        }

        if(optFlag[OPT_S] != 0){
            help();
            exit(0);
        }

        if(optFlag[OPT_F] != 0){
            help();
            exit(0);
        }
    }

    if(optFlag[OPT_F] != 0)
    {
        if(optFlag[OPT_S] != 0){
            help();
            exit(0);
        }
        
        if(optFlag[OPT_P] != 0){
            help();
            exit(0);
        }
    }
}


int main( int argc, char ** argv )
{
	int returnStatus = EXIT_SUCCESS;
	MQTTContext_t mqttContext = { 0 };
	MQTTStatus_t mqttStatus = MQTTSuccess;
	NetworkContext_t networkContext = { 0 };
	OpensslParams_t opensslParams = { 0 };
    
	bool clientSessionPresent = false, createCleanSession = false;
	bool brokerSessionPresent, mqttSessionEstablished = false;
	struct timespec tp;
    int c; // getopt options


	signal(SIGINT, signal_handler);

    while(1)
    {
        static struct option long_options[] = 
        {
            {"cert", required_argument, 0, 'c'},
            {"client", required_argument, 0, 'C'},
            {"fleet", no_argument, 0, 'f'},
            {"help", no_argument, 0, 'h'},
            {"message", required_argument, 0, 'm'},
            {"pub", no_argument, 0, 'p'},
            {"sub", no_argument, 0, 's'},
            {"topic", required_argument, 0, 't'}
        };
    

        int option_index = 0;

        c = getopt_long(argc, argv, "c:C:fhm:p:st:", long_options, &option_index);

        if(c == -1)
            break;
    
        switch(c)
        {
            case 'c':
                if(strlen(optarg) > 5)
                {
                    optFlag[OPT_C] = 1;
                    strcpy(defCertfileId, optarg);
                }
                else
                    exit(0);
            break;
            case 'C':
                if(strlen(optarg) > 2)
                {
                    optFlag[OPT_CL] = 1;
                    strcpy(uuidStr, optarg);
                }
                else
                    exit(0);
            break;
            case 'f':
                optFlag[OPT_F] = 1;
            break;
            case 'h':
                help();
                exit(0);
            break;
            case 'm':
            {
                JSONStatus_t jsonResult = 0;
                
                if(strlen(optarg) > 0)
                {
                    jsonResult = JSON_Validate(optarg, strlen(optarg));
                    if(jsonResult != JSONSuccess)
                        exit(0);
                    else
                    {
                        optFlag[OPT_M] = 1;
                        strcpy(MqttExMessage[3], optarg);
                        MqttExMessageLength[3] = strlen(optarg);
                    }
                }
                else
                {
                    strcpy(MqttExMessage[3], "{}");
                    MqttExMessageLength[3] = strlen(MqttExMessage[3]);
                }
            }
            break;
            case 'p':
                optFlag[OPT_P] = atoi(optarg);
            break;
            case 's':
                optFlag[OPT_S] = 1;
            break;
            case 't':
                if(strlen(optarg) > 0)
                {
                    optFlag[OPT_T] = 1;
                    strcpy(TopicFilter[USER_PUBSUB], optarg);
                    TopicFilterLength[USER_PUBSUB] = strlen(optarg);
                }            
            break;
            case '?':
                help();
                exit(0);
            break;
            default:
                help();
                exit(0);
            break;
        }
    }
    optionCheck();

	gSessionPresent = &clientSessionPresent;
	// Initialize UUID 
	if(optFlag[OPT_CL] != 1)
	{
		FILE *fp = fopen(UUID_FILE_PATH, "r");
		char buffer[40] = {0, };
		int count = 0;

		while(feof(fp) == 0)
		{
			count = fread(buffer, sizeof(buffer), 1, fp);
			buffer[strlen(buffer)-1] = '\0';
			strcpy(uuidStr, buffer);
		}
		fclose(fp);
	}
	
	//strcpy(uuidStr, "1234567-abcde-fghij-klmno-1234567abc-TLS350");
	/* Set the pParams member of the network context with desired transport. */
	networkContext.pParams = &opensslParams;
    memcpy(&gNetworkContext, &networkContext, sizeof(NetworkContext_t));
	/* Seed pseudo random number generator (provided by ISO C standard library) for
	 * use by retry utils library when retrying failed network operations. */

	/* Get current time to seed pseudo random number generator. */
	( void ) clock_gettime( CLOCK_REALTIME, &tp );
	/* Seed pseudo random number generator with nanoseconds. */
	srand( tp.tv_nsec );
	// Subscription Topic initialize
	returnStatus = initSubscriptionList();
	initPublishMessage();
	// MQTT 라이브러리를 초기화 한다. 본 예제에선 단 한번만 MQTT 라이브러리의 초기화를 필요로 한다.
	returnStatus = initializeMqtt( &mqttContext, &networkContext );

	if( returnStatus == EXIT_SUCCESS )
	{
		returnStatus = connectToServerWithBackoffRetries( &networkContext, EX_IDENTIFIER );
		if( returnStatus == EXIT_FAILURE )
		{
			/* Log error to indicate connection failure after all
			 * reconnect attempts are over. */
			LogError( ( "Failed to connect to MQTT broker %.*s.",
						AWS_IOT_ENDPOINT_LENGTH,
						AWS_IOT_ENDPOINT ) );
		}

		createCleanSession = (clientSessionPresent == true) ? false : true;
		returnStatus = establishMqttSession(&mqttContext, createCleanSession, &brokerSessionPresent, EX_IDENTIFIER);

		if(returnStatus == EXIT_SUCCESS)
		{
			mqttSessionEstablished = true;
			clientSessionPresent = true;

			if(brokerSessionPresent == true)
			{
				LogInfo( ( "An MQTT session with broker is re-established. "
							"Resending unacked publishes." ) );
				returnStatus = handlePublishResend(&mqttContext);
			}
			else
			{
				LogInfo( ( "A clean MQTT connection is established."
							" Cleaning up all the stored outgoing publishes.\n\n" ) );

				/* Clean up the outgoing publishes waiting for ack as this new
				 * connection doesn't re-establish an existing session. */
				cleanupOutgoingPublishes();
			}
		}

        if(optFlag[OPT_F] == 1)
        {
            returnStatus = subscribeFleetTopic(&mqttContext, &mqttStatus);

            publishToTopic(&mqttContext, PROVISIONING_CC, 0);
        }
        else if(optFlag[OPT_S] == 1)
        {
            returnStatus = subscribeToTopic(&mqttContext, USER_PUBSUB);

            if(returnStatus == EXIT_SUCCESS)
            {
                mqttStatus = MQTT_ProcessLoop(&mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS);

                if(mqttStatus != MQTTSuccess)
                {
                    returnStatus = EXIT_FAILURE;
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
                }
            }
        }
        else if(optFlag[OPT_P] == 1)
        {
            returnStatus = publishToTopic(&mqttContext, USER_PUBSUB, 3);
            mqttStatus = MQTT_ProcessLoop( &mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );
                
            if( mqttStatus != MQTTSuccess)
            {
                /* Log message indicating an iteration completed successfully. */
                LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
                returnStatus = EXIT_FAILURE;
                LogInfo( ( "Demo completed successfully." ) );
            }
            gLoop = 0;
        }

        while(gLoop)
        {
            // MQTT 브로커에 연결을 시도한다. 만약 연결이 실패했을 경우 Timeout 이후 재시도한다.
            // EXIT_FAILURE 발생 시 TCP Connection에 실패한 것을 의미함.
            if(set_in_progress == SET_COMPLETE)
            {
                #if 0
                if(optFlag[OPT_F] == 1 || optFlag[OPT_S] == 1)
                {
                    if((returnStatus == EXIT_SUCCESS) && (globalSubAckStatus == MQTTSubAckFailure))
                    {
                        LogInfo( ( "Server rejected initial subscription request. Attempting to re-subscribe to topic %.*s.",
                            MQTT_EXAMPLE_TOPIC_LENGTH,
                            MQTT_EXAMPLE_TOPIC ) );
                        returnStatus = handleResubscribe( pMqttContext );
                    }
                }
                #endif
                if(optFlag[OPT_P] == 2)
                    returnStatus = publishToTopic(&mqttContext, USER_PUBSUB, 3);
                mqttStatus = MQTT_ProcessLoop( &mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );
                
                if( mqttStatus != MQTTSuccess)
                {
                    /* Log message indicating an iteration completed successfully. */
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
                    returnStatus = EXIT_FAILURE;
                    LogInfo( ( "Demo completed successfully." ) );
                }
                LogInfo( ( "Short delay before starting the next iteration....\n" ) );
            }
            sleep( 1 );
        }

        if(optFlag[OPT_F] == 1 || optFlag[OPT_S] == 1)
        {
            if(returnStatus == EXIT_SUCCESS)
            {
                if(optFlag[OPT_F] == 1)
                    returnStatus = unsubscribeFromTopic(&mqttContext, OPENWORLD);
                else if(optFlag[OPT_S] == 1)
                    returnStatus = unsubscribeFromTopic(&mqttContext, USER_PUBSUB);

                if(returnStatus == EXIT_SUCCESS)
                {
                    mqttStatus = MQTT_ProcessLoop(&mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS);

                    if(mqttStatus != MQTTSuccess)
                    {
                        returnStatus = EXIT_FAILURE;
                        LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
                    }
                }
            }
        }
		
	}
	/* Send an MQTT Disconnect packet over the already connected TCP socket.
	 * There is no corresponding response for the disconnect packet. After sending
	 * disconnect, client must close the network connection. */
	if( mqttSessionEstablished == true )
	{
		LogInfo( ( "Disconnecting the MQTT connection with %.*s.",
					AWS_IOT_ENDPOINT_LENGTH,
					AWS_IOT_ENDPOINT ) );

		if( returnStatus == EXIT_FAILURE )
		{
			/* Returned status is not used to update the local status as there
			 * were failures in demo execution. */
			( void ) disconnectMqttSession( &mqttContext );
		}
		else
		{
			returnStatus = disconnectMqttSession( &mqttContext );
		}

        /* End TLS session, then close TCP connection. */
		( void ) Openssl_Disconnect( &networkContext );
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/
