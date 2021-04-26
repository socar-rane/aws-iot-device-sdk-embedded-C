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

/*
 * This demonstration downloads files from URLs present in job documents
 * received from the AWS IoT Jobs service. It shows the use of the jobs
 * library with the Mosquitto client MQTT library for communicating with the
 * AWS IoT Jobs service.  More details are available in the usage function
 * in this file.  Note: This demo focuses on use of the jobs library;
 * a thorough explanation of libmosquitto is beyond the scope of the demo.
 */

/* C standard includes. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* POSIX includes. */
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <err.h>
#include <getopt.h>

#include <mosquitto.h>
#if ( LIBMOSQUITTO_VERSION_NUMBER < 1004010 )
    #error Please use libmosquitto at version 1.4.10 or higher.
#endif

#include "demo_config.h"
#include "core_json.h"

/*-----------------------------------------------------------*/

/**
 * @brief MQTT server port number.
 *
 * AWS IoT Core uses this port for MQTT over TLS.
 */
#define DEFAULT_MQTT_PORT       ( 8883 )

/**
 * @brief Certificate Authority Directory.
 *
 * Debian and Ubuntu use this directory for CA certificates.
 */
#define DEFAULT_CA_DIRECTORY    "/etc/ssl/certs"

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) name for AWS IoT MQTT.
 */
#define ALPN_NAME               "x-amzn-mqtt-ca"
#define UUID_FILE_PATH "/proc/sys/kernel/random/uuid"
#define NETWORK_BUFFER_SIZE    (4096)

/*-----------------------------------------------------------*/

/**
 * @brief Describe program usage on stderr.
 *
 * @param[in] programName the value of argv[0]
 */
static void usage( const char * programName )
{
    fprintf( stderr,
             "\nThis demonstration downloads files from URLs received via AWS IoT Jobs.\n"
             "(See https://docs.aws.amazon.com/iot/latest/developerguide/iot-jobs.html for an introduction.)\n"
             "\nCreating a job may be done with the AWS console, or the aws cli, e.g.,\n"
             "$ aws iot create-job --job-id t12 --targets arn:aws:iot:us-east-1:1234567890:thing/device1 \\\n"
             "  --document '{\"url\":\"https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.8.5.tar.xz\"}'\n"
             "\nTo execute the job, on the target device run the demo program with the device's credentials, e.g.,\n"
             "$ %s -n device1 -h abcdefg123.iot.us-east-1.amazonaws.com \\\n"
             "  --certfile bbaf123456-certificate.pem.crt --keyfile bbaf123456-private.pem.key\n"
             "\nTo exit the program, type Control-C, or send a SIGTERM signal.\n",
             programName );
    fprintf( stderr,
             "\nOutput should look like the following:\n"
             "Connecting to abcdefg123.iot.us-east-1.amazonaws.com, port 8883.\n"
             "Client device1 sending CONNECT\n"
             "Client device1 received CONNACK\n"
             "Client device1 sending SUBSCRIBE (Mid: 1, Topic: $aws/things/device1/jobs/start-next/accepted, QoS: 1)\n"
             "Client device1 received SUBACK\n"
             "[...]\n"
             "starting job id: t12\n"
             "sending first update\n" );
    fprintf( stderr,
             "\nIf the output does not show a successful connection, check in the AWS console\n"
             "that the client certificate is associated with the target thing and is activated.\n"
             "Also check that the Amazon Root CA certificates are in your system's trust store.\n"
             "Note, you can provide a CA certificate file directly as a command-line argument.\n" );
    fprintf( stderr,
             "\nThis demonstration exits on most error conditions.  One way to retry while avoiding\n"
             "throttling due to excessive reconnects is to periodically relaunch from cron(8).\n"
             "Given a shell script wrapper with the necessary arguments called download, the following\n"
             "line in /etc/crontab would start the downloader unless it is already running.\n"
             "This tries every 3 minutes, with an additional random delay up to 2 minutes.\n\n"
             "*/3 * * * *  root  exec 9> /tmp/lock && flock -n 9 && sleep $((RANDOM %% 120)) && download\n"
             );
    fprintf( stderr,
             "\nusage: %s "
             "[-o] -n name -h host [-p port] {--cafile file | --capath dir} --certfile file --keyfile file [--pollinv seconds] [--updateinv seconds]\n"
             "\n"
             "-o : run once, exit after the first job is finished.\n"
             "-n : thing name\n"
             "-h : mqtt host to connect to.\n"
             "-p : network port to connect to. Defaults to %d.\n",
             programName, DEFAULT_MQTT_PORT );
    fprintf( stderr,
             "--cafile    : path to a file containing trusted CA certificates to enable encrypted\n"
             "              certificate based communication.\n"
             "--capath    : path to a directory containing trusted CA certificates to enable encrypted\n"
             "              communication.  Defaults to %s.\n"
             "--certfile  : client certificate for authentication in PEM format.\n"
             "--keyfile   : client private key for authentication in PEM format.\n",
             DEFAULT_CA_DIRECTORY );
    fprintf( stderr,
             "--pollinv   : after this many idle seconds, request a job.\n"
             "              Without this option and a positive value, no polling is done.\n"
             "--updateinv : after this many seconds running a job, resend the current status to the jobs service.\n"
             "              Without this option and a positive value, status is not resent.\n\n"
             );
}

/*-----------------------------------------------------------*/

/**
 * @brief The several states of execution.
 */
typedef enum
{
    None = 0, /* no current job */
    Ready,    /* job document received and parsed */
    Running,  /* download in progress */
    Cancel,   /* cancel due to failed update */
} runStatus_t;

/**
 * @brief All runtime parameters and state.
 */
typedef struct
{
    /* thing name */
    char * name;
    size_t nameLength;
    /* connection parameters */
    char * host;
    uint16_t port;
    char * cafile;
    char * capath;
    char * certfile;
    char * keyfile;
    uint32_t pollinv;   /* 0 (default) disables polling for new jobs */
    uint32_t updateinv; /* 0 (default) disables periodic resending of status */
    /* flags */
    bool runOnce;
    /* callback-populated values */
    int connectError;
    int subscribeQOS;
    /* mosquitto library handle */
    struct mosquitto * m;
    /* job parameters received via MQTT */
    char * jobid;
    size_t jobidLength;
    char * url;
    size_t urlLength;
    /* internal state tracking */
    runStatus_t runStatus;
    char * report;
    time_t lastPrompt;
    time_t lastUpdate;
    bool forcePrompt;
    bool forceUpdate;
    pid_t child;
} handle_t;

/*-----------------------------------------------------------*/

/**
 * @brief Populate a handle with default values.
 *
 * @param[in] p runtime state handle
 */
void initHandle( handle_t * p, uint8_t flag );

/**
 * @brief Validate the values within a handle.
 *
 * @param[in] h runtime state handle
 *
 * @return true if necessary arguments are present and valid;
 * false otherwise
 */
static bool requiredArgs( handle_t * h );

/**
 * @brief Populate a handle from command line arguments.
 *
 * @param[in] h runtime state handle
 * @param[in] argc count of arguments
 * @param[in] argv array of arguments
 *
 * @return false if there is an unrecognized switch;
 * true otherwise
 */
static bool parseArgs( handle_t * h,
                       int argc,
                       char * argv[] );

/**
 * @brief The libmosquitto callback for connection result.
 *
 * @param[in] m unused
 * @param[in] p runtime state handle
 * @param[in] rc connection result code
 */
static void on_connect( struct mosquitto * m,
                        void * p,
                        int rc );

/**
 * @brief Connect to AWS IoT Core MQTT broker.
 *
 * @param[in] h runtime state handle
 *
 * @return true if a connection is established;
 * false otherwise
 */
static bool connect( handle_t * h );

/**
 * @brief Disconnect from AWS IoT Core MQTT broker.
 *
 * @param[in] h runtime state handle
 */
static void closeConnection( handle_t * h );

/**
 * @brief The libmosquitto callback for subscription result.
 *
 * @param[in] m unused
 * @param[in] p runtime state handle
 * @param[in] mid unused
 * @param[in] qos_count count of granted subscriptions
 * @param[in] granted_qos the granted QOS subscription values
 */
static void on_subscribe( struct mosquitto * m,
                          void * p,
                          int mid,
                          int qos_count,
                          const int * granted_qos );


/**
 * @brief Subscribe to topic.
 *
 * @param[in] h runtime state handle
 * @param[in] in_topic the desired topic
 *
 * @return true if the broker granted the subscription;
 * false otherwise
 */
static bool subscribe( handle_t * h, char *in_topic);

/**
 * @brief Publish to topic.
 *
 * @param[in] h runtime state handle
 * @param[in] in_topic the desired topic
 * @param[in] in_message an MQTT publish message
 * @return true if the broker granted the publish;
 * false otherwise
 */
static bool publish( handle_t *h, char *in_topic, char *in_message);

/**
 * @brief The libmosquitto callback for a received publish message.
 *
 * @param[in] m unused
 * @param[in] p runtime state handle
 * @param[in] message an MQTT publish message
 *
 * This checks if a message corresponds to a Jobs API, and transitions
 * runtime state based on the API and current state.
 */
int on_message( struct mosquitto * m,
                 void * p,
                 const struct mosquitto_message * message );
/**
 * @brief The libmosquitto callback for log messages.
 *
 * @param[in] m unused
 * @param[in] p unused
 * @param[in] level unused
 * @param[in] log the message to print
 */
static void on_log( struct mosquitto * m,
                    void * p,
                    int level,
                    const char * log );

/**
 * @brief Generic signal handler.
 *
 * @param[in] signal the caught signal value
 */
static void catch( int signal );

/**
 * @brief Setup signal handling and libmosquitto.
 *
 * @param[in] h runtime state handle
 *
 * @return false if a step failed;
 * true otherwise
 */
static bool setup( handle_t * h );

/**
 * @brief Disconnect and clean up.
 *
 * @param[in] x unused
 * @param[in] p runtime state handle
 */
static void teardown( int x,
                      void * p );

/**
 * @brief Subscribe Fleet Provisioning all topics
 * 
 * @param[in] h runtime state handle
 */

static bool subscribeFleetProvisioning(handle_t *h);

/**
 * @brief Unubscribe Fleet Provisioning all topics
 * 
 * @param[in] h runtime state handle
 */

static bool unsubscribeFleetProvisioning(handle_t *h);

/**
 * @brief Find topic index function
 */ 
int findTopicIndex(char *in_topic);

/**
 * @brief Parse Certificate And Keys
 * 
 * @param[in] pBuffer Incoming Publish Payload
 * @param[in] pBufferLength Incoming Publish Payload Length
 */

static bool assemble_certificates(char *pBuffer, size_t pBufferLength);

/**
 * @brief Convert JSON to Cert file functions
 * 
 * @param[in] inStr Input JSON String
 * @param[in] inStrLength Input JSON String length
 * @param[in] fp cert file descripter
 */

static int JSONtoCertFile(char *inStr, int inStrLength, FILE *fp);

/**
 * @brief Register new things
 * 
 * @param[in] token  Input Certificates Ownership Token
 * @param[in] tokenLength Input Token Length
 */ 
static bool registerThing(char *token, size_t tokenLength);

/**
 * @brief Unsubscribe from Topic
 * 
 * @param[in] h runtime state handle
 * @param[in] in_topic unsubscribe topic
 */ 
static bool unsubscribe( handle_t *h, char *in_topic);

/**
 * @brief Create UUID String
 */ 
static void createUUIDStr();

static bool changeConnectionInformation(handle_t *h);

/**
 * @brief Log an informational message.
 */
#define info    warnx

/**
 * @brief Format a JSON status message.
 *
 * @param[in] x one of "IN_PROGRESS", "SUCCEEDED", or "FAILED"
 */
#define makeReport_( x )    "{\"status\":\"" x "\"}"
#define TOPIC_LENGTH		8

// Topic Identifier
enum
{
	TEMPLATE_REJECT,        // Provisioning Template Reject Topic
	CERTIFICATE_REJECT,     // Create Certificate Reject Topic
	TEMPLATE_ACCEPT,        // Provisioning Template Accept Topic
	CERTIFICATE_ACCEPT,     // Create Certificate Accept Topic
	OPENWORLD,              // Create New Session Example Topic
	PROVISIONING_CC,        // Provisioning Create Certificate Topic
	PROVISIONING_TT,         // Provisioning Template Topic
    USER_PUBSUB
};

enum
{
    SET_COMPLETE,           // Set Complete Flag
    SET_IN_PROGRESS,        // Set In Progress Flag
    SET_FAILED,             // Set Failed Flag
    RESERVED                // Reserved
};

/**
 * @brief Initialize Topic name
 */

char TopicFilter[TOPIC_LENGTH][256] = {
	TEMPLATE_REJECT_TOPIC,
	CERTIFICATE_REJECT_TOPIC,
	TEMPLATE_ACCEPT_TOPIC,
	CERTIFICATE_ACCEPT_TOPIC,
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
	sizeof("openworld")-1,
	PROVISIONING_CC_LENGTH,
	PROVISIONING_TT_LENGTH,
    0
};

char MqttExMessage[4][1024] = {
	"{}",
	"{}",
    "{\"service_response\":\"##### RESPONSE FROM PREVIOUSLY FORBIDDEN TOPIC #####\"}",
    "{}"
};

/// @brief Create Certificate Parsing query Key
char queryCertificate[4][64] = 
{
	"certificateId",
	"certificatePem",
	"privateKey",
	"certificateOwnershipToken"
};

bool completeFlag[2] = {false, false};
/// @brief Endpoint Device UUID
char uuidStr[64] = {0,};

/// @brief New Session Client Identifier 
char gClientId[128] = {0,};

/// @brief Set in progress Flag
int set_in_progress = 0;

/**
 * @brief Publish Payload Message Length Array
 */ 
uint16_t MqttExMessageLength[4] = {0, };

/// @brief Global Certificate ID
char gCertificateId[16] = {0,};

/// @brief Global Endpoint Address
char gEndpointAddress[64] = {0,};

/// @brief Global CA Certificate File
char gCAFileName[64] = {0,};

/// @brief Global Certificate File
char gCertFile[64] = {0,};

/// @brief Global Private Key File
char gPrivateKey[64] = {0,};

/*-----------------------------------------------------------*/

void initHandle( handle_t * p, uint8_t flag )
{
    info("initHandle\n");
    assert( p != NULL );
    info("initHandle start\n");
    handle_t h = { 0 };

    #ifdef AWS_IOT_ENDPOINT
        h.host = AWS_IOT_ENDPOINT;
    #endif

    switch(flag)
    {
        case 1:
            #ifdef CLIENT_CERT_PATH
                h.certfile = CLIENT_CERT_PATH;
            #endif

            #ifdef CLIENT_PRIVATE_KEY_PATH
                h.keyfile = CLIENT_PRIVATE_KEY_PATH;
            #endif

            #ifdef ROOT_CA_CERT_PATH
                h.cafile = ROOT_CA_CERT_PATH;
            #else
                h.capath = DEFAULT_CA_DIRECTORY;
            #endif
        break;
        case 2:
        {
            h.name = gClientId;
            h.nameLength = strlen(gClientId);
            h.host = gEndpointAddress;
            char fileName[128] = {0,};
                h.certfile = gCertFile;
                info("connect function cert file : %s\n", h.certfile);

                h.keyfile = gPrivateKey;
                info("connect function keyfile : %s\n", h.keyfile);

                h.cafile = gCAFileName;
                //h.capath = "./certificates";
        }
        break;
    }

    h.port = DEFAULT_MQTT_PORT;

    h.runOnce = false;

    /* initialize to -1, set by on_connect() to 0 or greater */
    h.connectError = -1;
    /* initialize to -1, set by on_subscribe() to 0 or greater */
    h.subscribeQOS = 1;

    *p = h;
}

/*-----------------------------------------------------------*/

static bool requiredArgs( handle_t * h )
{
    bool ret = true;
    struct stat s;

    assert( h != NULL );

#define checkString( x )                               \
    if( ( h->x == NULL ) || ( h->x[ 0 ] == '\0' ) )    \
    {                                                  \
        ret = false;                                   \
        warnx( "%s argument must not be empty", # x ); \
    }

    checkString( name );
    checkString( host );
    checkString( certfile );
    checkString( keyfile );

#define checkPath( x )                                                            \
    if( ( h->x != NULL ) && ( h->x[ 0 ] != '\0' ) && ( stat( h->x, &s ) == -1 ) ) \
    {                                                                             \
        ret = false;                                                              \
        warn( "cannot access '%s'", h->x );                                       \
        h->x = NULL;                                                              \
    }

    checkPath( certfile );
    checkPath( keyfile );
    checkPath( cafile );

    checkPath( capath );

    /* use value in struct stat s from last check */
    if( ( h->capath != NULL ) && ( h->capath[ 0 ] != '\0' ) && ( !S_ISDIR( s.st_mode ) ) )
    {
        ret = false;
        warnx( "not a directory: %s", h->capath );
    }

    return ret;
}

/*-----------------------------------------------------------*/

static bool parseArgs( handle_t * h,
                       int argc,
                       char * argv[] )
{
    bool ret = true;

    assert( h != NULL );

    if( argc == 1 )
    {
        ret = false;
        usage( argv[ 0 ] );
    }

    while( ret == true )
    {
        int c, option_index = 0;
        long x;
        static struct option long_options[] =
        {
            { "once",      no_argument,       NULL, 'o' },
            { "name",      required_argument, NULL, 'n' },
            { "host",      required_argument, NULL, 'h' },
            { "port",      required_argument, NULL, 'p' },
            { "cafile",    required_argument, NULL, 'f' },
            { "capath",    required_argument, NULL, 'd' },
            { "certfile",  required_argument, NULL, 'c' },
            { "keyfile",   required_argument, NULL, 'k' },
            { "pollinv",   required_argument, NULL, 'P' },
            { "updateinv", required_argument, NULL, 'u' },
            { "help",      no_argument,       NULL, '?' },
            { NULL,        0,                 NULL, 0   }
        };

        c = getopt_long( argc, argv, "on:h:p:P:u:f:d:c:k:?",
                         long_options, &option_index );

        if( c == -1 )
        {
            break;
        }

        switch( c )
        {
            case 'o':
                h->runOnce = true;
                break;

            case 'n':
                h->name = optarg;
                h->nameLength = strlen( optarg );
                break;

            case 'h':
                h->host = optarg;
                strcpy(gEndpointAddress, h->host);
                break;

#define optargToInt( element, min, max )                \
    x = strtol( optarg, NULL, 0 );                      \
                                                        \
    if( ( x > min ) && ( x <= max ) )                   \
    {                                                   \
        h->element = x;                                 \
    }                                                   \
    else                                                \
    {                                                   \
        ret = false;                                    \
        warnx( "bad %s value: %s", # element, optarg ); \
    }

            case 'p':
                optargToInt( port, 0, 0xFFFF );
                break;

            case 'P':
                optargToInt( pollinv, 0, INTERVAL_MAX );
                break;

            case 'u':
                optargToInt( updateinv, 0, INTERVAL_MAX );
                break;

            case 'f':
                h->cafile = optarg;
                h->capath = NULL;
                strcpy(gCAFileName, h->cafile);
                break;

            case 'd':
                h->capath = optarg;
                break;

            case 'c':
                h->certfile = optarg;
                break;

            case 'k':
                h->keyfile = optarg;
                break;

            case '?':
            default:
                ret = false;
                usage( argv[ 0 ] );
        }
    }

    if( optind < argc )
    {
        ret = false;
        usage( argv[ 0 ] );
    }

    if( ret == true )
    {
        ret = requiredArgs( h );
    }

    return ret;
}


/*-----------------------------------------------------------*/

static bool registerThing(char *token, size_t tokenLength)
{
	JSONStatus_t jsonResult;
    info("registerThing called\n");
	char parseToken[1024] = {0,};
	strncpy(parseToken, token, sizeof(char)*tokenLength);
	sprintf(MqttExMessage[1], "{\"certificateOwnershipToken\":\"%s\",\"parameters\":{\"SerialNumber\":\"%s\"}}",parseToken, uuidStr);
	MqttExMessageLength[1] = strlen(MqttExMessage[1]);

	jsonResult = JSON_Validate(MqttExMessage[1], MqttExMessageLength[1]);

	if(jsonResult == JSONSuccess)
		return true;
	else
		return false;
}

/*-----------------------------------------------------------*/

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

/*-----------------------------------------------------------*/

static bool assemble_certificates(char *pBuffer, size_t pBufferLength)
{
	char tempId[16] = {0,}, certificateId[16] = {0,};
	char certFileName[36] = {0,}, privateFileName[36] = {0,};
	char payloadBuffer[NETWORK_BUFFER_SIZE];
	
	int convertResult = 0;
	JSONStatus_t jsonResult;
	size_t valueLength;
	size_t queryLength = strlen(queryCertificate[0]);
	char *value;

	strncpy(payloadBuffer, pBuffer, pBufferLength);
    info("JSON Validation\n");
	jsonResult = JSON_Validate(pBuffer, pBufferLength);

	if(jsonResult == JSONSuccess)
	{
        info("JSON Search 1\n");
		jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[0], queryLength,
			&value, &valueLength);
		if(jsonResult == JSONSuccess)
		{
			memcpy(tempId, value, 10);
			memcpy(certificateId, tempId, 10);
			memcpy(gCertificateId, certificateId, 10);
			memset(payloadBuffer, 0, sizeof(char) * pBufferLength);
			strncpy(payloadBuffer, pBuffer, sizeof(char)*pBufferLength);

			// Cert Key Parsing
			queryLength = strlen(queryCertificate[1]);
            info("JSON Search 2\n");
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[1], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				sprintf(certFileName, "%s/%s-certificate.pem.crt", CERTFILE_PATH, certificateId);
				strcpy(gCertFile, certFileName);
                fp = fopen(certFileName, "w");
				
				convertResult = JSONtoCertFile(value, valueLength, fp);
				fclose(fp);
			}
			else
			{
				errx(1, "JSON Search Error\n");
			}
            info("JPrivate Key Parsing\n");
			// Private Key Parsing
			queryLength = strlen(queryCertificate[2]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[2], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				sprintf(privateFileName, "%s/%s-private.pem.key", CERTFILE_PATH, tempId);
                strcpy(gPrivateKey, privateFileName);
				fp = fopen(privateFileName, "w");
				convertResult = JSONtoCertFile(value, valueLength, fp);
				fclose(fp);
			}

			queryLength = strlen(queryCertificate[3]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[3], queryLength,
				&value, &valueLength);
            info("certificate Ownership Parsing\n");
			// certificate Ownership Parsing
			if(jsonResult == JSONSuccess)
			{
				convertResult = registerThing(value, valueLength);
				
                if(convertResult == false)
                {
                    errx(1, "Registration new service failed\n");
                    return false;
                }
                else
                {
                    info("assemble certificates complete!\n");
                    return true;
                }
			}
		}
		else
		{
			errx(1, "JSON Search Error\n");
            return false;
		}
	}
	else
	{
		errx(1, "JSON Validation Error\n");
        return false;
	}
}

/*-----------------------------------------------------------*/

static void on_connect( struct mosquitto * m,
                        void * p,
                        int rc )
{
    handle_t * h = p;

    assert( h != NULL );

    info("connection error : %d\n", h->connectError);

    h->connectError = rc;
}

/*-----------------------------------------------------------*/

static bool connect( handle_t * h )
{
    int ret = MOSQ_ERR_SUCCESS;
    size_t i;

    assert( h != NULL );
    assert( h->m != NULL );

    info("cafile : %s\n", h->cafile);
    info("capath : %s\n", h->capath);
    info("certfile : %s\n", h->certfile);
    info("keyfile : %s\n", h->keyfile);

    assert( h->connectError == -1 );

    if( h->port == 443 )
    {
        #if ( LIBMOSQUITTO_VERSION_NUMBER >= 1006000 )
            ret = mosquitto_string_option( h->m, MOSQ_OPT_TLS_ALPN, ALPN_NAME );
        #else
            warnx( "ALPN (port 443) is not supported by libmosquitto before version 1.6" );
            ret = MOSQ_ERR_INVAL;
        #endif
    }

    if( ret == MOSQ_ERR_SUCCESS )
    {
        ret = mosquitto_tls_set( h->m, h->cafile, h->capath, h->certfile, h->keyfile, NULL );
    }

    if( ret == MOSQ_ERR_SUCCESS )
    {
        info( "Connecting to %s, port %d.", h->host, h->port );
        ret = mosquitto_connect( h->m, h->host, h->port, MQTT_KEEP_ALIVE );
    }

    /* expect the on_connect() callback to update h->connectError */
    for( i = 0; ( i < MAX_LOOPS ) &&
         ( ret == MOSQ_ERR_SUCCESS ) &&
         ( h->connectError == -1 ); i++ )
    {
        ret = mosquitto_loop( h->m, MQTT_SHORT_WAIT_TIME, 1 );
    }

    if( h->connectError > 0 )
    {
        warnx( "%s", mosquitto_connack_string( h->connectError ) );
    }
    else if( ret != MOSQ_ERR_SUCCESS )
    {
        warnx( "connect: %s", mosquitto_strerror( ret ) );
    }

    return h->connectError == 0 ? true : false;
}

/*-----------------------------------------------------------*/

static void closeConnection( handle_t * h )
{
    assert( h != NULL );

    if( h->m != NULL )
    {
        int ret = mosquitto_disconnect( h->m );

        if( ret != MOSQ_ERR_SUCCESS )
        {
            warnx( "closeConnection: %s", mosquitto_strerror( ret ) );
        }
    }
}

/*-----------------------------------------------------------*/

static void on_subscribe( struct mosquitto * m,
                          void * p,
                          int mid,
                          int qos_count,
                          const int * granted_qos )
{
    handle_t * h = p;

    assert( h != NULL );
    assert( granted_qos != NULL );
    assert( qos_count == 1 );

    info("Client Received subscription message\n");

    /* subscribe() is called with a single topic. */
    h->subscribeQOS = granted_qos[ 0 ];
}

/*-----------------------------------------------------------*/

static bool unsubscribe( handle_t *h, char *in_topic)
{
    int ret;
    size_t i;

    assert( h != NULL );
    assert( MQTT_QOS <= 2 );

    ret = mosquitto_unsubscribe(h->m, NULL, in_topic);

    for( i = 0; ( i < MAX_LOOPS ) &&
         ( ret == MOSQ_ERR_SUCCESS ) &&
         ( h->subscribeQOS == -1 ); i++ )
    {
        ret = mosquitto_loop( h->m, MQTT_SHORT_WAIT_TIME, 1 );
    }

    if(ret != MOSQ_ERR_SUCCESS)
    {
        warnx("unsubscribe : %s", mosquitto_strerror(ret));
        return false;
    }
    else
        return true;
}

/*-----------------------------------------------------------*/

static bool subscribe( handle_t * h, char *in_topic)
{
    int ret;
    size_t i;

    assert( h != NULL );
    assert( MQTT_QOS <= 2 );

    /* set to default value */
    info("subscribe in_topic : %s\n", in_topic);
    h->subscribeQOS = -1;
    
    //ret = mosquitto_subscribe( h->m, NULL, in_topic, MQTT_QOS );
    ret = mosquitto_subscribe_callback(on_message, NULL, in_topic, MQTT_QOS, h->host, h->port, 
    h->name, MQTT_KEEP_ALIVE, true, NULL, NULL, NULL, NULL);
    /* expect the on_subscribe() callback to update h->subscribeQOS */
    for( i = 0; ( i < MAX_LOOPS ) &&
         ( ret == MOSQ_ERR_SUCCESS ) &&
         ( h->subscribeQOS == -1 ); i++ )
    {
        ret = mosquitto_loop( h->m, MQTT_SHORT_WAIT_TIME, 1 );
    }

    if( h->subscribeQOS == 0x80 )
    {
        warnx( "broker rejected subscription" );
    }
    else if( ret != MOSQ_ERR_SUCCESS )
    {
        warnx( "subscribe: %s", mosquitto_strerror( ret ) );
    }

    return ( ( h->subscribeQOS >= 0 ) && ( h->subscribeQOS <= MQTT_QOS ) ) ? true : false;
}

/*-----------------------------------------------------------*/

static bool publish( handle_t *h, char *in_topic, char *in_message)
{
    int ret;
    size_t i;

    assert( h != NULL);
    assert( MQTT_QOS <= 2 );

    info("publish message : %s\n", in_message);
    ret = mosquitto_publish(h->m, NULL, in_topic, strlen(in_message), in_message, MQTT_QOS, 0);

    if( ret != MOSQ_ERR_SUCCESS )
    {
        warnx( "publish: %s", mosquitto_strerror( ret ) );
        return false;
    }

    return true;
}

/*-----------------------------------------------------------*/

int findTopicIndex(char *in_topic)
{
    int i = 0;

    for(i = 0 ; i < TOPIC_LENGTH ; i++)
    {
        if(strcmp(in_topic, TopicFilter[i]) == 0)
        {
            return i;
        }
    }
}



int on_message( struct mosquitto * m,
                 void * p,
                 const struct mosquitto_message * message )
{
    handle_t * h = p;
    bool ret = false;

    assert( h != NULL );
    assert( message->topic != NULL );

    int index = findTopicIndex(message->topic);

    info("on_message topic : %s / on message : %s / index : %d\n", message->topic, message->payload, index);

    switch(index)
    {
        case CERTIFICATE_ACCEPT:
            ret = assemble_certificates(message->payload, message->payloadlen);

            if(ret == false)
                errx(1, "Assemble certificates failed\n");
            else
            {
                info("on message assemble certificates success\n");
                completeFlag[0] = false;
                set_in_progress = SET_IN_PROGRESS;
            }
        break;
        
        case TEMPLATE_ACCEPT:
        {
            ret = unsubscribeFleetProvisioning(h);

            if(ret == true)
            {
                JSONStatus_t jsonResult;
                char *value, tQuery[24] = {0,};

                set_in_progress = SET_IN_PROGRESS;
                
                strcpy(tQuery, "thingName");
                size_t valueLength, queryLength = strlen(tQuery);

                jsonResult = JSON_Validate(message->payload, message->payloadlen);

                if(jsonResult == JSONSuccess)
                {
                    jsonResult = JSON_Search(message->payload, message->payloadlen,
                    tQuery, queryLength, &value, &valueLength);
                    strncpy(gClientId, value, valueLength);
                    info("[LOG] Client Id : %s\n", gClientId);
                }
                
                closeConnection(h);
                //mosquitto_destroy(h->m);
                changeConnectionInformation(h);
                //mosquitto_destroy( h->m );

                completeFlag[1] = true;
                
            }
        }
        break;
        default:
        break;
    }
    info("on_message out\n");
}

/*-----------------------------------------------------------*/

static void on_log( struct mosquitto * m,
                    void * p,
                    int level,
                    const char * log )
{
    assert( log != NULL );

    info( "%s", log );
}

/*-----------------------------------------------------------*/

static void catch( int signal )
{
    errx( 1, "exit on signal: %d", signal );
}

/*-----------------------------------------------------------*/

static bool setup( handle_t * h )
{
    bool ret = false;
    struct sigaction sa = { 0 };

    assert( h != NULL );

    /* ensure teardown() will run for these signals */
    sa.sa_handler = catch;
    sigemptyset( &sa.sa_mask );
    assert( sigaction( SIGHUP, &sa, NULL ) != -1 );
    assert( sigaction( SIGINT, &sa, NULL ) != -1 );
    assert( sigaction( SIGTERM, &sa, NULL ) != -1 );

    mosquitto_lib_init();
    h->m = mosquitto_new( h->name, true, h );

    if( h->m != NULL )
    {
        mosquitto_log_callback_set( h->m, on_log );
        mosquitto_connect_callback_set( h->m, on_connect );
        mosquitto_subscribe_callback_set( h->m, on_subscribe );
        //mosquitto_message_callback_set( h->m, on_message );
        ret = true;
    }

    return ret;
}

/*-----------------------------------------------------------*/

static void teardown( int x,
                      void * p )
{
    handle_t * h = p;

    assert( h != NULL );

    if( h->url != NULL )
    {
        free( h->url );
    }

    if( h->jobid != NULL )
    {
        free( h->jobid );
    }

    closeConnection( h );
    mosquitto_destroy( h->m );
    mosquitto_lib_cleanup();
}

/*-----------------------------------------------------------*/

static bool subscribeFleetProvisioning(handle_t *h)
{
    bool ret;
    int i = 0;
    for(i = 0 ; i < 4 ; i++)
    {
        ret = subscribe(h, TopicFilter[i]);
        if(ret != true)
            errx(1, "subscribe topic error\n");
    }
    
    if(ret != true)
        return false;
    else
        return true;    
}

/*-----------------------------------------------------------*/

static bool unsubscribeFleetProvisioning(handle_t *h)
{
    bool ret;

    int i = 0;
    for(i = 0 ; i < 4 ; i++)
    {
        ret = unsubscribe(h, TopicFilter[i]);
        if(ret != true)
            errx(1, "unsubscribe topic error\n");
    }

    if(ret != true)
        return false;
    else
        return true;
}

/*-----------------------------------------------------------*/

static bool changeConnectionInformation(handle_t *h)
{
    char privateKeyFile[50] = {0,}, certFile[50] = {0,};

    sprintf(certFile, "./%s/%s-certificate.pem.crt", CERTFILE_PATH, gCertificateId);
    sprintf(privateKeyFile, "./%s/%s-private.pem.key", CERTFILE_PATH, gCertificateId);
}

/*-----------------------------------------------------------*/

static void createUUIDStr()
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

int main( int argc, char * argv[] )
{
    handle_t h_, * h = &h_;
    time_t now;

    createUUIDStr();
    initHandle( h, 1 );

    if( parseArgs( h, argc, argv ) == false )
    {
        exit( 1 );
    }

    on_exit( teardown, h );

    if( ( setup( h ) == false ) || ( connect( h ) == false ) )
    {
        errx( 1, "fatal error" );
    }

    if( subscribeFleetProvisioning(h) == false )
    {
        errx( 1, "fatal error" );
    }

    
    
    //h->lastPrompt = time( NULL );

    while( 1 )
    {
        bool ret = true;
        int m_ret;
        info("main loop\n");
        if(completeFlag[0] == false)
        {
            publish(h, TopicFilter[PROVISIONING_CC], MqttExMessage[0]);
            sleep(1);
            publish(h, TopicFilter[PROVISIONING_TT], MqttExMessage[1]);
            completeFlag[0] = true;
        }

        else if(completeFlag[1] == true)
        {
            bool ret[2];
            h->name = gClientId;
            initHandle(h, 2);
            ret[0] = setup(h);
            ret[1] = connect(h);
            if( ret[0] == false || ret[1] == false )
            {
                errx( 1, "fatal error" );
            }
            set_in_progress = SET_COMPLETE;
            subscribe(h, TopicFilter[OPENWORLD]);
            completeFlag[1] = false;
        }

        if(set_in_progress == SET_COMPLETE)
        {
            info("mosquitto loop\n");
            m_ret = mosquitto_loop( h->m, MQTT_WAIT_TIME, 1 );

            if( m_ret != MOSQ_ERR_SUCCESS )
            {
                errx( 1, "mosquitto_loop: %s", mosquitto_strerror( m_ret ) );
            }

            //now = time( NULL );
        }
        sleep(1);
    }

    exit( EXIT_SUCCESS );
}
