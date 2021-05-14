/* C standard includes. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

/* POSIX includes. */
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>

#include <err.h>
#include <getopt.h>

/* CAN Communication */
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <curses.h>
#include <endian.h>



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
             "\nusage: %s "
             "-h <endpoint> -c <cert id> -n <client id> -d <cert dir> -m <mode> [-l loop <Publish only>]\n"
             "-c : Certificate ID\n"
             "-d : Cert file Directory\n"
             "-f : Fleet Provisioning Template Name\n"
             "-n : Client ID\n"
             "-m : select mode. 1: Publish / 2: Subscribe / 3: Fleet Provisioning / 4: UpDownstream Test\n"
             "-M : Publish Message.\n"
             "-N : MDN Number\n"
             "-t : Publish / Subscribe Topic\n"
             "-l : Loop count. 0 : Forever / not 0 : Loop count <Publish only>\n"
             "-h : mqtt endpoint Address\n");
}

/*-----------------------------------------------------------*/

/**
 * @brief CAN data set
 * 
 */ 

typedef struct
{
	uint16_t rpm;
	uint8_t speed;
	uint8_t temp;
	uint8_t turn_signal;
	uint8_t light;
	uint8_t seat_belt;
	uint8_t foot_brake;
	uint8_t trunk;
	uint8_t hood;
	uint8_t side_brake;
	uint8_t gear;
} data_set_t;

/**
 * @brief CAN frame data set
 * 
 */ 

typedef struct
{
	uint32_t ids;
	struct can_frame frames;
} can_data_t;

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
static bool mqttConnect( handle_t * h );

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
void on_message( struct mosquitto * m,
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

/**
 * @brief Change MQTT Connection Information
 * @param[in] h runtime state handle
 */
static bool changeConnectionInformation(handle_t *h);

/**
 * @brief Convert mapping function
 * @param[in] x Source value
 * @param[in] in_min before min value
 * @param[in] in_max before max value
 * @param[in] out_min after min value
 * @param[in] out_max after max value
 */ 
long map(long x, long in_min, long in_max, long out_min, long out_max);

/// @brief Initialize CAN frame data set
static void can_frame_init();

/// @brief Initialize CAN Socket
static int can_init(int *sck, char *ifname);

/// @brief Find change can data
static void diff_can(struct can_frame frame);

/// @brief Process can data
static void process_can(struct can_frame *frame);

/// @brief Receive can data
static void receive_can(int *sck, struct can_frame *frame);

/// @brief MQTT Handler function
static void mqtt_handler();

/// @brief Create Timer handler (MQTT, JSON, CAN)
static int makeTimer(char *name, timer_t *timerID, int sec, int msec);

/// @brief Initialize timer handler function
static void timer_handler(int sig, siginfo_t *si, void *uc);

/// @brief Create Report JSON String
static void json_handler();
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
#define TOPIC_LENGTH		10

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
    USER_PUBSUB,
    DOWNSTREAM,
    UPSTREAM
};

enum
{
    SET_COMPLETE,           // Set Complete Flag
    SET_IN_PROGRESS,        // Set In Progress Flag
    SET_FAILED,             // Set Failed Flag
    RESERVED                // Reserved
};

enum
{
    MODE_PUBLISH = 1,
    MODE_SUBSCRIBE,
    MODE_FLEET_PROV,
    MODE_UPDOWN_STREAM
};

enum frame_ids
{
	CN7_P_GEAR_SFT = 0x111,
	CN7_P_STEERING = 0x2B0,
	CN7_P_RPM_SPEED = 0x316,
	CN7_P_PEDAL_POS = 0x329,
	CN7_P_LIGHT_TH = 0x541,
	CN7_P_WIPER = 0x553,
	CN7_P_SOC = 0x593,
	CN7_B_DOOR = 0x168,
};

enum can_index
{
	ID_GEAR,
	ID_STEERING,
	ID_SPEED,
	ID_PEDAL,
	ID_LIGHT,
	ID_WIPER,
	ID_SOC,
	ID_DOOR
};

/// @brief Global CAN socket
int *gSock = 0;

/**
 * @brief Global can data
 */
can_data_t cn7_data[P_IDS], b_data[P_IDS];

/**
 * @brief Global data set
 */ 
data_set_t current_data;

/**
 * @brief Initialize Topic name
 */

char TopicFilter[TOPIC_LENGTH][256] = {0, };

/**
 * @brief Initialize Topic name length
 */

uint16_t TopicFilterLength[TOPIC_LENGTH] = {0,};

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

/// @brief Provisioning complete Flag
bool completeFlag[4] = {false, false, false, false};

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

/// @brief Global MDN Number
char gMDNNumber[13] = {0,};

char jsonBuffer[512] = {0,};
char dummy_buffer[30][512] = {0,};

/// @brief Active Mode
uint8_t gMode = 0, gLcount = 0, gLFlag = 1, dLoop = 0;

/// @brief timer handler ID
timer_t CANTimerID;
timer_t JSONTimerID;
timer_t MqttTimerID;
timer_t dJSONTimerID;

/// @brief Global runtime state handle
handle_t *g_h;

/*-----------------------------------------------------------*/

static void dummyJSON_handler()
{
    int i = 0;
    char *dtPtr, *cdmaPtr;
    char *ptr = strtok(dummy_buffer[dLoop], "\n");

    time_t rawtime;
    struct tm *timeinfo;

    while(ptr != NULL)
    {
        if(i == 1)
        {
            cdmaPtr = index(ptr, ':');
            strcpy(cdmaPtr + 2, gMDNNumber);
        }
        else if(i == 11)
        {
            dtPtr = index(ptr, ':');

            time(&rawtime);
            timeinfo = localtime(&rawtime);

            char tempdt[40] = {0,};

            strftime(tempdt, 40, "\"%Y-%m-%d %H:%M:%S\"", timeinfo);
            strcpy(dtPtr + 2, tempdt);
        }
        ptr = strtok(NULL, "\n");
        i++;
    }

    if(dLoop < 30)
        dLoop++;
    else
        dLoop = 0;
}

static void initCANData()
{
    int fd = open("./car_data.bin", O_RDONLY);
    read(fd, dummy_buffer, sizeof(dummy_buffer));
    close(fd);
}

static void can_frame_init()
{
	int i;

	memset(&current_data, 0, sizeof(can_data_t));
	for(i = 0 ; i < P_IDS ; i++)
	{
		memset(&cn7_data[i], 0, sizeof(can_data_t));
		memset(&b_data[i], 0, sizeof(can_data_t));
	}
	
	cn7_data[0].ids = CN7_P_GEAR_SFT;
	cn7_data[1].ids = CN7_P_STEERING;
	cn7_data[2].ids = CN7_P_RPM_SPEED;
	cn7_data[3].ids = CN7_P_PEDAL_POS;
	cn7_data[4].ids = CN7_P_LIGHT_TH;
	cn7_data[5].ids = CN7_P_WIPER;
	cn7_data[6].ids = CN7_P_SOC;
}

static int can_init(int *sck, char *ifname)
{
	struct sockaddr_can addr;
	struct ifreq ifr;

	if((*sck = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0)
	{
		perror("CAN Socket Error\n");
		return 1;
	}

	memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
	strcpy(ifr.ifr_name, ifname);
	
	if(ioctl(*sck, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("SIOCGIFINDEX Error\n");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	if(bind(*sck, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("Bind Error\n");
		return 1;
	}

//	setsockopt(*sck, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &rfilter, sizeof(rfilter));
	return 0;
}

long map(long x, long in_min, long in_max, long out_min, long out_max)
{
  return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

static void diff_can(struct can_frame frame)
{
	switch(frame.can_id)
	{
		case CN7_P_GEAR_SFT:
			if(b_data[ID_GEAR].frames.data[SHIFTER] != frame.data[SHIFTER])
			{
				current_data.gear = frame.data[SHIFTER];

                #if DEBUG
				printf("current gear : %c\n", (frame.data[SHIFTER] == 0x0) ? 'P' :
				frame.data[SHIFTER] == 0x7 ? 'R' :
				frame.data[SHIFTER] == 0x6 ? 'N' : 'D');
                #endif
			}
		break;
		case CN7_P_STEERING:
		break;
		case CN7_P_RPM_SPEED:
			if(b_data[ID_SPEED].frames.data[SPEED] != frame.data[SPEED])
			{
				current_data.speed = frame.data[SPEED];
                #if DEBUG
				printf("current speed : %02X\n", frame.data[SPEED]);
                #endif
			}
			
			if(b_data[ID_SPEED].frames.data[RPM] != frame.data[RPM])
			{
				current_data.rpm = (uint16_t)map(frame.data[RPM], 5, 0x4E, 350, 4907);
                #if DEBUG
				printf("current rpm : %ld\n", map(frame.data[RPM], 5, 0x4E, 350, 4907));
                #endif
			}
		break;
		case CN7_P_PEDAL_POS:
			//if(b_data[ID_SPEED].frames.data[TPS] != frame.data[TPS])
				//printf("current Throttle : %02X\n", frame.data[TPS]);
			if(b_data[ID_SPEED].frames.data[APS] != frame.data[APS])
			{
				//current_data.acc
				//printf("current Accel : %02X\n", frame.data[APS]);
			}
			if(b_data[ID_PEDAL].frames.data[COOLANT] != frame.data[COOLANT])
			{
				current_data.temp = (uint8_t) map(frame.data[COOLANT], 0, 255, -48, 134);
                #if DEBUG
				printf("current temperature : %ld\n", map(frame.data[COOLANT], 0, 255, -48, 134));
                #endif
			}
			if(b_data[ID_PEDAL].frames.data[FOOTBRAKE] != frame.data[FOOTBRAKE])
			{
				current_data.foot_brake = (frame.data[FOOTBRAKE] >> 1);
                #if DEBUG
				printf("foot brake : %s\n", frame.data[FOOTBRAKE] == 0x02 ? "On" : "Off");
                #endif
			}
		break;
		case CN7_P_LIGHT_TH:
			if(b_data[ID_LIGHT].frames.data[HAZARD] != frame.data[HAZARD])
			{
				current_data.turn_signal = (frame.data[HAZARD] == 0x02) ? 1 : 0;
                #if DEBUG
				printf("Hazard : %s\n", (frame.data[HAZARD] == 0x02) ? "On": "Off");
                #endif
			}
			else if(b_data[ID_LIGHT].frames.data[TURN_HOOD] != frame.data[TURN_HOOD])
			{
				if((((frame.data[TURN_HOOD] >> 3) == 0) || ((frame.data[TURN_HOOD] >> 3) == 1))
				&& ((frame.data[TURN_HOOD] & 0x02) == (b_data[ID_LIGHT].frames.data[TURN_HOOD] & 0x02)))
				{
					current_data.turn_signal = (frame.data[TURN_HOOD] >> 3) ? 2 : 0;
                    #if DEBUG
					printf("L_Turn : %s / %02X\n", (frame.data[TURN_HOOD] >> 3) ? "On": "Off" , frame.data[TURN_HOOD] >> 3);
                    #endif
				}
				else if(((((frame.data[TURN_HOOD] & 0x02) >> 1) == 1) || ((((frame.data[TURN_HOOD] & 0x02) >> 1) == 0)))
				&& ((frame.data[TURN_HOOD] >> 3) == (b_data[ID_LIGHT].frames.data[TURN_HOOD] >> 3)))
				{
					current_data.hood = (frame.data[TURN_HOOD] & 0x02) >> 1;
                    #if DEBUG
					printf("Hood : %s\n", (((frame.data[TURN_HOOD] & 0x02) >> 1) == 1) ? "On": "Off");
                    #endif
				}
			}
			else if(b_data[ID_LIGHT].frames.data[TURN_SIDE] != frame.data[TURN_SIDE])
			{
				if(((frame.data[TURN_SIDE] >> 6) == 1 || (frame.data[TURN_SIDE] >> 6) == 0) 
					&& ((frame.data[TURN_SIDE] & 0x10) == (b_data[ID_LIGHT].frames.data[TURN_SIDE] & 0x10)))
					{
						current_data.turn_signal = ((frame.data[TURN_SIDE] >> 6) == 1) ? 3 : 0;
                        #if DEBUG
						printf("R_Turn : %s\n", ((frame.data[TURN_SIDE] >> 6) == 1) ? "On": "Off");
                        #endif
					}
				else if(((((frame.data[TURN_SIDE] & 0x10) >> 4) == 1) || (((frame.data[TURN_SIDE] & 0x10) >> 4) == 0))
					&& ((frame.data[TURN_SIDE] >> 6) == (b_data[ID_LIGHT].frames.data[TURN_SIDE] >> 6)))
					{
						current_data.side_brake = ((frame.data[TURN_SIDE] & 0x10) >> 4);
                        #if DEBUG
						printf("Side Brake : %s\n", (((frame.data[TURN_SIDE] & 0x10) >> 4) == 1) ? "On": "Off");
                        #endif
					}
			}
				
			else if(b_data[ID_LIGHT].frames.data[HEADLAMP] != frame.data[HEADLAMP])
			{
				current_data.light = (frame.data[HEADLAMP] == 0x80) ? 1 : 0;
                #if DEBUG
				printf("Light : %s\n", (frame.data[HEADLAMP] == 0x80) ? "On": "Off");
                #endif
			}
			
			if(b_data[ID_LIGHT].frames.data[TRUNK_SEATBELT] != frame.data[TRUNK_SEATBELT])
			{
				if(((frame.data[TRUNK_SEATBELT] >> 4) == 1 || (frame.data[TRUNK_SEATBELT] >> 4) == 0) 
				&& ((frame.data[TRUNK_SEATBELT] & 0x04) == (b_data[ID_LIGHT].frames.data[TRUNK_SEATBELT] & 0x04)))
				{
					current_data.trunk = ((frame.data[TRUNK_SEATBELT] >> 4) == 1) ? 1 : 0;
                    #if DEBUG
					printf("Trunk : %s\n", ((frame.data[TRUNK_SEATBELT] >> 4) == 1) ? "On" : "Off");
                    #endif
				}
				else if(((((frame.data[TRUNK_SEATBELT] & 0x04) >> 2) == 1) || (((frame.data[TRUNK_SEATBELT] & 0x04) >> 2) == 0))
				&& ((frame.data[TRUNK_SEATBELT] >> 4) == (b_data[ID_LIGHT].frames.data[TRUNK_SEATBELT] >> 4)))
				{
					current_data.seat_belt = (((frame.data[TRUNK_SEATBELT] & 0x04) >> 2) == 1) ? 1 : 0;
                    #if DEBUG
					printf("Seat Belt : %s\n", (((frame.data[TRUNK_SEATBELT] & 0x04) >> 2) == 1) ? "On" : "Off");
                    #endif
				}
				
			}
		break;
		case CN7_P_WIPER:
		break;
		case CN7_P_SOC:
		break;
		case CN7_B_DOOR:
		break;
	}
}

static void process_can(struct can_frame *frame)
{

	int i = 0;

	for(i = 0 ; i < P_IDS ; i++)
	{
		if(frame->can_id == cn7_data[i].ids)
		{
			memcpy(&cn7_data[i].frames.data, frame->data, sizeof(uint8_t)*8);
			cn7_data[i].frames.can_id = frame->can_id;
			diff_can(cn7_data[i].frames);
			b_data[i] = cn7_data[i];
		}
	}
}

static void receive_can(int *sck, struct can_frame *frame)
{

	int bytes = 0;

	bytes = read(*sck, frame, sizeof(struct can_frame));

	if(bytes < 0)
	{
		perror("Read Error\n");
		exit(1);
	}
	process_can(frame);
}

static void json_handler()
{
    char temp[128] = {0,}, t_buff[128] = {0,};
    time_t rawtime;
    struct tm* timeinfo;

    memset(jsonBuffer, 0, sizeof(char) * 2048);

    sprintf(temp, "{\n");
    strcpy(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"cdma_id\" : 0%d,\n", atoi(gMDNNumber));
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"trunk\" : \"%s\",\n", current_data.trunk ? "On" : "Off");
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"hood\" : \"%s\",\n", current_data.hood ? "On" : "Off");
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"side_brake\" : \"%s\",\n", current_data.side_brake ? "On" : "Off");
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"gear\" : \"%c\",\n", (current_data.gear == 0x0) ? 'P' :
				current_data.gear == 0x7 ? 'R' :
				current_data.gear == 0x6 ? 'N' : 'D');
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"turn_signal\" : \"%s\",\n", current_data.turn_signal == 1 ? "Hazard" :
    current_data.turn_signal == 2 ? "Left" : current_data.turn_signal == 3 ? "Right" : "Off");
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"light\" : \"%s\",\n", current_data.light ? "On" : "Off");
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"coolant\" : %d,\n", current_data.temp);
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"speed\" : %d,\n", current_data.speed);
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "\t\"rpm\" : %d,\n", current_data.rpm);
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(t_buff, 128, "\"%Y-%m-%d %H:%M:%S\"", timeinfo);

    sprintf(temp, "\t\"created_at\" : %s\n", t_buff);
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    sprintf(temp, "}\n", t_buff);
    strcat(jsonBuffer,temp);
    memset(temp, 0, sizeof(char) * 128);

    #if DEBUG
        info("JSON String : %s\n", jsonBuffer);
    #endif
    
    
 #if 0   
    if(b_Loop < 30)
    {
        strcpy(out_buffer[b_Loop], buffer);
        b_Loop++;
    }
    else
    {
        b_Loop = 0;
        strcpy(out_buffer[b_Loop], buffer);
        int fd = open("./car_data.bin", O_RDWR);
        write(fd, out_buffer, sizeof(out_buffer));
        close(fd);
        printf("write complete\n");
    }
#endif
}

static void timer_handler(int sig, siginfo_t *si, void *uc)
{
    timer_t *tidp;
    tidp = si->si_value.sival_ptr;
    struct can_frame frame;
    if(*tidp == CANTimerID)
    {
        receive_can(gSock, &frame);
    }
    else if(*tidp == JSONTimerID)
    {
        json_handler();
    }
    else if(*tidp == MqttTimerID)
    {
        mqtt_handler();
    }
    else if(*tidp == dJSONTimerID)
    {
        dummyJSON_handler();
    }
}

static int makeTimer(char *name, timer_t *timerID, int sec, int msec)
{
    struct sigevent te;
    struct itimerspec its;
    struct sigaction sa;  
    int sigNo = SIGRTMIN;  
   
    /* Set up signal handler. */  
    sa.sa_flags = SA_SIGINFO;  
    sa.sa_sigaction = timer_handler;  
    sigemptyset(&sa.sa_mask);  
  
    info("Initialize makeTimer : %s\n", name);
    if (sigaction(sigNo, &sa, NULL) == -1)  
    {  
        printf("sigaction error\n");
        return -1;  
    }  
   
    /* Set and enable alarm */  
    te.sigev_notify = SIGEV_SIGNAL;  
    te.sigev_signo = sigNo;  
    te.sigev_value.sival_ptr = timerID;  
    timer_create(CLOCK_REALTIME, &te, timerID);  
   
    its.it_interval.tv_sec = sec;
    its.it_interval.tv_nsec = msec * 1000000;  
    its.it_value.tv_sec = sec;
    
    its.it_value.tv_nsec = msec * 1000000;
    timer_settime(*timerID, 0, &its, NULL);  
   
    return 0;  
}

void initTopicFilter(char *t_name)
{
    sprintf(TopicFilter[TEMPLATE_REJECT], TEMPLATE_REJECT_TOPIC, t_name);
    sprintf(TopicFilter[CERTIFICATE_REJECT], CERTIFICATE_REJECT_TOPIC, t_name);
    sprintf(TopicFilter[TEMPLATE_ACCEPT], TEMPLATE_ACCEPT_TOPIC, t_name);
    sprintf(TopicFilter[CERTIFICATE_ACCEPT], CERTIFICATE_ACCEPT_TOPIC, t_name);
    sprintf(TopicFilter[PROVISIONING_TT], PROVISIONING_TEMPLATE_TOPIC, t_name);
    strcpy(TopicFilter[PROVISIONING_CC], PROVISIONING_CERT_CREATE_TOPIC);
    
    TopicFilterLength[TEMPLATE_REJECT] = strlen(TopicFilter[TEMPLATE_REJECT]);
    TopicFilterLength[CERTIFICATE_REJECT] = strlen(TopicFilter[CERTIFICATE_REJECT]);
    TopicFilterLength[TEMPLATE_ACCEPT] = strlen(TopicFilter[TEMPLATE_ACCEPT]);
    TopicFilterLength[CERTIFICATE_ACCEPT] = strlen(TopicFilter[CERTIFICATE_ACCEPT]);
    TopicFilterLength[PROVISIONING_TT] = strlen(TopicFilter[PROVISIONING_TT]);
    TopicFilterLength[PROVISIONING_CC] = strlen(TopicFilter[PROVISIONING_CC]);
}

void initHandle( handle_t * p, uint8_t flag )
{
    assert( p != NULL );
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
            h.certfile = gCertFile;
            h.keyfile = gPrivateKey;
            h.cafile = gCAFileName;
            h.capath = "./certificates";
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
    checkPath( cafile );
    checkPath( certfile );
    checkPath( keyfile );
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
    char tempPath[3][128] = {0,};
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
            { "certid",    required_argument, NULL, 'c' },
            { "path",      required_argument, NULL, 'd' },
            { "fleet",     required_argument, NULL, 'f' },
            { "host",      required_argument, NULL, 'h' },
            { "loop",      required_argument, NULL, 'l' },
            { "mode",      required_argument, NULL, 'm' },
            { "message",   required_argument, NULL, 'M' },
            { "name",      required_argument, NULL, 'n' },
            { "mdn",       required_argument, NULL, 'N' },
            { "topic",     required_argument, NULL, 't' },
            { "help",      no_argument,       NULL, '?' },
            { NULL,        0,                 NULL, 0   }
        };

        c = getopt_long( argc, argv, "c:d:h:n:l:m:f:M:N:t:?",
                         long_options, &option_index );

        if( c == -1 )
        {
            break;
        }

        switch( c )
        {

            case 'c':
            {
                strcpy(gCertificateId, optarg);
                sprintf(tempPath[0], CERTFILE_PREFIX, gCertificateId);
                sprintf(tempPath[1], KEYFILE_PREFIX, gCertificateId);
            }   
                break;

            case 'd':
            {
                h->capath = optarg;
                sprintf(gCertFile, "%s/%s", h->capath, tempPath[0]);
                sprintf(gPrivateKey, "%s/%s", h->capath, tempPath[1]);
                sprintf(tempPath[2], "%s/AmazonRootCA1.crt", h->capath);
                sprintf(gCAFileName, tempPath[2]);
                h->certfile = gCertFile;
                h->keyfile = gPrivateKey;
                h->cafile = gCAFileName;
            }
                break;
            case 'f':
            {
                char templateName[30] = {0,};
                assert(optarg != NULL);
                strcpy(templateName, optarg);
                initTopicFilter(templateName);
            }
            break;
            case 'h':
                h->host = optarg;
                strcpy(gEndpointAddress, h->host);
                break;

            case 'l':
                if(optarg == NULL)
                    exit(1);
                gLcount = atoi(optarg);
                break;

            case 'm':
                if(optarg == NULL)
                    exit(1);
                gMode = atoi(optarg);
                break;

            case 'M':
                strcpy(MqttExMessage[3], optarg);
                MqttExMessageLength[3] = strlen(MqttExMessage[3]);
                break;

            case 'N':
            {
                char *clientID = malloc(sizeof(char)*40);
                strcpy(gMDNNumber, optarg);
                sprintf(clientID, "sts-%s", gMDNNumber);
                h->name = clientID;
                h->nameLength = strlen( clientID );
            }
                break;

            case 't':
                if(optarg == NULL)
                    exit(1);
                strcpy(TopicFilter[USER_PUBSUB], optarg);
                TopicFilterLength[USER_PUBSUB] = strlen(TopicFilter[USER_PUBSUB]);
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
        if(gMode == 1 || gMode == 2)
        {
            if(TopicFilter[USER_PUBSUB] == NULL || strlen(TopicFilter[USER_PUBSUB]) == 0)
                ret = false;
        }
        if(gMode == 0)
            ret = false;
    }

    return ret;
}


/*-----------------------------------------------------------*/

static bool registerThing(char *token, size_t tokenLength)
{
	JSONStatus_t jsonResult;
	char parseToken[1024] = {0,};
	strncpy(parseToken, token, sizeof(char)*tokenLength);
	sprintf(MqttExMessage[1], "{\"certificateOwnershipToken\":\"%s\",\"parameters\":{\"MdnNumber\":\"%s\"}}",parseToken, gMDNNumber);
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
	jsonResult = JSON_Validate(pBuffer, pBufferLength);

	if(jsonResult == JSONSuccess)
	{
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
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[1], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				sprintf(certFileName, "%s/%s-certificate.pem.crt", CERTFILE_PATH, certificateId);
				memset(gCertFile, 0, sizeof(gCertFile));
                strcpy(gCertFile, certFileName);
                fp = fopen(certFileName, "w");
				
				convertResult = JSONtoCertFile(value, valueLength, fp);
				fclose(fp);
			}
			else
			{
				errx(1, "JSON Search Error\n");
			}
			// Private Key Parsing
			queryLength = strlen(queryCertificate[2]);
			jsonResult = JSON_Search(payloadBuffer, pBufferLength, queryCertificate[2], queryLength,
				&value, &valueLength);
			
			if(jsonResult == JSONSuccess)
			{
				FILE *fp;
				sprintf(privateFileName, "%s/%s-private.pem.key", CERTFILE_PATH, tempId);
                memset(gPrivateKey, 0, sizeof(gPrivateKey));
                strcpy(gPrivateKey, privateFileName);
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
				
                if(convertResult == false)
                {
                    errx(1, "Registration new service failed\n");
                    return false;
                }
                else
                {
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

    h->connectError = rc;
}

/*-----------------------------------------------------------*/

static bool mqttConnect( handle_t * h )
{
    int ret = MOSQ_ERR_SUCCESS;
    size_t i;

    assert( h != NULL );
    assert( h->m != NULL );
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
    h->subscribeQOS = -1;
    
    ret = mosquitto_subscribe( h->m, NULL, in_topic, MQTT_QOS );
    info( "subscribe: %s", mosquitto_strerror( ret ) );
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

    ret = mosquitto_publish(h->m, NULL, in_topic, strlen(in_message), in_message, MQTT_QOS, 0);

    if( ret != MOSQ_ERR_SUCCESS )
    {
        warnx( "subscribe: %s", mosquitto_strerror( ret ) );
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



void on_message( struct mosquitto * m,
                 void * p,
                 const struct mosquitto_message * message )
{
    handle_t * h = p;
    bool ret = false;

    assert( h != NULL );
    assert( message->topic != NULL );

    int index = findTopicIndex(message->topic);

    info("on topic : %s / on message : %s\n", message->topic, message->payload);

    switch(index)
    {
        case CERTIFICATE_ACCEPT:
            ret = assemble_certificates(message->payload, message->payloadlen);

            if(ret == false)
                errx(1, "Assemble certificates failed\n");
            else
            {
                completeFlag[1] = true;
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
                }
                
                closeConnection(h);
                //mosquitto_destroy(h->m);
                //changeConnectionInformation(h);
                //mosquitto_destroy( h->m );

                completeFlag[2] = true;
                
            }
        }
        break;
        case CERTIFICATE_REJECT:
        break;
        case TEMPLATE_REJECT:
        break;
        case DOWNSTREAM:
            info("Downstream Message!\n");
        break;  
        default:
        break;
    }
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
        mosquitto_message_callback_set( h->m, on_message );
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

    #if RANE_CAN_TEST
    close(*gSock);
    #endif
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

static void mqtt_handler()
{
    bool ret = true;
    int m_ret, i = 0;

    switch(gMode)
    {
        case MODE_PUBLISH:
            if(!gLcount)
                publish(g_h, TopicFilter[USER_PUBSUB], MqttExMessage[3]);
            else
            {
                if(i == gLcount)
                {
                    gLFlag = 0;
                    exit(1);
                }
                publish(g_h, TopicFilter[USER_PUBSUB], MqttExMessage[3]);
                i++;
            }
        break;
        case MODE_FLEET_PROV:
            if(completeFlag[0] == true)
            {
                publish(g_h, TopicFilter[PROVISIONING_CC], MqttExMessage[0]);
                completeFlag[0] = false;
            }
            if(completeFlag[1] == true)
            {
                publish(g_h, TopicFilter[PROVISIONING_TT], MqttExMessage[1]);
                completeFlag[1] = false;
            }

            else if(completeFlag[2] == true)
            {
                bool ret[2];
                initHandle(g_h, 2);
                ret[0] = setup(g_h);
                ret[1] = mqttConnect(g_h);
                if( ret[0] == false || ret[1] == false )
                {
                    errx( 1, "fatal error" );
                }
                set_in_progress = SET_COMPLETE;
                //subscribe(h, TopicFilter[OPENWORLD]);
                sprintf(TopicFilter[DOWNSTREAM], DEVICE_DOWNSTREAM_TOPIC, gClientId);
                TopicFilterLength[DOWNSTREAM] = strlen(TopicFilter[DOWNSTREAM]);
                subscribe(g_h, TopicFilter[DOWNSTREAM]);

                sprintf(TopicFilter[UPSTREAM], DEVICE_UPSTREAM_TOPIC, gClientId);
                TopicFilterLength[UPSTREAM] = strlen(TopicFilter[UPSTREAM]);
//                subscribe(g_h, TopicFilter[UPSTREAM]);
                completeFlag[2] = false;
                completeFlag[3] = true;
            }
            else if(completeFlag[3] == true)
            {
                #if RANE_CAN_TEST
                    publish(g_h, TopicFilter[UPSTREAM], jsonBuffer);
                #else
                    publish(g_h, TopicFilter[UPSTREAM], dummy_buffer[dLoop]);
                #endif
            }
        break; 
        case MODE_UPDOWN_STREAM:
            #if RANE_CAN_TEST
                publish(g_h, TopicFilter[UPSTREAM], jsonBuffer);
            #else
                publish(g_h, TopicFilter[UPSTREAM], dummy_buffer[dLoop]);
            #endif
        break;
    }
    {
        m_ret = mosquitto_loop( g_h->m, MQTT_WAIT_TIME, 1 );

        if( m_ret != MOSQ_ERR_SUCCESS )
        {
            errx( 1, "mosquitto_loop: %s", mosquitto_strerror( m_ret ) );
        }
        //now = time( NULL );
    }
}

int main( int argc, char * argv[] )
{
    handle_t h_, * h = &h_;
    time_t now;
    int i = 0, sock = 0;

    createUUIDStr();
    initHandle( h, 1 );

#if RANE_CAN_TEST
    can_frame_init();
    can_init(&sock, "can0");
    gSock = &sock;
#else
    initCANData();
#endif

    g_h = h;
    

    if( parseArgs( h, argc, argv ) == false )
    {
        exit( 1 );
    }

    on_exit( teardown, h );

    if( ( setup( h ) == false ) || ( mqttConnect( h ) == false ) )
    {
        errx( 1, "fatal error" );
    }
       
    //h->lastPrompt = time( NULL );

#if RANE_CAN_TEST
    makeTimer("CAN Data Read", &CANTimerID, 0, 5);
    makeTimer("JSON Handler", &JSONTimerID, 1, 0);
#else
    makeTimer("dummy JSON Handler", &dJSONTimerID, 1, 0);
#endif
    makeTimer("Mqtt Handler", &MqttTimerID, 1, 0);
    if(gMode == MODE_SUBSCRIBE)
        subscribe(h, TopicFilter[USER_PUBSUB]);

    else if(gMode == MODE_FLEET_PROV)
    {
        if( subscribeFleetProvisioning(h) == false )
                {
                    errx( 1, "fatal error" );
                }
                completeFlag[0] = true; 
    }
    else if(gMode == MODE_UPDOWN_STREAM)
    {
        sprintf(gClientId, "sts-%s", gMDNNumber);
        sprintf(TopicFilter[DOWNSTREAM], DEVICE_DOWNSTREAM_TOPIC, gClientId);
        TopicFilterLength[DOWNSTREAM] = strlen(TopicFilter[DOWNSTREAM]);
        subscribe(g_h, TopicFilter[DOWNSTREAM]);

        sprintf(TopicFilter[UPSTREAM], DEVICE_UPSTREAM_TOPIC, gClientId);
        TopicFilterLength[UPSTREAM] = strlen(TopicFilter[UPSTREAM]);
    }

    while(1)
    {
        sleep(1);
        #if 0
        bool ret = true;
        int m_ret;

        switch(gMode)
        {
            case MODE_PUBLISH:
                if(!gLcount)
                    publish(h, TopicFilter[USER_PUBSUB], MqttExMessage[3]);
                else
                {
                    if(i == gLcount)
                    {
                        gLFlag = 0;
                        exit(1);
                    }
                    publish(h, TopicFilter[USER_PUBSUB], MqttExMessage[3]);
                    i++;
                }
            break;
            case MODE_FLEET_PROV:
                if(completeFlag[0] == true)
                {
                    publish(h, TopicFilter[PROVISIONING_CC], MqttExMessage[0]);
                    completeFlag[0] = false;
                }
                if(completeFlag[1] == true)
                {
                    publish(h, TopicFilter[PROVISIONING_TT], MqttExMessage[1]);
                    completeFlag[1] = false;
                }

                else if(completeFlag[2] == true)
                {
                    bool ret[2];
                    initHandle(h, 2);
                    ret[0] = setup(h);
                    ret[1] = mqttConnect(h);
                    if( ret[0] == false || ret[1] == false )
                    {
                        errx( 1, "fatal error" );
                    }
                    set_in_progress = SET_COMPLETE;
                    //subscribe(h, TopicFilter[OPENWORLD]);
                    sprintf(TopicFilter[DOWNSTREAM], DEVICE_DOWNSTREAM_TOPIC, gClientId);
                    TopicFilterLength[DOWNSTREAM] = strlen(TopicFilter[DOWNSTREAM]);
                    subscribe(h, TopicFilter[DOWNSTREAM]);

                    sprintf(TopicFilter[DOWNSTREAM], DEVICE_DOWNSTREAM_TOPIC, gClientId);
                    TopicFilterLength[DOWNSTREAM] = strlen(TopicFilter[DOWNSTREAM]);
    
                    completeFlag[2] = false;
                    completeFlag[3] = true;
                }
                else if(completeFlag[3] == true)
                {
                    publish(h, TopicFilter[UPSTREAM], buffer);
                }
            break; 
        }
        {
            m_ret = mosquitto_loop( h->m, MQTT_WAIT_TIME, 1 );

            if( m_ret != MOSQ_ERR_SUCCESS )
            {
                errx( 1, "mosquitto_loop: %s", mosquitto_strerror( m_ret ) );
            }

            //now = time( NULL );
        }
        printf("main loop\n");
        sleep(1);
        #endif
    }

    exit( EXIT_SUCCESS );
}
