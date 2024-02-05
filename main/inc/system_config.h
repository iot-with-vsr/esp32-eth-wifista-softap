#ifndef GLOBAL_VARIABLES_INCLUDED
#define GLOBAL_VARIABLES_INCLUDED

#include "utils.h"
#include "cJSON.h"

typedef enum
{
    ETH_NOT_CONNECTED,
    ETH_CONNECTED_BUT_NO_IP,
    ETH_CONNECTED
} Eth_Status_t;

typedef enum
{
    WIFI_STATUS_DISCONNECTED,
    WIFI_STATUS_CONNECTED_BUT_NO_IP,
    WIFI_STATUS_CONNECTED
} WiFi_Status_t;

typedef enum
{
    DOOR_STATUS_CLOSED,
    DOOR_STATUS_OPEN

} Door_Status_t;

extern Eth_Status_t eth_status;
extern WiFi_Status_t wifi_status;
extern Door_Status_t door_status;

#define NORMALLY_OPEN 1
#define NORMALLY_CLOSED 0

#define SENS_DETECT_TIME 10000
#define RELAY_ON_DURATION 10000

// NVS KEYS
#define NVS_WIFI_SSID "ssid"
#define NVS_WIFI_PASS "pass"
#define NVS_API_URL "url"
#define NVS_API_INTERVAL "interval"
#define NVS_API_STATUS "status"
#define NVS_ADMIN_PASSWORD "apipass"
#define NVS_USER_PASSWORD "userpass"
#define NVS_API_KEY "apikey"
#define NVS_COMPANY_ID "company"
#define NVS_LOG_IDX_KEY "logs"
#define NVS_PENDING_LOG_IDX_KEY "p_logs"
#define NVS_LOG_KEY_FMT "log_%d"
#define NVS_PENDING_LOG_KEY_FMT "p_log_%d"
#define NVS_RELAY_TYPE_KEY "relaytype"
#define NVS_SENS_TYPE_KEY "senstype"

#define DEFAULT_WIFI_SSID "AmpleTrails"
#define DEFAULT_WIFI_PASSWORD "ampletrails"
#define DEFAULT_API_URL "http://amplecontroller.deskhours.in/"
#define DEFAULT_API_CALL_INTERVAL 30 // Seconds
#define DEFAULT_API_CALL_STATUS 1    // Enabled
#define DEFAULT_ADMIN_PASSWORD "admin"
#define DEFAULT_USER_PASSWORD "user"
#define DEFAULT_API_KEY ""
#define DEFAULT_COMPANY_ID ""
#define DEFAULT_RELAY_TYPE NORMALLY_OPEN
#define DEFAULT_SENS_TYPE NORMALLY_OPEN

#define LOG_BUFFER_SIZE 100
#define LOG_MESSAG_SIZE 50

// Declarations with 'extern'
extern char WIFI_SSID[32];
extern char WIFI_PASS[64];
extern char API_URL[120];
extern const char *ADMIN_USERNAME;
extern const char *USER_USERNAME;
extern char ADMIN_PASSWORD[64];
extern char USER_PASSWORD[64];
extern uint32_t API_CALL_INTERVAL;
extern uint8_t API_CALL_STATUS;
extern char COMPANY_ID[120];
extern char API_KEY[120];
extern char ESP_MAC_ADDR[13];
extern uint8_t SENS_TYPE;
extern uint8_t RELAY_TYPE;

void setWIFI_CREDENTIALS(const char *new_ssid, const char *new_pwd);
void setAPI_URL(const char *new_url);
void setAPI_INTERVAL(uint32_t new_interval);
void setAPI_STATUS(uint8_t new_status);
void setADMIN_PASSWORD(const char *pwd);
void setCOMPANY_ID(const char *new_id);
void setAPI_KEY(const char *new_key);
void reset_config(void);
void setWiFiStatus(WiFi_Status_t st);
void setEthernetStatus(Eth_Status_t st);
void Eth_Status_String(char *str);
void WiFi_Status_String(char *str);
void Door_Status_String(char *str);
void setDoorStatus(Door_Status_t st);
void load_system_config(void);
void setUSER_PASSWORD(const char *pwd);
uint8_t isInternetConnected(void);
void sendPendingLogs(void);
void logMessage(const char *newString);
char *getLogAtIdx(int i);
int getNumLogs(void);
int getNumPendingLogs(void);
char *getPendingLogAtIdx(int i);
void get_mac_address(void);
void setSENS_TYPE(uint8_t sens_type);
void setRELAY_TYPE(uint8_t relay_type);

#endif