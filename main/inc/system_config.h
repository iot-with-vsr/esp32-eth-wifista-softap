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

// NVS KEYS
#define NVS_WIFI_SSID "ssid"
#define NVS_WIFI_PASS "pass"
#define NVS_API_URL "url"
#define NVS_API_INTERVAL "interval"
#define NVS_API_STATUS "status"
#define NVS_ADMIN_PASSWORD "apipass"

#define DEFAULT_WIFI_SSID "AmpleTrails"
#define DEFAULT_WIFI_PASSWORD "ampletrails"
#define DEFAULT_API_URL "http://amplecontroller.deskhours.in/"
#define DEFAULT_API_CALL_INTERVAL 30 // Seconds
#define DEFAULT_API_CALL_STATUS 1    // Enabled
#define DEFAULT_ADMIN_PASSWORD "password"

// Declarations with 'extern'
extern char WIFI_SSID[32];
extern char WIFI_PASS[64];
extern char API_URL[120];
extern const char *API_USERNAME;
extern char API_PASSWORD[64];
extern uint32_t API_CALL_INTERVAL;
extern uint8_t API_CALL_STATUS;

void load_system_config(void);

void setWIFI_CREDENTIALS(const char *new_ssid, const char *new_pwd);
void setAPI_URL(const char *new_url);
void setAPI_INTERVAL(uint32_t new_interval);
void setAPI_STATUS(uint8_t new_status);
void setADMIN_PASSWORD(const char *pwd);
void reset_config(void);
void setWiFiStatus(WiFi_Status_t st);
void setEthernetStatus(Eth_Status_t st);
void Eth_Status_String(char *str);
void WiFi_Status_String(char *str);
void Door_Status_String(char *str);
void setDoorStatus(Door_Status_t st);

#endif