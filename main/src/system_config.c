#include "utils.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "system_config.h"
#include "api_thread.h"

static const char *TAG = "system_config";

char WIFI_SSID[32];
char WIFI_PASS[64];
char API_URL[120];
char API_KEY[120];
char COMPANY_ID[120];
const char *ADMIN_USERNAME = "admin";
const char *USER_USERNAME = "user";
char USER_PASSWORD[64];
char ADMIN_PASSWORD[64];
char ESP_MAC_ADDR[13];
uint32_t API_CALL_INTERVAL;
uint8_t API_CALL_STATUS;

Eth_Status_t eth_status;
WiFi_Status_t wifi_status;
Door_Status_t door_status;

char logBuffer[LOG_BUFFER_SIZE][LOG_MESSAG_SIZE];
char pendinglogBuffer[LOG_BUFFER_SIZE][LOG_MESSAG_SIZE];

static uint8_t logIndex = 0;
static uint8_t pendinglogIndex = 0;

uint8_t isInternetConnected()
{
    return (wifi_status == WIFI_STATUS_CONNECTED || eth_status == ETH_CONNECTED);
}

void pendinlogMessage(const char *newString)
{

    char key[16];

    if (logIndex >= (LOG_BUFFER_SIZE - 1))
    {
        pendinglogIndex = LOG_BUFFER_SIZE - 1;
        // Shift elements in the log buffer using memcpy
        memcpy(&pendinglogBuffer[0], &pendinglogBuffer[1], pendinglogIndex * LOG_MESSAG_SIZE);
        // Copy the new string to the last index of the log buffer
        strcpy(pendinglogBuffer[LOG_BUFFER_SIZE - 1], newString);
        pendinglogIndex++;
    }
    else
    {
        strcpy(pendinglogBuffer[pendinglogIndex], newString);
        pendinglogIndex++;
    }

    sprintf(key, NVS_PENDING_LOG_KEY_FMT, pendinglogIndex);
    utils_nvs_set_u8(NVS_PENDING_LOG_IDX_KEY, pendinglogIndex);
    utils_nvs_set_str(key, pendinglogBuffer[pendinglogIndex - 1]);
}

void sendPendingLogs(void)
{
    if (isInternetConnected())
    {
        if (pendinglogIndex > 0)
        {
            pendinglogIndex = 0;
            for (int i = 0; i < pendinglogIndex; i++)
            {
                sendEventLog(pendinglogBuffer[i]);
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
    }
}

int getNumLogs(void)
{
    return logIndex;
}

char *getLogAtIdx(int i)
{
    if (i >= 0 && i < logIndex)
    {
        return logBuffer[i];
    }
    else
    {
        return NULL; // Index out of bounds or log entry does not exist
    }
}

int getNumPendingLogs(void)
{
    return pendinglogIndex;
}

char *getPendingLogAtIdx(int i)
{
    if (i >= 0 && i < pendinglogIndex)
    {
        return pendinglogBuffer[i];
    }
    else
    {
        return NULL; // Index out of bounds or log entry does not exist
    }
}

void logMessage(const char *newString)
{
    char key[16];

    if (logIndex >= (LOG_BUFFER_SIZE - 1))
    {
        logIndex = LOG_BUFFER_SIZE - 1;
        // Shift elements in the log buffer using memcpy
        memcpy(&logBuffer[0], &logBuffer[1], logIndex * LOG_MESSAG_SIZE);
        // Copy the new string to the last index of the log buffer
        strcpy(logBuffer[LOG_BUFFER_SIZE - 1], newString);
        logIndex++;
    }
    else
    {
        strcpy(logBuffer[logIndex], newString);
        logIndex++;
    }

    sprintf(key, NVS_LOG_KEY_FMT, logIndex);
    utils_nvs_set_u8(NVS_LOG_IDX_KEY, logIndex);
    utils_nvs_set_str(key, logBuffer[logIndex - 1]);

    if (wifi_status == WIFI_STATUS_CONNECTED || eth_status == ETH_CONNECTED)
    {
        sendEventLog(newString);
    }
    else
    {
        pendinlogMessage(newString);
    }
}

static void loadMessagesFromNVS(void)
{
    char key[16];
    size_t len = LOG_MESSAG_SIZE;
    utils_nvs_get_u8(NVS_LOG_IDX_KEY, &logIndex);
    for (int i = 0; i < logIndex; i++)
    {
        sprintf(key, NVS_LOG_KEY_FMT, i);
        utils_nvs_get_str(key, logBuffer[i], &len);
    }

    utils_nvs_get_u8(NVS_PENDING_LOG_IDX_KEY, &pendinglogIndex);
    for (int i = 0; i < pendinglogIndex; i++)
    {
        sprintf(key, NVS_PENDING_LOG_KEY_FMT, i);
        utils_nvs_get_str(key, pendinglogBuffer[i], &len);
    }
}

void Eth_Status_String(char *str)
{
    switch (eth_status)
    {
    case ETH_NOT_CONNECTED:
        sprintf(str, "Not Connected");
        break;
    case ETH_CONNECTED_BUT_NO_IP:
        sprintf(str, "No IP");
        break;
    case ETH_CONNECTED:
        sprintf(str, "Connected");
        break;
    }
}

void WiFi_Status_String(char *str)
{
    switch (wifi_status)
    {
    case WIFI_STATUS_DISCONNECTED:
        sprintf(str, "Not Connected");
        break;
    case WIFI_STATUS_CONNECTED_BUT_NO_IP:
        sprintf(str, "No IP");
        break;
    case WIFI_STATUS_CONNECTED:
        sprintf(str, "Connected");
        break;
    }
}

void Door_Status_String(char *str)
{
    switch (door_status)
    {
    case DOOR_STATUS_OPEN:
        sprintf(str, "Open");
        break;
    case DOOR_STATUS_CLOSED:
        sprintf(str, "Closed");
        break;
    }
}

void setDoorStatus(Door_Status_t st)
{
    door_status = st;
}

void setEthernetStatus(Eth_Status_t st)
{
    eth_status = st;
}

void setWiFiStatus(WiFi_Status_t st)
{
    wifi_status = st;
}

void setWIFI_CREDENTIALS(const char *new_ssid, const char *new_pwd)
{
    strcpy(WIFI_SSID, new_ssid);
    utils_nvs_set_str(NVS_WIFI_SSID, WIFI_SSID);

    strcpy(WIFI_PASS, new_pwd);
    utils_nvs_set_str(NVS_WIFI_PASS, WIFI_PASS);
}

void setAPI_URL(const char *new_url)
{
    strcpy(API_URL, new_url);
    utils_nvs_set_str(NVS_API_URL, API_URL);
}

void setAPI_KEY(const char *new_key)
{
    strcpy(API_KEY, new_key);
    utils_nvs_set_str(NVS_API_KEY, API_KEY);
}

void setCOMPANY_ID(const char *new_id)
{
    strcpy(COMPANY_ID, new_id);
    utils_nvs_set_str(NVS_COMPANY_ID, COMPANY_ID);
}

void setADMIN_PASSWORD(const char *pwd)
{
    strcpy(ADMIN_PASSWORD, pwd);
    utils_nvs_set_str(NVS_ADMIN_PASSWORD, ADMIN_PASSWORD);
}

void setUSER_PASSWORD(const char *pwd)
{
    strcpy(USER_PASSWORD, pwd);
    utils_nvs_set_str(NVS_USER_PASSWORD, USER_PASSWORD);
}

void setAPI_INTERVAL(uint32_t new_interval)
{
    API_CALL_INTERVAL = new_interval;
    utils_nvs_set_u32(NVS_API_INTERVAL, API_CALL_INTERVAL);
}

void setAPI_STATUS(uint8_t new_status)
{
    API_CALL_STATUS = new_status;
    utils_nvs_set_u8(NVS_API_STATUS, API_CALL_STATUS);
}

void get_mac_address(void)
{
    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    sprintf(ESP_MAC_ADDR, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void reset_config(void)
{
    setWIFI_CREDENTIALS(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASSWORD);
    setAPI_INTERVAL(DEFAULT_API_CALL_INTERVAL);
    setAPI_STATUS(DEFAULT_API_CALL_STATUS);
    setAPI_URL(DEFAULT_API_URL);
    setADMIN_PASSWORD(DEFAULT_ADMIN_PASSWORD);
    setUSER_PASSWORD(DEFAULT_USER_PASSWORD);
}

void load_system_config(void)
{
    // Initialize NVS
    utils_nvs_init();
    loadMessagesFromNVS();
    size_t nvs_read_len = sizeof(ADMIN_PASSWORD);

    if (utils_nvs_get_str(NVS_ADMIN_PASSWORD, ADMIN_PASSWORD, &nvs_read_len) != ESP_OK)
    {
        strcpy(ADMIN_PASSWORD, DEFAULT_ADMIN_PASSWORD);
        utils_nvs_set_str(NVS_ADMIN_PASSWORD, ADMIN_PASSWORD);
        ESP_LOGI(TAG, "DEFAULT ADMIN_PASSWORD : %s", ADMIN_PASSWORD);
    }
    else
    {
        ESP_LOGI(TAG, "ADMIN_PASSWORD NVS : %s", ADMIN_PASSWORD);
    }

    if (utils_nvs_get_str(NVS_USER_PASSWORD, USER_PASSWORD, &nvs_read_len) != ESP_OK)
    {
        strcpy(USER_PASSWORD, DEFAULT_USER_PASSWORD);
        utils_nvs_set_str(NVS_USER_PASSWORD, USER_PASSWORD);
        ESP_LOGI(TAG, "DEFAULT USER_PASSWORD : %s", USER_PASSWORD);
    }
    else
    {
        ESP_LOGI(TAG, "USER_PASSWORD NVS : %s", USER_PASSWORD);
    }

    nvs_read_len = sizeof(WIFI_SSID);

    if (utils_nvs_get_str(NVS_WIFI_SSID, WIFI_SSID, &nvs_read_len) != ESP_OK)
    {
        strcpy(WIFI_SSID, DEFAULT_WIFI_SSID);
        utils_nvs_set_str(NVS_WIFI_SSID, WIFI_SSID);
        ESP_LOGW(TAG, "DEFAULT WIFI SSID : %s", WIFI_SSID);
    }
    else
    {
        ESP_LOGI(TAG, "WIFI SSID NVS : %s", WIFI_SSID);
    }

    nvs_read_len = sizeof(WIFI_PASS);

    if (utils_nvs_get_str(NVS_WIFI_PASS, WIFI_PASS, &nvs_read_len) != ESP_OK)
    {
        strcpy(WIFI_PASS, DEFAULT_WIFI_PASSWORD);
        utils_nvs_set_str(NVS_WIFI_PASS, WIFI_PASS);
        ESP_LOGW(TAG, "DEFAULT WIFI PASS : %s", WIFI_PASS);
    }
    else
    {
        ESP_LOGI(TAG, "WIFI PASS NVS : %s", WIFI_PASS);
    }

    nvs_read_len = sizeof(API_URL);

    if (utils_nvs_get_str(NVS_API_URL, API_URL, &nvs_read_len) != ESP_OK)
    {
        strcpy(API_URL, DEFAULT_API_URL);
        utils_nvs_set_str(NVS_API_URL, API_URL);
        ESP_LOGW(TAG, "DEFAULT API_URL : %s", API_URL);
    }
    else
    {
        ESP_LOGI(TAG, "API_URL NVS : %s", API_URL);
    }

    if (utils_nvs_get_str(NVS_API_KEY, API_KEY, &nvs_read_len) != ESP_OK)
    {
        setAPI_KEY(DEFAULT_API_KEY);
        ESP_LOGW(TAG, "DEFAULT API_URL : %s", API_KEY);
    }
    else
    {
        ESP_LOGI(TAG, "API_KEY NVS : %s", API_KEY);
    }

    if (utils_nvs_get_str(NVS_COMPANY_ID, COMPANY_ID, &nvs_read_len) != ESP_OK)
    {
        setCOMPANY_ID(DEFAULT_COMPANY_ID);
        ESP_LOGW(TAG, "DEFAULT COMPANY_ID : %s", COMPANY_ID);
    }
    else
    {
        ESP_LOGI(TAG, "COMPANY_ID NVS : %s", COMPANY_ID);
    }

    if (utils_nvs_get_u32(NVS_API_INTERVAL, &API_CALL_INTERVAL) != ESP_OK)
    {
        API_CALL_INTERVAL = DEFAULT_API_CALL_INTERVAL;
        utils_nvs_set_u32(NVS_API_INTERVAL, API_CALL_INTERVAL);
        ESP_LOGW(TAG, "DEFAULT API_CALL_INTERVAL : %lu", API_CALL_INTERVAL);
    }
    else
    {
        ESP_LOGI(TAG, "API_CALL_INTERVAL NVS : %lu", API_CALL_INTERVAL);
    }

    if (utils_nvs_get_u8(NVS_API_STATUS, &API_CALL_STATUS) != ESP_OK)
    {
        API_CALL_STATUS = DEFAULT_API_CALL_STATUS;
        utils_nvs_set_u8(NVS_API_STATUS, API_CALL_STATUS);
        ESP_LOGW(TAG, "DEFAULT API_CALL_STATUS : %u", API_CALL_STATUS);
    }
    else
    {
        ESP_LOGI(TAG, "API_CALL_STATUS NVS : %u", API_CALL_STATUS);
    }
}