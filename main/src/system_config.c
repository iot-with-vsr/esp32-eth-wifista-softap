#include "utils.h"
#include "esp_log.h"
#include "esp_err.h"
#include "system_config.h"

static const char *TAG = "system_config";

char WIFI_SSID[32];
char WIFI_PASS[64];
char API_URL[120];
const char *API_USERNAME = "admin";
char API_PASSWORD[64];
uint32_t API_CALL_INTERVAL;
uint8_t API_CALL_STATUS;

Eth_Status_t eth_status;
WiFi_Status_t wifi_status;
Door_Status_t door_status;

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

void setADMIN_PASSWORD(const char *pwd)
{
    strcpy(API_PASSWORD, pwd);
    utils_nvs_set_str(NVS_ADMIN_PASSWORD, API_PASSWORD);
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

void reset_config(void)
{
    setWIFI_CREDENTIALS(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASSWORD);
    setAPI_INTERVAL(DEFAULT_API_CALL_INTERVAL);
    setAPI_STATUS(DEFAULT_API_CALL_STATUS);
    setAPI_URL(DEFAULT_API_URL);
    setADMIN_PASSWORD(DEFAULT_ADMIN_PASSWORD);
}

void load_system_config(void)
{
    // Initialize NVS
    utils_nvs_init();

    size_t nvs_read_len = sizeof(API_PASSWORD);

    if (utils_nvs_get_str(NVS_ADMIN_PASSWORD, API_PASSWORD, &nvs_read_len) != ESP_OK)
    {
        strcpy(WIFI_SSID, DEFAULT_ADMIN_PASSWORD);
        utils_nvs_set_str(NVS_ADMIN_PASSWORD, API_PASSWORD);
        ESP_LOGI(TAG, "DEFAULT API_PASSWORD : %s", API_PASSWORD);
    }
    else
    {
        ESP_LOGI(TAG, "API_PASSWORD NVS : %s", API_PASSWORD);
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