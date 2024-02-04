#include "utils.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <time.h>
#include <sys/time.h>

static const char *TAG = "utils";

static nvs_handle_t configNvsHandle;

void system_set_time(struct tm *timeinfo)
{
    struct timeval tv;

    time_t time_seconds = mktime(timeinfo);

    // Fill the timeval structure
    tv.tv_sec = time_seconds;
    tv.tv_usec = 0;

    if (settimeofday(&tv, NULL) == 0)
    {
        ESP_LOGI(TAG, "System time set successfully.\n");
    }
    else
    {
        ESP_LOGE(TAG, "Error setting system time");
    }
}

void current_time_str(char *str)
{
    if (str)
    {
        struct timeval tv;
        struct tm timeinfo;

        // Get current time
        gettimeofday(&tv, NULL);

        // Convert to struct tm for easy formatting
        localtime_r(&tv.tv_sec, &timeinfo);

        // Print formatted time
        sprintf(str, "%04d-%02d-%02dT%02d:%02d:%02d",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    }
}

void print_system_time(void)
{
    struct timeval tv;
    struct tm timeinfo;

    // Get current time
    gettimeofday(&tv, NULL);

    // Convert to struct tm for easy formatting
    localtime_r(&tv.tv_sec, &timeinfo);

    // Print formatted time
    ESP_LOGI(TAG, "Current system time: %04d-%02d-%02d %02d:%02d:%02d\n",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

int64_t millis(void)
{
    int64_t m = esp_timer_get_time(); // Return Time Since Boot in Microseconds
    m = m / 1000;
    return m;
}

int64_t micros(void)
{
    int64_t m = esp_timer_get_time(); // Return Time Since Boot in Microseconds
    return m;
}

esp_err_t utils_nvs_get_u8(const char *key, uint8_t *value)
{
    return nvs_get_u8(configNvsHandle, key, value);
}

esp_err_t utils_nvs_get_u32(const char *key, uint32_t *value)
{
    return nvs_get_u32(configNvsHandle, key, value);
}

esp_err_t utils_nvs_get_str(const char *key, char *value, size_t *len)
{
    return nvs_get_str(configNvsHandle, key, value, len);
}

void utils_nvs_set_str(const char *key, const char *val)
{
    nvs_set_str(configNvsHandle, key, val);
    nvs_commit(configNvsHandle);
}

void utils_nvs_set_u8(const char *key, uint8_t val)
{
    nvs_set_u8(configNvsHandle, key, val);
    nvs_commit(configNvsHandle);
}

void utils_nvs_set_u32(const char *key, uint32_t val)
{
    nvs_set_u32(configNvsHandle, key, val);
    nvs_commit(configNvsHandle);
}

void utils_nvs_init(void)
{
    esp_err_t nvsConfigErr = nvs_open("config", NVS_READWRITE, &configNvsHandle);
    if (nvsConfigErr != ESP_OK)
    {
        ESP_LOGW(TAG, "Failed to open NVS for configL %d", nvsConfigErr);
    }
}