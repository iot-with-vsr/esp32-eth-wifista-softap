#include "utils.h"
#include "esp_log.h"

static const char *TAG = "utils";

static nvs_handle_t configNvsHandle;

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