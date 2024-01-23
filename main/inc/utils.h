#ifndef UTILS_INCLUDED
#define UTILS_INCLUDED

#include <string.h>
#include <inttypes.h>
#include <nvs_flash.h>
#include "esp_err.h"

void utils_nvs_init(void);
esp_err_t utils_nvs_get_u8(const char *key, uint8_t *value);
esp_err_t utils_nvs_get_u32(const char *key, uint32_t *value);
esp_err_t utils_nvs_get_str(const char *key, char *value, size_t *len);
void utils_nvs_set_u32(const char *key, uint32_t val);
void utils_nvs_set_u8(const char *key, uint8_t val);
void utils_nvs_set_str(const char *key, const char *val);

#endif