#ifndef SERVER_SETUP_INCLUDED
#define SERVER_SETUP_INCLUDED

#include <string.h>
#include <fcntl.h>
#include "esp_http_server.h"
#include "esp_chip_info.h"
#include "esp_random.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "cJSON.h"

esp_err_t start_rest_server(const char *base_path);
#endif