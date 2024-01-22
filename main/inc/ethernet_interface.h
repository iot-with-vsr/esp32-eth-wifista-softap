#ifndef ETH_INTERFACE_INCLUDED
#define ETH_INTERFACE_INCLUDED

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "ethernet_init.h"
#include "sdkconfig.h"

void app_ethernet_init(void);

#endif