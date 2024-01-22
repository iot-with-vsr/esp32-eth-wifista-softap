idf_component_register(SRCS "wifi_init.c"
                       PRIV_REQUIRES driver 
                                esp_wifi
                                nvs_flash
                       INCLUDE_DIRS ".")
