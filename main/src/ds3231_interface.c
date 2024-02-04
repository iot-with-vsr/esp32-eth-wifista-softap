#include "ds3231_interface.h"
#include "utils.h"
#include "esp_log.h"

static const char *TAG = "ds3231-interface";

static i2c_dev_t dev;

void ds3231_SetTime(int year, int month, int day, int hh, int mm, int ss)
{
    struct tm ctime;
    ctime.tm_hour = hh;
    ctime.tm_min = mm;
    ctime.tm_sec = ss;
    ctime.tm_mday = day;
    ctime.tm_year = year - 1900;
    ctime.tm_mon = month - 1;
    ds3231_set_time(&dev, &ctime);
    system_set_time(&ctime);
}

void ds3231_init(int RTC_SDA, int RTC_SCL)
{
    memset(&dev, 0, sizeof(i2c_dev_t));

    ESP_ERROR_CHECK(ds3231_init_desc(&dev, 0, RTC_SDA, RTC_SCL));

    if (false)
    {
        ESP_LOGW(TAG, "ds3231 not initialized. Check connections");
    }
    else
    {
        struct tm time;
        ds3231_get_time(&dev, &time);
        time_t unix_time = mktime(&time);

        if (unix_time < 1706655848)
        {                           // if time is less than the time of writing this code . probably it is wrong
            unix_time = 1706655848; // Replace this with your timestamp
            // Convert timestamp to struct tm using gmtime
            struct tm *timeinfo = gmtime(&unix_time);
            ds3231_set_time(&dev, timeinfo);
            system_set_time(timeinfo);

            // ds3231_SetTime();
        }
        else
        {
            system_set_time(&time);
            // ESP_LOGI(TAG, "Time Was Set Already in RTC");
        }

        print_system_time();
    }
}