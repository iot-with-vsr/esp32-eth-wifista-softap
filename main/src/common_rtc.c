#include "common_rtc.h"

void RTCinit(void)
{
#if WHICH_RTC == USE_DS1307
    ds1307_init(RTC_SDA, RTC_SCL);
#elif WHICH_RTC == USE_DS3231
    ds3231_init(RTC_SDA, RTC_SCL);
#endif
}

void RTCsettime(int year, int month, int day, int hh, int mm, int ss)
{
#if WHICH_RTC == USE_DS1307
    ds1307_SetTime(year, month, day, hh, mm, ss);
#elif WHICH_RTC == USE_DS3231
    ds3231_SetTime(year, month, day, hh, mm, ss);
#endif
}