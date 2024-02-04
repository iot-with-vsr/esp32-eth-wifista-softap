#ifndef DS3231_INTERFACE_INCLUDED
#define DS3231_INTERFACE_INCLUDED
#include "ds3231.h"

void ds3231_SetTime(int year, int month, int day, int hh, int mm, int ss);
void ds3231_init(int RTC_SDA, int RTC_SCL);
#endif