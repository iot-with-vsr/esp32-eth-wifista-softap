#pragma once
#include "ds3231_interface.h"
#include "ds1307_interface.h"
#define RTC_SDA 21
#define RTC_SCL 22

#define USE_DS3231 0
#define USE_DS1307 1

#define WHICH_RTC USE_DS3231

void RTCinit(void);
void RTCsettime(int year, int month, int day, int hh, int mm, int ss);