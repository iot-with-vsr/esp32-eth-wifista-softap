#ifndef ds1307_INTERFACE_INCLUDED
#define ds1307_INTERFACE_INCLUDED
#include "ds1307.h"

void ds1307_SetTime(int year, int month, int day, int hh, int mm, int ss);
void ds1307_init(int RTC_SDA, int RTC_SCL);
#endif