#ifndef API_THREAD_INCLUDED
#define API_THREAD_INCLUDED
#include "system_config.h"

void start_api_thread(void);
void sendEventLog(const char *evt);
#endif