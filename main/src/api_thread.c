#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include <ctype.h>
#include "api_thread.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_system.h"
#include <inttypes.h>
#include "driver/gpio.h"
static const char *TAG = "api-thread";
#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

#define RELAY_GPIO_PIN 2
#define RELAY_GPIO_BIT_MASK (1ULL << RELAY_GPIO_PIN)
#define BUZZER_GPIO_PIN 14
#define BUZZER_GPIO_BIT_MASK (1ULL << BUZZER_GPIO_PIN)
#define SENS_GPIO_PIN 16
#define SENS_GPIO_BIT_MASK (1ULL << SENS_GPIO_PIN)
#define BUTTON_GPIO_PIN 17
#define BUTTON_GPIO_BIT_MASK (1ULL << BUTTON_GPIO_PIN)

static int64_t lastApiCall = 0;

unsigned long Sens_Prev_time = 0;

bool Buzz_on = false;
bool Sens = false;
bool relayTriggered = false;
unsigned long relayChangeTime = 0;
int64_t buzzerInverseDuration = -1;
int64_t relayInverseDuration = -1;
unsigned long buzzerChangeTime = 0;

typedef enum
{
    InvaliCommand,
    NoPendingCommand,
    OpenDoorTemporary,
    CloseDoorTemporary,
    OpenDoorPermanent,
    CloseDoorPermanent,
    RingBuzzerTemporary,
    RingBuzzerPermanent,
    OffBuzzerTemporary,
    OffBuzzerPermanent
} CommandType_t;

typedef enum
{
    DurationType_Seconds,
    DurationType_Minute
} DurationType_t;

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer; // Buffer to store response of http request from event handler
    static int output_len;      // Stores number of bytes read
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        /*
         *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
         *  However, event handler can also be used in case chunked encoding is used.
         */
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            // If user_data buffer is configured, copy the response into the buffer
            int copy_len = 0;
            if (evt->user_data)
            {
                copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                if (copy_len)
                {
                    memcpy(evt->user_data + output_len, evt->data, copy_len);
                }
            }
            else
            {
                const int buffer_len = esp_http_client_get_content_length(evt->client);
                if (output_buffer == NULL)
                {
                    output_buffer = (char *)malloc(buffer_len);
                    output_len = 0;
                    if (output_buffer == NULL)
                    {
                        ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                        return ESP_FAIL;
                    }
                }
                copy_len = MIN(evt->data_len, (buffer_len - output_len));
                if (copy_len)
                {
                    memcpy(output_buffer + output_len, evt->data, copy_len);
                }
            }
            output_len += copy_len;
        }

        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
        if (output_buffer != NULL)
        {
            // Response is accumulated in output_buffer. Uncomment the below line to print the accumulated response
            // ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
        int mbedtls_err = 0;
        esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
        if (err != 0)
        {
            ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
            ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
        }
        if (output_buffer != NULL)
        {
            free(output_buffer);
            output_buffer = NULL;
        }
        output_len = 0;
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGI(TAG, "HTTP_EVENT_REDIRECT");
        esp_http_client_set_header(evt->client, "From", "user@example.com");
        esp_http_client_set_header(evt->client, "Accept", "text/html");
        esp_http_client_set_redirection(evt->client);
        break;
    }
    return ESP_OK;
}

char *url_encode(const char *input)
{
    size_t len = strlen(input);
    size_t encoded_len = 0;

    // Count the required size for the encoded string
    for (size_t i = 0; i < len; i++)
    {
        char c = input[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded_len++;
        }
        else
        {
            encoded_len += 3; // %XX takes three characters
        }
    }

    // Allocate memory for the encoded string
    char *encoded_str = (char *)malloc(encoded_len + 1); // +1 for the null terminator

    if (encoded_str == NULL)
    {
        // Handle memory allocation failure
        return NULL;
    }

    // Encode the string
    size_t j = 0;
    for (size_t i = 0; i < len && j < encoded_len; i++)
    {
        char c = input[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded_str[j++] = c;
        }
        else
        {
            snprintf(encoded_str + j, 4, "%%%02X", c);
            j += 3;
        }
    }

    // Null-terminate the encoded string
    encoded_str[j] = '\0';

    return encoded_str;
}

static esp_err_t perform_http_request(const char *url, esp_http_client_method_t method,
                                      const char *write_buf, size_t write_len,
                                      char **read_buf, size_t *read_len)
{

    if (!isInternetConnected())
    {
        return ESP_FAIL;
    }

    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
    esp_http_client_config_t config = {
        .url = url,
        .method = method,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer};

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL)
    {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    // Set write data if provided
    if (write_buf != NULL && write_len > 0)
    {
        esp_http_client_set_post_field(client, write_buf, write_len);
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %" PRIu64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
        // Get the response information
        *read_len = esp_http_client_get_content_length(client);
        *read_buf = malloc(*read_len + 1); // +1 for null-terminator

        strncpy(*read_buf, local_response_buffer, *read_len);
        (*read_buf)[*read_len] = '\0';
    }
    else
    {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }

    // Clean up
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    return err;
}

DurationType_t DurationType_From_String(const char *pString)
{
    DurationType_t dur = DurationType_Minute;

    if (strcmp(pString, "Seconds") == 0)
    {
        dur = DurationType_Seconds;
    }

    return dur;
}

const char *CommandType_To_String(CommandType_t cmd)
{
    switch (cmd)
    {
    case NoPendingCommand:
        return "NoPendingCommand";
    case OpenDoorTemporary:
        return "OpenDoorTemporary";
    case OpenDoorPermanent:
        return "OpenDoorPermanent";
    case CloseDoorTemporary:
        return "CloseDoorTemporary";
    case CloseDoorPermanent:
        return "CloseDoorPermanent";
    case RingBuzzerTemporary:
        return "RingBuzzerTemporary";
    case RingBuzzerPermanent:
        return "RingBuzzerPermanent";
    case OffBuzzerTemporary:
        return "OffBuzzerTemporary";
    case OffBuzzerPermanent:
        return "OffBuzzerPermanent";
    default:
        return "InvalidCommand";
    }
}

CommandType_t CommandType_From_String(const char *pString)
{
    CommandType_t cmd = InvaliCommand;
    if (strcmp(pString, "NoPendingCommand") == 0)
    {
        cmd = NoPendingCommand;
    }
    else if (strcmp(pString, "OpenDoorTemporary") == 0)
    {
        cmd = OpenDoorTemporary;
    }
    else if (strcmp(pString, "OpenDoorPermanent") == 0)
    {
        cmd = OpenDoorPermanent;
    }
    else if (strcmp(pString, "CloseDoorTemporary") == 0)
    {
        cmd = CloseDoorTemporary;
    }
    else if (strcmp(pString, "CloseDoorPermanent") == 0)
    {
        cmd = CloseDoorPermanent;
    }
    else if (strcmp(pString, "RingBuzzerTemporary") == 0)
    {
        cmd = RingBuzzerTemporary;
    }
    else if (strcmp(pString, "RingBuzzerPermanent") == 0)
    {
        cmd = RingBuzzerPermanent;
    }
    else if (strcmp(pString, "OffBuzzerTemporary") == 0)
    {
        cmd = OffBuzzerTemporary;
    }
    else if (strcmp(pString, "OffBuzzerPermanent") == 0)
    {
        cmd = OffBuzzerPermanent;
    }

    return cmd;
}

bool relayOn = false;
static char log_msg[LOG_MESSAG_SIZE];
void setRelayState(int state)
{
#if RELAY_TYPE == NORMALLY_OPEN
    gpio_set_level(RELAY_GPIO_PIN, state);
#elif RELAY_TYPE == NORMALLY_CLOSED
    gpio_set_level(RELAY_GPIO_PIN, !state);
#endif
    relayOn = state;
    sprintf(log_msg, "DOOR %s", (state ? "OPEN" : "CLOSED"));
    logMessage(log_msg);
}

void setBuzzerState(int state)
{
    gpio_set_level(BUZZER_GPIO_PIN, state);
    Buzz_on = state;
    sprintf(log_msg, "BUZZER %s", (state ? "ON" : "OFF"));
    logMessage(log_msg);
}

void saveCommandLog(CommandType_t cmd)
{
    char timeStr[40];
    current_time_str(timeStr);

    char URL[700];
    char *encoded_time = url_encode(timeStr);

    sprintf(URL, "%s/api/DeviceEventsHandled/SaveLog?ApiKey=%s&CompanyID=%s&DeviceSerial=%s&EventType=%s&EventDateTime=%s",
            API_URL, API_KEY, COMPANY_ID, ESP_MAC_ADDR, CommandType_To_String(cmd), encoded_time);

    free(encoded_time);
    char *resp = NULL;
    size_t resp_len = 0;

    ESP_LOGI(TAG, "URL : %s", URL);

    if (perform_http_request(URL, HTTP_METHOD_POST, NULL, 0, &resp, &resp_len) == ESP_OK)
    {
        if (resp_len > 0 && resp)
        {
            // logMessage("API Response Success");
            ESP_LOGI(TAG, "Resp : %s", resp);
            // parseCommand(resp);
        }
        else
        {
            // logMessage("API No Response");
            ESP_LOGI(TAG, "No Response");
        }
    }
    else
    {
        // logMessage("API Request not sent");
        ESP_LOGI(TAG, "API Request not sent");
    }

    free(resp);
    resp = NULL;
}

void sendEventLog(const char *evt)
{
    char timeStr[40];
    current_time_str(timeStr);

    char URL[700];

    char *encoded_evt = url_encode(evt);
    char *encoded_time = url_encode(timeStr);

    sprintf(URL, "%s/api/DeviceEventsHandled/SaveLog?ApiKey=%s&CompanyID=%s&DeviceSerial=%s&EventType=%s&EventDateTime=%s",
            API_URL, API_KEY, COMPANY_ID, ESP_MAC_ADDR, encoded_evt, encoded_time);

    free(encoded_evt);
    free(encoded_time);

    char *resp = NULL;
    size_t resp_len = 0;

    ESP_LOGI(TAG, "URL : %s", URL);

    if (perform_http_request(URL, HTTP_METHOD_POST, NULL, 0, &resp, &resp_len) == ESP_OK)
    {
        if (resp_len > 0 && resp)
        {
            // logMessage("API Response Success");
            ESP_LOGI(TAG, "Resp : %s", resp);
            // parseCommand(resp);
        }
        else
        {
            // logMessage("API No Response");
            ESP_LOGI(TAG, "No Response");
        }
    }
    else
    {
        // logMessage("API Request not sent");
        ESP_LOGI(TAG, "API Request not sent");
    }

    free(resp);
    resp = NULL;
}

void updateRecord(uint64_t cmd_id)
{
    char timeStr[40];
    current_time_str(timeStr);

    char URL[700];

    sprintf(URL, "%s/api/UpdateCommandStatus/UpdateRecord?ApiKey=%s&CompanyID=%s&DeviceSerial=%s&CommandID=%llu",
            API_URL, API_KEY, COMPANY_ID, ESP_MAC_ADDR, cmd_id);

    char *resp = NULL;
    size_t resp_len = 0;

    ESP_LOGI(TAG, "URL : %s", URL);

    logMessage("UPDATE RECORD");
    if (perform_http_request(URL, HTTP_METHOD_POST, NULL, 0, &resp, &resp_len) == ESP_OK)
    {
        if (resp_len > 0 && resp)
        {
            logMessage("API Response Success");
            ESP_LOGI(TAG, "Resp : %s", resp);
            // parseCommand(resp);
        }
        else
        {
            logMessage("API No Response");
            ESP_LOGI(TAG, "No Response");
        }
    }
    else
    {
        logMessage("API Request not sent");
        ESP_LOGI(TAG, "API Request not sent");
    }

    free(resp);
    resp = NULL;
}

void parseCommand(const char *pJson)
{

    CommandType_t cmd = InvaliCommand;
    DurationType_t duration_type = DurationType_Seconds;
    uint64_t command_duration = 0;
    uint64_t command_id = 0;

    cJSON *root = cJSON_Parse(pJson);
    if (root)
    {
        cJSON *CommandType = cJSON_GetObjectItem(root, "CommandType");
        if (CommandType && cJSON_IsString(CommandType))
        {
            cmd = CommandType_From_String(CommandType->valuestring);

            if (cmd == InvaliCommand)
            {
                ESP_LOGI(TAG, "Invalid Command : %s", CommandType->valuestring);
            }
            else if (cmd == NoPendingCommand)
            {
                ESP_LOGI(TAG, "No Pending Command");
            }
        }

        if (!(cmd == InvaliCommand || cmd == NoPendingCommand))
        {
            cJSON *CommandID = cJSON_GetObjectItem(root, "CommandID");
            if (CommandID && cJSON_IsString(CommandID))
            {
                sscanf(CommandID->valuestring, "%llu", &command_id);
                ESP_LOGI(TAG, "command_id : %llu", command_id);
            }

            cJSON *DurationType_Minute_Seconds = cJSON_GetObjectItem(root, "DurationType_Minute_Seconds");
            if (DurationType_Minute_Seconds && cJSON_IsString(DurationType_Minute_Seconds))
            {
                duration_type = DurationType_From_String(DurationType_Minute_Seconds->valuestring);
                ESP_LOGI(TAG, "duration_type : %d", duration_type);
            }

            cJSON *CommandDuration = cJSON_GetObjectItem(root, "CommandDuration");
            if (CommandDuration && cJSON_IsString(CommandDuration))
            {
                sscanf(CommandDuration->valuestring, "%llu", &command_duration);
                if (duration_type == DurationType_Minute)
                {
                    command_duration = command_duration * 60;
                }

                ESP_LOGI(TAG, "command_duration[seconds] : %llu", command_duration);
            }
        }

        cJSON_Delete(root);
    }

    if (cmd != InvaliCommand)
    {
        if (cmd == OpenDoorPermanent)
        {
            ESP_LOGI(TAG, "Open Door");
            setRelayState(1);
            relayInverseDuration = -1;
        }
        else if (cmd == CloseDoorPermanent)
        {
            ESP_LOGI(TAG, "Close Door");
            setRelayState(0);
            relayInverseDuration = -1;
        }
        else if (cmd == OpenDoorTemporary)
        {
            ESP_LOGI(TAG, "Opening Door For %llu seconds", command_duration);
            setRelayState(1);
            relayInverseDuration = command_duration * 1000;
            relayChangeTime = millis();
        }
        else if (cmd == CloseDoorTemporary)
        {
            ESP_LOGI(TAG, "Closing Door For %llu seconds", command_duration);
            setRelayState(0);
            relayInverseDuration = command_duration * 1000;
            relayChangeTime = millis();
        }
        else if (cmd == RingBuzzerTemporary)
        {
            ESP_LOGI(TAG, "Ring Buzzer For %llu seconds", command_duration);
            setBuzzerState(1);
            buzzerInverseDuration = command_duration * 1000;
            buzzerChangeTime = millis();
        }
        else if (cmd == OffBuzzerTemporary)
        {
            ESP_LOGI(TAG, "Off Buzzer For %llu seconds", command_duration);
            setBuzzerState(0);
            buzzerInverseDuration = command_duration * 1000;
            buzzerChangeTime = millis();
        }
        else if (cmd == RingBuzzerPermanent)
        {
            ESP_LOGI(TAG, "Ring Buzzer");
            setBuzzerState(1);
            buzzerInverseDuration = -1;
        }
        else if (cmd == OffBuzzerPermanent)
        {
            ESP_LOGI(TAG, "Off Buzzer");
            setBuzzerState(0);
            buzzerInverseDuration = -1;
        }
    }

    if (cmd != NoPendingCommand)
    {
        saveCommandLog(cmd);
        updateRecord(command_id);
    }
}

void getCommandsForDevice()
{
    char URL[700];

    sprintf(URL, "%s/api/CommandsForDevice/GetCommands?ApiKey=%s&CompanyID=%s&DeviceSerial=%s",
            API_URL, API_KEY, COMPANY_ID, ESP_MAC_ADDR);

    char *resp = NULL;
    size_t resp_len = 0;

    ESP_LOGI(TAG, "URL : %s", URL);

    logMessage("GET COMMANDS");
    if (perform_http_request(URL, HTTP_METHOD_GET, NULL, 0, &resp, &resp_len) == ESP_OK)
    {
        if (resp_len > 0 && resp)
        {
            logMessage("API Response Success");
            ESP_LOGI(TAG, "Resp : %s", resp);
            parseCommand(resp);
        }
        else
        {
            logMessage("API No Response");
            ESP_LOGI(TAG, "No Response");
        }
    }
    else
    {
        logMessage("API Request not sent");
        ESP_LOGI(TAG, "API Request not sent");
    }

    free(resp);
    resp = NULL;
}

static void apiThread(void *pvParameters)
{
    (void)pvParameters;

    uint8_t current_state_internet = false;
    uint8_t last_state_internet = false;
    for (;;)
    {
        while (!(wifi_status == WIFI_STATUS_CONNECTED || eth_status == ETH_CONNECTED))
        {
            current_state_internet = false;
            if (last_state_internet != current_state_internet)
            {
                logMessage("INTERNET DISCONNECTED");
            }
            vTaskDelay(pdMS_TO_TICKS(3000));
        }

        if (millis() - lastApiCall > (API_CALL_INTERVAL * 1000))
        {
            if (wifi_status == WIFI_STATUS_CONNECTED || eth_status == ETH_CONNECTED)
            {
                current_state_internet = true;

                if (last_state_internet != current_state_internet)
                {
                    logMessage("INTERNET CONNECTED");
                    sendPendingLogs();
                }

                getCommandsForDevice();
                lastApiCall = millis();
            }
        }

        if (buzzerInverseDuration != -1)
        {
            if (millis() - buzzerChangeTime >= buzzerInverseDuration)
            {
                ESP_LOGI(TAG, "Setting Buzzer State : %s", Buzz_on ? "OFF" : "ON");
                setBuzzerState(!Buzz_on);
                buzzerInverseDuration = -1;
            }
        }

        if (relayInverseDuration != -1)
        {
            if (millis() - relayChangeTime >= relayInverseDuration)
            {
                ESP_LOGI(TAG, "Setting Relay State : %s", relayOn ? "OFF" : "ON");
                setRelayState(!relayOn);
                relayInverseDuration = -1;
            }
        }

        last_state_internet = current_state_internet;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

uint8_t lastButtonState = 0;
unsigned long relayTurnedOnAt = 0;
unsigned long relayOnDuration = 10000; // MS

static void buttonThread(void *pvParameters)
{
    (void)pvParameters;

    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_DISABLE};

    io_conf.pin_bit_mask = RELAY_GPIO_BIT_MASK;
    gpio_config(&io_conf);
    setRelayState(0);

    io_conf.pin_bit_mask = BUZZER_GPIO_BIT_MASK;
    gpio_config(&io_conf);
    setBuzzerState(0);

    io_conf.mode = GPIO_MODE_INPUT;

    io_conf.pin_bit_mask = SENS_GPIO_BIT_MASK;
    gpio_config(&io_conf);

    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    io_conf.pin_bit_mask = BUTTON_GPIO_BIT_MASK;
    gpio_config(&io_conf);

    Buzz_on = false;
    Sens = false;

    lastButtonState = gpio_get_level(BUTTON_GPIO_PIN);

    for (;;)
    {

        if (Sens)
        {
            if (SENS_TYPE ^ gpio_get_level(SENS_GPIO_PIN))
            {
                Sens = false;
                if (Buzz_on)
                {
                    ESP_LOGI(TAG, "Turning off Buzzer");
                    gpio_set_level(SENS_GPIO_PIN, 0);
                    Buzz_on = false;
                }
            }
            else if ((millis() - Sens_Prev_time) > SENS_DETECT_TIME)
            {
                if (!Buzz_on)
                {
                    ESP_LOGI(TAG, "Turning on Buzzer");
                    gpio_set_level(SENS_GPIO_PIN, 1);
                    Buzz_on = true;
                }
            }
        }
        else if (!Sens)
        {
            if (!(SENS_TYPE ^ gpio_get_level(SENS_GPIO_PIN)))
            {
                Sens_Prev_time = millis();
                ESP_LOGI(TAG, "Triggered");
                Sens = true;
            }
        }

        uint8_t currentButtonState = gpio_get_level(BUTTON_GPIO_PIN);

        if (currentButtonState != lastButtonState && currentButtonState == 0)
        {
            ESP_LOGI(TAG, "RELAY ON");
            setRelayState(1);
            relayTurnedOnAt = millis();
            // if(relayTriggered){
            //     ESP_LOGI(TAG, "RELAY OFF");
            //     setRelayState(0);
            // }else{
            //     setRelayState(1);
            //     ESP_LOGI(TAG, "RELAY ON");
            // }
            // relayTriggered = !relayTriggered;
        }
        lastButtonState = currentButtonState;

        if (relayOn && (relayTurnedOnAt != 0))
        {
            if (millis() - relayTurnedOnAt >= relayOnDuration)
            {
                ESP_LOGI(TAG, "RELAY OFF");
                setRelayState(0);
                relayTurnedOnAt = 0;
            }
        }

        // if(!gpio_get_level(BUTTON_GPIO_PIN) && !relayTriggered){
        //     relayTriggered = true;
        //     setRelayState(1);
        // }else if(gpio_get_level(BUTTON_GPIO_PIN) && relayTriggered){
        //     relayTriggered = false;
        //     setRelayState(0);
        // }

        // if (!relayTriggered)
        // {
        //     if (!(BUTTON_TYPE ^ gpio_get_level(SENS_GPIO_PIN)))
        //     {
        //         ESP_LOGI(TAG, "Turning On Relay");
        //         setRelayState(1);
        //         relayChangeTime = millis();
        //         relayTriggered = false;
        //     }
        // }
        // else
        // {

        //     if (millis() - relayChangeTime > RELAY_ON_DURATION)
        //     {
        //         ESP_LOGI(TAG, "Turning Off Relay");
        //         setRelayState(0);
        //         relayChangeTime = millis();
        //         relayTriggered = false;
        //     }
        // }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    vTaskDelete(NULL);
}

void start_api_thread(void)
{
    // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
    xTaskCreate(apiThread, "api-thread", 1024 * 10, NULL, tskIDLE_PRIORITY + 9, NULL);
    xTaskCreate(buttonThread, "button-thread", 1024 * 8, NULL, tskIDLE_PRIORITY + 9, NULL);
}