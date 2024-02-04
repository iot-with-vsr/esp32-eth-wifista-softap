#include "server_setup.h"
#include "esp_tls_crypto.h"
#include "esp_wifi.h"
#include "system_config.h"
#include "wifi_interface.h"
#include "common_rtc.h"

static const char *TAG = "server_setup";

#define REST_CHECK(a, str, goto_tag, ...)                                         \
    do                                                                            \
    {                                                                             \
        if (!(a))                                                                 \
        {                                                                         \
            ESP_LOGE(TAG, "%s(%d): " str, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            goto goto_tag;                                                        \
        }                                                                         \
    } while (0)

#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 128)
#define SCRATCH_BUFSIZE (10240)

typedef struct rest_server_context
{
    char base_path[ESP_VFS_PATH_MAX + 1];
    char scratch[SCRATCH_BUFSIZE];
} rest_server_context_t;

#define CHECK_FILE_EXTENSION(filename, ext) (strcasecmp(&filename[strlen(filename) - strlen(ext)], ext) == 0)

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

typedef enum
{
    ADMIN_LOGIN,
    USER_LOGIN,
    ANY_USER
} Auth_Who_t;

static char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));
    digest = calloc(1, 6 + n + 1);
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    free(user_info);
    return digest;
}

static bool authorize(httpd_req_t *req, Auth_Who_t who, bool send_realm)
{
    char *buf = NULL;
    size_t buf_len = 0;
    bool authorized = false;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1)
    {
        buf = calloc(1, buf_len);
        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        }
        else
        {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *admin_credentials = http_auth_basic(ADMIN_USERNAME, ADMIN_PASSWORD);
        char *user_credentials = http_auth_basic(USER_USERNAME, USER_PASSWORD);

        uint8_t is_admin_verified = !strncmp(admin_credentials, buf, buf_len);
        uint8_t is_user_verified = !strncmp(user_credentials, buf, buf_len);

        if (who == ADMIN_LOGIN)
        {
            ESP_LOGI(TAG, "ADMIN LOGIN");
        }
        else if (who == USER_LOGIN)
        {
            ESP_LOGI(TAG, "USER_LOGIN");
        }
        else if (who == ANY_USER)
        {
            ESP_LOGI(TAG, "ANY_USER");
        }

        if (who == ADMIN_LOGIN && is_admin_verified)
        {
            authorized = true;
        }
        else if (who == USER_LOGIN && is_user_verified)
        {
            authorized = true;
        }
        else if ((who == ANY_USER) && (is_admin_verified || is_user_verified))
        {
            authorized = true;
        }
        else
        {
            authorized = false;
        }

        if (!authorized)
        {
            ESP_LOGE(TAG, "Not authenticated");

            if (send_realm)
            {
                httpd_resp_set_status(req, HTTPD_401);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_set_hdr(req, "Connection", "keep-alive");
                httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
                httpd_resp_send(req, NULL, 0);
            }
        }
        else
        {
            ESP_LOGI(TAG, "Authenticated!");
        }
        free(admin_credentials);
        free(user_credentials);
        free(buf);
    }
    else
    {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return authorized;
}

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filepath)
{
    const char *type = "text/plain";
    if (CHECK_FILE_EXTENSION(filepath, ".html"))
    {
        type = "text/html";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".js"))
    {
        type = "application/javascript";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".css"))
    {
        type = "text/css";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".png"))
    {
        type = "image/png";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".ico"))
    {
        type = "image/x-icon";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".svg"))
    {
        type = "text/xml";
    }
    return httpd_resp_set_type(req, type);
}

esp_err_t log_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    // Concatenate log messages with '\n' separator
    int logIndex = getNumLogs();

    char response[logIndex * LOG_MESSAG_SIZE]; // Assuming each message is a string of up to 255 characters
    response[0] = '\0';
    for (int i = 0; i < logIndex && i < LOG_BUFFER_SIZE; i++)
    {
        strcat(response, getLogAtIdx(i));
        strcat(response, "\n");
    }

    // Send the response
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, response, strlen(response));

    return ESP_OK;
}

esp_err_t pending_log_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    // Concatenate log messages with '\n' separator
    int logIndex = getNumPendingLogs();

    char response[logIndex * LOG_MESSAG_SIZE]; // Assuming each message is a string of up to 255 characters
    response[0] = '\0';
    for (int i = 0; i < logIndex && i < LOG_BUFFER_SIZE; i++)
    {
        strcat(response, getPendingLogAtIdx(i));
        strcat(response, "\n");
    }

    // Send the response
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, response, strlen(response));

    return ESP_OK;
}

static esp_err_t user_get_handler(httpd_req_t *req)
{
    if (!authorize(req, USER_LOGIN, true))
    {
        return ESP_OK; // if not authorize return here
    }

    char filepath[FILE_PATH_MAX];

    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    strlcpy(filepath, rest_context->base_path, sizeof(filepath));
    strlcat(filepath, "/index.html", sizeof(filepath));

    int fd = open(filepath, O_RDONLY, 0);
    if (fd == -1)
    {
        ESP_LOGE(TAG, "Failed to open file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
        return ESP_FAIL;
    }

    set_content_type_from_file(req, filepath);

    char *chunk = rest_context->scratch;
    ssize_t read_bytes;
    do
    {
        /* Read file in chunks into the scratch buffer */
        read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
        if (read_bytes == -1)
        {
            ESP_LOGE(TAG, "Failed to read file : %s", filepath);
        }
        else if (read_bytes > 0)
        {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK)
            {
                close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
                return ESP_FAIL;
            }
        }
    } while (read_bytes > 0);
    /* Close file after sending complete */
    close(fd);
    ESP_LOGI(TAG, "File sending complete");
    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Send HTTP response with the contents of the requested file */
static esp_err_t admin_get_handler(httpd_req_t *req)
{
    if (!authorize(req, ADMIN_LOGIN, true))
    {
        return ESP_OK; // if not authorize return here
    }

    char filepath[FILE_PATH_MAX];

    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    strlcpy(filepath, rest_context->base_path, sizeof(filepath));
    strlcat(filepath, req->uri, sizeof(filepath));

    int fd = open(filepath, O_RDONLY, 0);
    if (fd == -1)
    {
        ESP_LOGE(TAG, "Failed to open file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
        return ESP_FAIL;
    }

    set_content_type_from_file(req, filepath);

    char *chunk = rest_context->scratch;
    ssize_t read_bytes;
    do
    {
        /* Read file in chunks into the scratch buffer */
        read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
        if (read_bytes == -1)
        {
            ESP_LOGE(TAG, "Failed to read file : %s", filepath);
        }
        else if (read_bytes > 0)
        {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK)
            {
                close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
                return ESP_FAIL;
            }
        }
    } while (read_bytes > 0);
    /* Close file after sending complete */
    close(fd);
    ESP_LOGI(TAG, "File sending complete");
    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Send HTTP response with the contents of the requested file */
static esp_err_t rest_common_get_handler(httpd_req_t *req)
{

    char filepath[FILE_PATH_MAX];

    rest_server_context_t *rest_context = (rest_server_context_t *)req->user_ctx;
    strlcpy(filepath, rest_context->base_path, sizeof(filepath));
    if (req->uri[strlen(req->uri) - 1] == '/')
    {
        strlcat(filepath, "/index.html", sizeof(filepath));

        if (!authorize(req, USER_LOGIN, true))
        {
            return ESP_OK;
        }
    }
    else
    {
        strlcat(filepath, req->uri, sizeof(filepath));
        if (!authorize(req, ANY_USER, true))
        {
            return ESP_OK;
        }
    }
    int fd = open(filepath, O_RDONLY, 0);
    if (fd == -1)
    {
        ESP_LOGE(TAG, "Failed to open file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
        return ESP_FAIL;
    }

    set_content_type_from_file(req, filepath);

    char *chunk = rest_context->scratch;
    ssize_t read_bytes;
    do
    {
        /* Read file in chunks into the scratch buffer */
        read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
        if (read_bytes == -1)
        {
            ESP_LOGE(TAG, "Failed to read file : %s", filepath);
        }
        else if (read_bytes > 0)
        {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK)
            {
                close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "");
                return ESP_FAIL;
            }
        }
    } while (read_bytes > 0);
    /* Close file after sending complete */
    close(fd);
    ESP_LOGI(TAG, "File sending complete");
    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t change_date_time_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    int total_len = req->content_len;
    int cur_len = 0;
    char *buf = ((rest_server_context_t *)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);

    char resp[100];
    int year, month, day, hh, mm, ss;
    // Parse JSON
    cJSON *cYear = cJSON_GetObjectItemCaseSensitive(root, "year");
    cJSON *cMonth = cJSON_GetObjectItemCaseSensitive(root, "month");
    cJSON *cDay = cJSON_GetObjectItemCaseSensitive(root, "day");
    cJSON *cHH = cJSON_GetObjectItemCaseSensitive(root, "hh");
    cJSON *cMM = cJSON_GetObjectItemCaseSensitive(root, "mm");
    cJSON *cSS = cJSON_GetObjectItemCaseSensitive(root, "ss");

    if (cYear && cMonth && cDay && cHH && cMM && cSS)
    {
        year = cYear->valueint;
        month = cMonth->valueint;
        day = cDay->valueint;
        hh = cHH->valueint;
        mm = cMM->valueint;
        ss = cSS->valueint;

        RTCsettime(year, month, day, hh, mm, ss);
        strcpy(resp, "Date/Time saved successfully");
    }
    else
    {
        strcpy(resp, "Failed");
    }

    cJSON_Delete(root);
    httpd_resp_sendstr(req, "Date/Time saved successfully");
    return ESP_OK;
}

static esp_err_t factory_reset_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    reset_config();

    httpd_resp_sendstr(req, "Factory Reset Successful");
    return ESP_OK;
}

static esp_err_t api_settings_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    int total_len = req->content_len;
    int cur_len = 0;
    char *buf = ((rest_server_context_t *)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);

    cJSON *api_url = cJSON_GetObjectItemCaseSensitive(root, "url");
    if (api_url)
    {
        setAPI_URL(api_url->valuestring);
        ESP_LOGI(TAG, "URL : %s", API_URL);
    }

    cJSON *api_interval = cJSON_GetObjectItemCaseSensitive(root, "interval");
    if (api_interval)
    {
        setAPI_INTERVAL(api_interval->valueint);
        ESP_LOGI(TAG, "INTERVAL : %lu", API_CALL_INTERVAL);
    }

    cJSON *api_status = cJSON_GetObjectItemCaseSensitive(root, "status");
    if (api_status)
    {
        setAPI_STATUS(api_status->valueint);
        ESP_LOGI(TAG, "STATUS : %u", API_CALL_STATUS);
    }

    cJSON *api_key = cJSON_GetObjectItemCaseSensitive(root, "key");
    if (api_key)
    {
        setAPI_KEY(api_key->valuestring);
        ESP_LOGI(TAG, "API KEY : %s", API_KEY);
    }

    cJSON *comp_id = cJSON_GetObjectItemCaseSensitive(root, "id");
    if (comp_id)
    {
        setCOMPANY_ID(comp_id->valuestring);
        ESP_LOGI(TAG, "STATUS : %s", COMPANY_ID);
    }

    // Parse JSON

    cJSON_Delete(root);
    httpd_resp_sendstr(req, "API Settings saved successfully");
    return ESP_OK;
}

static esp_err_t save_wifi_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    int total_len = req->content_len;
    int cur_len = 0;
    char *buf = ((rest_server_context_t *)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);

    cJSON *ssid = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *pwd = cJSON_GetObjectItemCaseSensitive(root, "pwd");
    int ret = 0;
    if (ssid && pwd)
    {
        setWIFI_CREDENTIALS(ssid->valuestring, pwd->valuestring);
        ESP_LOGI(TAG, "WIFI SSID : %s", WIFI_SSID);
        ESP_LOGI(TAG, "WIFI PASS : %s", WIFI_PASS);
        ret = 1;
        httpd_resp_sendstr(req, "WiFi Credentials saved successfully");
        vTaskDelay(pdMS_TO_TICKS(300));
        esp_wifi_stop();
        app_wifi_connect();
    }
    else
    {
        httpd_resp_sendstr(req, "Invalid request body");
    }

    cJSON_Delete(root);
    return ESP_OK;
}

#define DEFAULT_SCAN_LIST_SIZE 15

esp_err_t wifi_scan_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    // char response_buffer[2048];
    // response_buffer[0] = '\0';
    esp_wifi_scan_start(NULL, true);
    ESP_LOGI(TAG, "Max AP number ap_info can hold = %u", number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);
    cJSON *root = cJSON_CreateObject();
    cJSON *scan_array = cJSON_AddArrayToObject(root, "scan_result");
    for (int i = 0; i < number; i++)
    {
        // ESP_LOGI(TAG, "SSID \t\t%s", ap_info[i].ssid);
        // ESP_LOGI(TAG, "RSSI \t\t%d", ap_info[i].rssi);
        cJSON_AddItemToArray(scan_array, cJSON_CreateString((const char *)ap_info[i].ssid));
        // strcat(response_buffer, (const char *)ap_info[i].ssid);
        // strcat(response_buffer, "\n");
    }

    // free(ap_records);
    char *response_buffer = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_buffer, HTTPD_RESP_USE_STRLEN);
    cJSON_Delete(root);
    free(response_buffer);
    return ESP_OK;
}

static esp_err_t change_password_handler(httpd_req_t *req)
{

    bool isAdmin = false;
    bool isUser = false;
    isAdmin = authorize(req, ADMIN_LOGIN, false);

    if (isAdmin)
    {
        goto CHANGE_PWD;
    }

    isUser = authorize(req, USER_LOGIN, false);

    if (isUser)
    {
        goto CHANGE_PWD;
    }

    httpd_resp_sendstr(req, "Auth Failed");
    return ESP_OK;

CHANGE_PWD:

    int total_len = req->content_len;
    int cur_len = 0;
    char *buf = ((rest_server_context_t *)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);

    cJSON *current = cJSON_GetObjectItemCaseSensitive(root, "current");
    cJSON *new = cJSON_GetObjectItemCaseSensitive(root, "new");
    int ret = 0;
    if (current && new)
    {
        if ((strcmp(current->valuestring, ADMIN_PASSWORD) == 0) && (isAdmin))
        {
            setADMIN_PASSWORD(new->valuestring);
            ret = 1;
        }
        else if ((strcmp(current->valuestring, USER_PASSWORD) == 0) && (isUser))
        {
            setUSER_PASSWORD(new->valuestring);
            ret = 1;
        }
        else
        {
            httpd_resp_sendstr(req, "Wrong Password");
        }
    }
    else
    {
        httpd_resp_sendstr(req, "Invalid request body");
    }

    cJSON_Delete(root);
    if (ret)
        httpd_resp_sendstr(req, "Password Changed successfully");
    return ESP_OK;
}

// HTTP GET handler function
esp_err_t mac_address_handler(httpd_req_t *req)
{

    // Send the MAC address as the HTTP response
    httpd_resp_send(req, ESP_MAC_ADDR, strlen(ESP_MAC_ADDR));

    return ESP_OK;
}

esp_err_t get_wifi_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();

    if (root)
    {
        cJSON_AddStringToObject(root, "ssid", WIFI_SSID);
        cJSON_AddStringToObject(root, "pwd", WIFI_PASS);
        char *buf = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, strlen(buf));
        free(buf);
        buf = NULL;
    }

    return ESP_OK;
}

esp_err_t get_wifi_status_handler(httpd_req_t *req)
{
    char wifi_status_string[64];
    WiFi_Status_String(wifi_status_string);
    // Send the MAC address as the HTTP response
    httpd_resp_send(req, wifi_status_string, strlen(wifi_status_string));

    return ESP_OK;
}

esp_err_t get_admin_settings_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    char c[30];

    if (root)
    {
        cJSON_AddStringToObject(root, "mac", (ESP_MAC_ADDR));
        cJSON_AddStringToObject(root, "url", (API_URL));
        cJSON_AddStringToObject(root, "key", (API_KEY));
        cJSON_AddStringToObject(root, "id", (COMPANY_ID));
        sprintf(c, "%lu", API_CALL_INTERVAL);
        cJSON_AddStringToObject(root, "interval", (c));
        sprintf(c, "%u", API_CALL_STATUS);
        cJSON_AddStringToObject(root, "status", (c));
        cJSON_AddStringToObject(root, "ssid", WIFI_SSID);
        cJSON_AddStringToObject(root, "pwd", WIFI_PASS);

        char *buf = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, strlen(buf));
        free(buf);
        buf = NULL;
    }

    return ESP_OK;
}

esp_err_t get_api_settings_handler(httpd_req_t *req)
{

    if (!authorize(req, ANY_USER, true))
    {
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    char c[30];

    if (root)
    {
        cJSON_AddStringToObject(root, "url", (API_URL));
        sprintf(c, "%lu", API_CALL_INTERVAL);
        cJSON_AddStringToObject(root, "interval", (c));
        sprintf(c, "%u", API_CALL_STATUS);
        cJSON_AddStringToObject(root, "status", (c));
        char *buf = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, strlen(buf));
        free(buf);
        buf = NULL;
    }

    return ESP_OK;
}

esp_err_t get_door_status_handler(httpd_req_t *req)
{
    char door_status_string[64];
    Door_Status_String(door_status_string);
    // Send the MAC address as the HTTP response
    httpd_resp_send(req, door_status_string, strlen(door_status_string));

    return ESP_OK;
}

esp_err_t get_eth_status_handler(httpd_req_t *req)
{
    char eth_status_string[64];
    Eth_Status_String(eth_status_string);
    // Send the MAC address as the HTTP response
    httpd_resp_send(req, eth_status_string, strlen(eth_status_string));

    return ESP_OK;
}

esp_err_t get_device_status_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    char c[30];

    char eth_status_string[64];
    Eth_Status_String(eth_status_string);

    char door_status_string[64];
    Door_Status_String(door_status_string);

    char wifi_status_string[64];
    WiFi_Status_String(wifi_status_string);

    if (root)
    {
        cJSON_AddStringToObject(root, "mac", (ESP_MAC_ADDR));
        cJSON_AddStringToObject(root, "eth", (eth_status_string));
        cJSON_AddStringToObject(root, "wifi", (wifi_status_string));
        cJSON_AddStringToObject(root, "door", (door_status_string));
        char *buf = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, strlen(buf));
        free(buf);
        buf = NULL;
    }

    return ESP_OK;
}
esp_err_t start_rest_server(const char *base_path)
{
    REST_CHECK(base_path, "wrong base path", err);
    rest_server_context_t *rest_context = calloc(1, sizeof(rest_server_context_t));
    REST_CHECK(rest_context, "No memory for rest context", err);
    strlcpy(rest_context->base_path, base_path, sizeof(rest_context->base_path));

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 21;
    config.stack_size = (1024 * 10);
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(TAG, "Starting HTTP Server");
    REST_CHECK(httpd_start(&server, &config) == ESP_OK, "Start server failed", err_start);

    httpd_uri_t change_password_uri = {
        .uri = "/changePassword",
        .method = HTTP_POST,
        .handler = change_password_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &change_password_uri);

    httpd_uri_t save_wifi_uri = {
        .uri = "/saveWifiSettings",
        .method = HTTP_POST,
        .handler = save_wifi_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &save_wifi_uri);

    httpd_uri_t save_api_uri = {
        .uri = "/saveApiSettings",
        .method = HTTP_POST,
        .handler = api_settings_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &save_api_uri);

    httpd_uri_t factory_reset_uri = {
        .uri = "/factoryReset",
        .method = HTTP_GET,
        .handler = factory_reset_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &factory_reset_uri);

    httpd_uri_t date_time_uri = {
        .uri = "/saveDateTime",
        .method = HTTP_POST,
        .handler = change_date_time_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &date_time_uri);

    httpd_uri_t mac_address_uri = {
        .uri = "/getSerialNo",
        .method = HTTP_GET,
        .handler = mac_address_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &mac_address_uri);

    httpd_uri_t get_wifi_uri = {
        .uri = "/getWiFiSettings",
        .method = HTTP_GET,
        .handler = get_wifi_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_wifi_uri);

    httpd_uri_t get_wifi_status_uri = {
        .uri = "/getWiFiStatus",
        .method = HTTP_GET,
        .handler = get_wifi_status_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_wifi_status_uri);

    httpd_uri_t get_api_settings_uri = {
        .uri = "/getAPISettings",
        .method = HTTP_GET,
        .handler = get_api_settings_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_api_settings_uri);

    httpd_uri_t get_eth_status_uri = {
        .uri = "/getEthernetStatus",
        .method = HTTP_GET,
        .handler = get_eth_status_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_eth_status_uri);

    httpd_uri_t get_door_status_uri = {
        .uri = "/getDoorStatus",
        .method = HTTP_GET,
        .handler = get_door_status_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_door_status_uri);

    httpd_uri_t load_admin_settings_uri = {
        .uri = "/getAdminSettings",
        .method = HTTP_GET,
        .handler = get_admin_settings_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &load_admin_settings_uri);

    httpd_uri_t get_device_status_uri = {
        .uri = "/getDeviceStatus",
        .method = HTTP_GET,
        .handler = get_device_status_handler,
        .user_ctx = NULL};

    httpd_register_uri_handler(server, &get_device_status_uri);

    httpd_uri_t get_logs_uri = {
        .uri = "/getLogs",
        .method = HTTP_GET,
        .handler = log_handler,
        .user_ctx = rest_context};
    httpd_register_uri_handler(server, &get_logs_uri);

    httpd_uri_t get_pendinglogs_uri = {
        .uri = "/getPendingLogs",
        .method = HTTP_GET,
        .handler = pending_log_handler,
        .user_ctx = rest_context};
    httpd_register_uri_handler(server, &get_pendinglogs_uri);

    /* URI handler for admin page */
    httpd_uri_t admin_get_uri = {
        .uri = "/admin.html",
        .method = HTTP_GET,
        .handler = admin_get_handler,
        .user_ctx = rest_context};
    httpd_register_uri_handler(server, &admin_get_uri);

    httpd_uri_t user_get_uri = {
        .uri = "/index.html",
        .method = HTTP_GET,
        .handler = user_get_handler,
        .user_ctx = rest_context};
    httpd_register_uri_handler(server, &user_get_uri);

    httpd_uri_t wifi_scan_uri = {
        .uri = "/wifi_scan",
        .method = HTTP_GET,
        .handler = wifi_scan_handler,
        .user_ctx = rest_context};

    httpd_register_uri_handler(server, &wifi_scan_uri);
    // user_get_uri.uri = "/";
    // httpd_register_uri_handler(server, &user_get_uri);

    // /* URI handler for getting web server files */
    httpd_uri_t common_get_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = rest_common_get_handler,
        .user_ctx = rest_context};
    httpd_register_uri_handler(server, &common_get_uri);

    return ESP_OK;
err_start:
    free(rest_context);
err:
    return ESP_FAIL;
}