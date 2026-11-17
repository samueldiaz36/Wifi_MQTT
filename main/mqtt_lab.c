/**
 * @file mqtt_lab.c
 * @brief Lab Session 2: Student Coding Exercises for MQTT & MQTTS (TLS)
 *
 * ============================================================================
 * STUDENT CODING TASKS IN THIS FILE:
 * ============================================================================
 * Search for `TODO (Task 1)` through `TODO (Task 5)` in this file:
 *
 *   - TASK 1 (`mqtt_event_handler`):
 *       Subscribe to `s_topic_cmd` (QoS 1), publish `"online"` (retained) to
 *       `s_topic_status` when `MQTT_EVENT_CONNECTED` fires, and safely copy
 *       incoming `MQTT_EVENT_DATA` buffers (which are NOT null-terminated!)
 *       before calling `mqtt_process_incoming_command()`.
 *
 *   - TASK 2 (`mqtt_app_start_plaintext`):
 *       Configure `esp_mqtt_client_config_t` for plaintext MQTT (`mqtt://`, Port 1883)
 *       including Last Will & Testament (LWT), initialize, register events, and start.
 *
 *   - TASK 3 (`mqtt_publish_telemetry`):
 *       Build a JSON telemetry payload with `cJSON`, serialize it, publish it to
 *       `s_topic_telemetry` with QoS 1, and free all allocated heap memory.
 *
 *   - TASK 4 (`mqtt_process_incoming_command`):
 *       Parse incoming JSON commands on `s_topic_cmd` (e.g., `{"action":"set_interval","value":3}`
 *       or `{"action":"ping"}`) and publish a JSON ACK response to `s_topic_status`.
 *
 *   - TASK 5 (`mqtt_app_start_tls`):
 *       Upgrade the connection to `mqtts://` (Port 8883) and attach your team's
 *       self-signed Root CA certificate (`LAB_CA_CERT_PEM` from `lab_certificates.h`)
 *       so mbedTLS verifies the broker's identity and encrypts all traffic!
 */

#include "mqtt_lab.h"
#include "lab_credentials.h"
#include "lab_certificates.h"
#include "wifi_sta.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "cJSON.h"

static const char *TAG = "MQTT_LAB";

/* Global MQTT Client Handle & State */
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool     s_is_connected = false;
static uint32_t s_telemetry_interval_sec = 10; /* Default: 10 seconds */

/* Formatted Topic Buffers for this ESP32's Hardware MAC */
static char s_mac_clean[13]       = {0}; /* e.g., "2805A5749288" */
static char s_topic_telemetry[64] = {0}; /* e.g., "lab/devices/2805A5749288/telemetry" */
static char s_topic_cmd[64]       = {0}; /* e.g., "lab/devices/2805A5749288/cmd" */
static char s_topic_status[64]    = {0}; /* e.g., "lab/devices/2805A5749288/status" */

/* Forward declaration of command parser (Task 4) */
static void mqtt_process_incoming_command(const char *topic, const char *payload);

/* ============================================================================
 * HELPER: Initialize Device-Specific Topics from Hardware MAC
 * ============================================================================ */
void mqtt_lab_init_topics(void)
{
    char mac_colon[18] = {0};
    wifi_get_mac_str(mac_colon, sizeof(mac_colon));

    /* Strip colons from "28:05:A5:74:92:88" -> "2805A5749288" */
    int j = 0;
    for (int i = 0; mac_colon[i] != '\0' && j < (int)sizeof(s_mac_clean) - 1; i++) {
        if (mac_colon[i] != ':') {
            s_mac_clean[j++] = mac_colon[i];
        }
    }
    s_mac_clean[j] = '\0';

    snprintf(s_topic_telemetry, sizeof(s_topic_telemetry), "%s/%s/telemetry", LAB_TOPIC_PREFIX, s_mac_clean);
    snprintf(s_topic_cmd,       sizeof(s_topic_cmd),       "%s/%s/cmd",       LAB_TOPIC_PREFIX, s_mac_clean);
    snprintf(s_topic_status,    sizeof(s_topic_status),    "%s/%s/status",    LAB_TOPIC_PREFIX, s_mac_clean);

    ESP_LOGI(TAG, "Initialized Device MQTT Topics:");
    ESP_LOGI(TAG, "  [PUB] Telemetry : %s", s_topic_telemetry);
    ESP_LOGI(TAG, "  [SUB] Commands  : %s", s_topic_cmd);
    ESP_LOGI(TAG, "  [LWT] Status    : %s", s_topic_status);
}

/* ============================================================================
 * CODING TASK 4: Parse Incoming JSON Commands & Publish ACK
 * ============================================================================ */
/**
 * @brief Parse a JSON command received on `s_topic_cmd` and act on it.
 *
 * Expected JSON format sent by student from PC (`mosquitto_pub`):
 *   {"action": "set_interval", "value": 3}
 *   {"action": "ping"}
 *   {"action": "reboot"}
 */
static void mqtt_process_incoming_command(const char *topic, const char *payload)
{
    ESP_LOGI(TAG, "Processing command on [%s]: %s", topic, payload);

    /* --- STUDENT CODE START (Task 4) --- */
    cJSON *root = cJSON_Parse(payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "JSON invalido: %s", payload);
        return;
    }

    cJSON *action = cJSON_GetObjectItemCaseSensitive(root, "action");
    if (!cJSON_IsString(action) || action->valuestring == NULL) {
        ESP_LOGW(TAG, "El comando no trae el campo 'action'");
        cJSON_Delete(root);
        return;
    }

    if (strcmp(action->valuestring, "set_interval") == 0) {
        cJSON *val = cJSON_GetObjectItemCaseSensitive(root, "value");
        if (cJSON_IsNumber(val) && val->valueint >= 1 && val->valueint <= 60) {
            s_telemetry_interval_sec = (uint32_t)val->valueint;
            char ack[64];
            snprintf(ack, sizeof(ack), "{\"status\":\"interval_updated\",\"value\":%d}", val->valueint);
            esp_mqtt_client_publish(s_mqtt_client, s_topic_status, ack, 0, 1, 0);
            ESP_LOGI(TAG, "Intervalo actualizado a %d s", val->valueint);
        } else {
            esp_mqtt_client_publish(s_mqtt_client, s_topic_status, "{\"status\":\"error_invalid_value\"}", 0, 1, 0);
            ESP_LOGW(TAG, "Valor de intervalo fuera de rango (1-60)");
        }
    } else if (strcmp(action->valuestring, "ping") == 0) {
        esp_mqtt_client_publish(s_mqtt_client, s_topic_status, "{\"status\":\"pong\"}", 0, 1, 0);
    } else if (strcmp(action->valuestring, "reboot") == 0) {
        esp_mqtt_client_publish(s_mqtt_client, s_topic_status, "{\"status\":\"rebooting\"}", 0, 1, 0);
        cJSON_Delete(root);
        vTaskDelay(pdMS_TO_TICKS(500)); /* deja salir el mensaje antes de reiniciar */
        esp_restart();
        return;
    } else {
        ESP_LOGW(TAG, "Accion desconocida: %s", action->valuestring);
    }

    cJSON_Delete(root);
    /* --- STUDENT CODE END (Task 4) --- */
}

/* ============================================================================
 * CODING TASK 1: MQTT Event Handler (`MQTT_EVENT_CONNECTED` & `MQTT_EVENT_DATA`)
 * ============================================================================ */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    esp_mqtt_client_handle_t client = event->client;

    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED: Connected to Broker!");
            s_is_connected = true;

            /* --- STUDENT CODE START (Task 1A) --- */
            int msg_id = esp_mqtt_client_subscribe(client, s_topic_cmd, 1);
            ESP_LOGI(TAG, "Suscrito a %s, msg_id=%d", s_topic_cmd, msg_id);

            esp_mqtt_client_publish(client, s_topic_status, "{\"status\":\"online\"}", 0, 1, 1);
            /* --- STUDENT CODE END (Task 1A) --- */
            break;

        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "MQTT_EVENT_DISCONNECTED: Broker connection lost.");
            s_is_connected = false;
            break;

        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;

        case MQTT_EVENT_PUBLISHED:
            ESP_LOGD(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;

        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA received!");

            /* --- STUDENT CODE START (Task 1B) --- */
            char topic_buf[128] = {0};
            char data_buf[512]  = {0};

            snprintf(topic_buf, sizeof(topic_buf), "%.*s", event->topic_len, event->topic);
            snprintf(data_buf,  sizeof(data_buf),  "%.*s", event->data_len,  event->data);

            mqtt_process_incoming_command(topic_buf, data_buf);
            /* --- STUDENT CODE END (Task 1B) --- */
            break;

        case MQTT_EVENT_ERROR:
            ESP_LOGE(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
                ESP_LOGE(TAG, "  Last esp-tls error code   : 0x%x", event->error_handle->esp_tls_last_esp_err);
                ESP_LOGE(TAG, "  Last tls stack error      : 0x%x", event->error_handle->esp_tls_stack_err);
                ESP_LOGE(TAG, "  Last cert verify flags    : 0x%x", event->error_handle->esp_tls_cert_verify_flags);
            }
            break;

        default:
            break;
    }
}

/* ============================================================================
 * CODING TASK 2: Start Plaintext MQTT Client (`mqtt://`, Port 1883 + LWT)
 * ============================================================================ */
esp_err_t mqtt_app_start_plaintext(void)
{
    mqtt_lab_init_topics();

    ESP_LOGI(TAG, "Starting Plaintext MQTT Client -> %s", LAB_MQTT_BROKER_PLAIN_URI);

    /* --- STUDENT CODE START (Task 2) --- */
    esp_mqtt_client_config_t mqtt_cfg = {0};
    mqtt_cfg.broker.address.uri = LAB_MQTT_BROKER_PLAIN_URI;

    mqtt_cfg.session.last_will.topic   = s_topic_status;
    mqtt_cfg.session.last_will.msg     = "{\"status\":\"offline_unexpected\"}";
    mqtt_cfg.session.last_will.msg_len = 0;
    mqtt_cfg.session.last_will.qos     = 1;
    mqtt_cfg.session.last_will.retain  = 1;

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_mqtt_client == NULL) {
        ESP_LOGE(TAG, "No se pudo inicializar el cliente MQTT");
        return ESP_FAIL;
    }
    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    return esp_mqtt_client_start(s_mqtt_client);
    /* --- STUDENT CODE END (Task 2) --- */
}

/* ============================================================================
 * CODING TASK 3: Build & Publish JSON Telemetry Payload
 * ============================================================================ */
esp_err_t mqtt_publish_telemetry(int rssi_dbm, uint32_t uptime_sec, uint32_t free_heap)
{
    if (!s_is_connected || s_mqtt_client == NULL) {
        ESP_LOGW(TAG, "Cannot publish telemetry: MQTT client not connected yet.");
        return ESP_FAIL;
    }

    /* --- STUDENT CODE START (Task 3) --- */
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ESP_FAIL;
    }
    cJSON_AddStringToObject(root, "student_id", LAB_STUDENT_ID);
    cJSON_AddStringToObject(root, "mac", s_mac_clean);
    cJSON_AddNumberToObject(root, "rssi_dbm", rssi_dbm);
    cJSON_AddNumberToObject(root, "uptime_sec", uptime_sec);
    cJSON_AddNumberToObject(root, "free_heap", free_heap);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json_str == NULL) {
        return ESP_FAIL;
    }

    int msg_id = esp_mqtt_client_publish(s_mqtt_client, s_topic_telemetry, json_str, 0, 1, 0);
    free(json_str);

    return (msg_id >= 0) ? ESP_OK : ESP_FAIL;
    /* --- STUDENT CODE END (Task 3) --- */
}

/* ============================================================================
 * CODING TASK 5: Upgrade to MQTTS (`mqtts://`, Port 8883 + Self-Signed Root CA)
 * ============================================================================ */
esp_err_t mqtt_app_start_tls(void)
{
    mqtt_lab_init_topics();

    ESP_LOGI(TAG, "Starting Secure MQTTS (TLS) Client -> %s", LAB_MQTT_BROKER_TLS_URI);

    /* --- STUDENT CODE START (Task 5) --- */
    esp_mqtt_client_config_t mqtt_cfg = {0};
    mqtt_cfg.broker.address.uri = LAB_MQTT_BROKER_TLS_URI;

    /* Verificar al broker con nuestra CA publica (ca.crt) */
    mqtt_cfg.broker.verification.certificate = LAB_CA_CERT_PEM;

    /* Mismo Last Will que en la Tarea 2 */
    mqtt_cfg.session.last_will.topic   = s_topic_status;
    mqtt_cfg.session.last_will.msg     = "{\"status\":\"offline_unexpected\"}";
    mqtt_cfg.session.last_will.msg_len = 0;
    mqtt_cfg.session.last_will.qos     = 1;
    mqtt_cfg.session.last_will.retain  = 1;

    /* Bonus mTLS: el ESP32 presenta su certificado de cliente */
    mqtt_cfg.credentials.authentication.certificate = LAB_CLIENT_CERT_PEM;
    mqtt_cfg.credentials.authentication.key         = LAB_CLIENT_KEY_PEM;

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_mqtt_client == NULL) {
        ESP_LOGE(TAG, "No se pudo inicializar el cliente MQTTS");
        return ESP_FAIL;
    }
    esp_mqtt_client_register_event(s_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    return esp_mqtt_client_start(s_mqtt_client);
    /* --- STUDENT CODE END (Task 5) --- */
}

bool mqtt_lab_is_connected(void)
{
    return s_is_connected;
}

uint32_t mqtt_lab_get_interval_sec(void)
{
    return s_telemetry_interval_sec;
}