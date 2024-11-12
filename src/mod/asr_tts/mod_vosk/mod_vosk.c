/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2013, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Modifications by: Nigel Daniels, 2024
 *
 * mod_vosk - Speech recognition using Vosk server with config message support
 */

#define __PRETTY_FUNCTION__ __func__
#include <switch.h>
#include <netinet/tcp.h>
#include <libks/ks.h>

#define AUDIO_BLOCK_SIZE 3200

SWITCH_MODULE_LOAD_FUNCTION(mod_vosk_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_vosk_shutdown);
SWITCH_MODULE_DEFINITION(mod_vosk, mod_vosk_load, mod_vosk_shutdown, NULL);

static switch_mutex_t *MUTEX = NULL;
static switch_event_node_t *NODE = NULL;

static struct {
    char *server_url;
    int return_json;

    int auto_reload;
    switch_memory_pool_t *pool;
    ks_pool_t *ks_pool;
} globals;

typedef struct {
    kws_t *ws;
    char *result;
    switch_mutex_t *mutex;
    switch_buffer_t *audio_buffer;
} vosk_t;

/*! Send a configuration message */
static switch_status_t vosk_send_config(vosk_t *vosk, switch_asr_handle_t *ah, int rate) {
    ks_json_t *config_message = ks_json_create_object();

    ks_json_add_string_to_object(config_message, "type", "config");
    ks_json_add_string_to_object(config_message, "call_uuid", switch_core_session_get_uuid(ah->session));
    ks_json_add_array_to_object(config_message, "phrase_list", ks_json_create_array()); // Empty array; we don't use a phrase list
    ks_json_add_number_to_object(config_message, "sample_rate", rate);
    ks_json_add_boolean_to_object(config_message, "words", true);
    ks_json_add_number_to_object(config_message, "max_alternatives", 1);

    char *config_str = ks_json_print_unformatted(config_message);
    if (kws_write_frame(vosk->ws, WSOC_TEXT, config_str, strlen(config_str)) < 0) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to send config message: %s\n", config_str);
        free(config_str);
        ks_json_delete(&config_message);
        return SWITCH_STATUS_GENERR;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Sent config message: %s\n", config_str);
    free(config_str);
    ks_json_delete(&config_message);

    return SWITCH_STATUS_SUCCESS;
}

/*! function to open the asr interface */
static switch_status_t vosk_asr_open(switch_asr_handle_t *ah, const char *codec, int rate, const char *dest, switch_asr_flag_t *flags) {
    vosk_t *vosk;
    ks_json_t *req = ks_json_create_object();
    ks_json_add_string_to_object(req, "url", (dest ? dest : globals.server_url));

    if (!(vosk = (vosk_t *) switch_core_alloc(ah->memory_pool, sizeof(*vosk)))) {
        return SWITCH_STATUS_MEMERR;
    }
    ah->private_info = vosk;
    switch_mutex_init(&vosk->mutex, SWITCH_MUTEX_NESTED, ah->memory_pool);

    if (switch_buffer_create_dynamic(&vosk->audio_buffer, AUDIO_BLOCK_SIZE, AUDIO_BLOCK_SIZE, 0) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Buffer create failed\n");
        return SWITCH_STATUS_MEMERR;
    }

    codec = "L16";
    ah->codec = switch_core_strdup(ah->memory_pool, codec);

    if (kws_connect_ex(&vosk->ws, req, KWS_BLOCK | KWS_CLOSE_SOCK, globals.ks_pool, NULL, 30000) != KS_STATUS_SUCCESS) {
        ks_json_delete(&req);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Websocket connect to %s failed\n", globals.server_url);
        return SWITCH_STATUS_GENERR;
    }

    ks_json_delete(&req);

    /* Send the config message */
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Preparing to send config message...\n");
    if (vosk_send_config(vosk, ah, rate) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "NIGEL Failed to send config message\n");
        return SWITCH_STATUS_GENERR;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "NIGEL Config message sent successfully\n");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR open\n");
    return SWITCH_STATUS_SUCCESS;
}

/*! function to close the asr interface */
static switch_status_t vosk_asr_close(switch_asr_handle_t *ah, switch_asr_flag_t *flags) {
    vosk_t *vosk = (vosk_t *) ah->private_info;

    switch_mutex_lock(vosk->mutex);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "ASR closed\n");

    kws_close(vosk->ws, KWS_CLOSE_SOCK);
    kws_destroy(&vosk->ws);

    switch_set_flag(ah, SWITCH_ASR_FLAG_CLOSED);
    switch_buffer_destroy(&vosk->audio_buffer);
    switch_safe_free(vosk->result);
    switch_mutex_unlock(vosk->mutex);

    return SWITCH_STATUS_SUCCESS;
}

/*! function to feed audio to the ASR */
static switch_status_t vosk_asr_feed(switch_asr_handle_t *ah, void *data, unsigned int len, switch_asr_flag_t *flags) {
    vosk_t *vosk = (vosk_t *) ah->private_info;

    if (switch_test_flag(ah, SWITCH_ASR_FLAG_CLOSED))
        return SWITCH_STATUS_BREAK;

    switch_mutex_lock(vosk->mutex);

    switch_buffer_write(vosk->audio_buffer, data, len);
    if (switch_buffer_inuse(vosk->audio_buffer) > AUDIO_BLOCK_SIZE) {
        char buf[AUDIO_BLOCK_SIZE];
        int rlen = switch_buffer_read(vosk->audio_buffer, buf, AUDIO_BLOCK_SIZE);

        ks_json_t *audio_message = ks_json_create_object();
        ks_json_add_string_to_object(audio_message, "type", "audio");
        ks_json_add_string_to_object(audio_message, "call_uuid", switch_core_session_get_uuid(ah->session));
        ks_json_add_base64_to_object(audio_message, "data", buf, rlen);

        char *audio_str = ks_json_print_unformatted(audio_message);
        if (kws_write_frame(vosk->ws, WSOC_TEXT, audio_str, strlen(audio_str)) < 0) {
            free(audio_str);
            ks_json_delete(&audio_message);
            switch_mutex_unlock(vosk->mutex);
            return SWITCH_STATUS_BREAK;
        }

        free(audio_str);
        ks_json_delete(&audio_message);
    }

    switch_mutex_unlock(vosk->mutex);
    return SWITCH_STATUS_SUCCESS;
}

/* ... The rest of the code remains unchanged ... */
