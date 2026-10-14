/* Linkio/Fermob LMP framing used by the ESPHome external component.
 *
 * Short frames (4 byte header + 16 byte body) carry every control message sent
 * to a single light. Long frames (2 byte header + chunk index/count + 16 byte
 * body, also 20 bytes on the wire) carry payloads longer than 15 bytes, such as
 * the 16 byte authkey and nonce.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- logging --
 * These sources are compiled both for the standalone ESP-IDF firmware and for
 * the ESPHome component. ESPHome owns the console and builds the ESP-IDF logger
 * down to ERROR, so an ESP_LOGI from a .c file that uses esp_log.h directly is
 * discarded before it is ever formatted: every pairing trace used to vanish.
 * Under ESPHome the messages therefore go through a wrapper into the ESPHome
 * logger; everywhere else they stay on the ESP-IDF macros.
 */
#if defined(__has_include) && __has_include("esphome/core/log.h")
#define LMP_LOG_VIA_ESPHOME 1
#endif

#ifdef LMP_LOG_VIA_ESPHOME
/* Levels match esphome::ESPHOME_LOG_LEVEL_*: 1 error, 2 warning, 3 info, 5 debug. */
void fermob_log(int level, const char *tag, int line, const char *format, ...);
#define LMP_LOGE(tag, ...) fermob_log(1, tag, __LINE__, __VA_ARGS__)
#define LMP_LOGW(tag, ...) fermob_log(2, tag, __LINE__, __VA_ARGS__)
#define LMP_LOGI(tag, ...) fermob_log(3, tag, __LINE__, __VA_ARGS__)
#define LMP_LOGD(tag, ...) fermob_log(5, tag, __LINE__, __VA_ARGS__)
#else
#define LMP_LOGE ESP_LOGE
#define LMP_LOGW ESP_LOGW
#define LMP_LOGI ESP_LOGI
#define LMP_LOGD ESP_LOGD
#endif

#define LMP_PAYLOAD_LEN 15
#define LMP_SHORT_BODY_LEN 16
#define LMP_SHORT_FRAME_LEN (4 + LMP_SHORT_BODY_LEN)
#define LMP_LONG_FRAME_LEN (2 + 2 + LMP_SHORT_BODY_LEN)
/* The app compares 5 + payload length against m_BLEService.MTU, hardcoded to 20. */
#define LMP_MTU 20

/* Longest payload this port will assemble. The app enforces no cap and completes
 * a long frame purely on "as many fragments as the last one declared", so this
 * is only a buffer bound; 16 fragments is 240 bytes and comfortably covers the
 * 7-fragment MODULE_INFO_GET answer a Moon light returns. */
#define LMP_LONG_PAYLOAD_MAX (16 * LMP_PAYLOAD_LEN)

#define LMP_DEFAULT_TRANSITION 50

#define LMP_API_V1 1
#define LMP_API_V2 2
#define LMP_API_V4 4

#define LMP_CONX_DIRECT 1
#define LMP_CONX_MESH 2

#define LMP_MSG_CMD_NO_ACK 0
#define LMP_MSG_CMD_ACK 1
#define LMP_MSG_ACK 2
/* The app's enum has no 5 or 6; the light's state notifications arrive as
 * STATUS or EVENT, never as an ACK. */
#define LMP_MSG_STATUS 3
#define LMP_MSG_EVENT 4

#define LMP_ADDR_LOCAL 0
#define LMP_ADDR_SHORT 1

#define LMP_ENC_NONE 0
#define LMP_ENC_PUBLIC_KEY 1
#define LMP_ENC_PRIVATE_KEY 2

#define LMP_FRAME_LOCAL_SHORT 0
#define LMP_FRAME_LMP_SHORT 2
#define LMP_FRAME_LOCAL_LONG_START 3
#define LMP_FRAME_LMP_LONG_START 5
#define LMP_FRAME_LONG_CONTINUED 6

#define LMP_CMD_DEVICE_DATA_SET 65
#define LMP_CMD_DEVICE_DATA_GET 66
#define LMP_CMD_NONCE_GENERATE 19
#define LMP_CMD_NONCE_SET 21
#define LMP_CMD_NONCE_GET 20
#define LMP_CMD_AUTHKEY_GENERATE 22
#define LMP_CMD_AUTHKEY_GET 23
#define LMP_CMD_AUTHKEY_SET 24
#define LMP_CMD_CRYPT_SET 25
#define LMP_CMD_REGISTER 16
#define LMP_CMD_UNREGISTER 17
#define LMP_CMD_MODULE_INFO_GET 48
#define LMP_CMD_DEVICE_INFO_GET 50

#define LMP_STATUS_ACK 128
#define LMP_STATUS_DEVICE_INFO 145
#define LMP_EVENT_DEVICE_DATA 146
#define LMP_STATUS_DEVICE_DATA 147
/* MODULE_INFO_GET parameters. */
#define LMP_PARAM_SHORT_ADDRESS 177
#define LMP_PARAM_MODULE_API_VERSION 184
#define LMP_ERR_SUCCESS 0
#define LMP_ERR_NOT_SUPPORTED 1
#define LMP_ERR_INVALID_COMMAND 2
#define LMP_ERR_INVALID_PARAMETER 3

#define LMP_LED_MODE_INIT 0
#define LMP_LED_MODE_COLOR 1
#define LMP_LED_MODE_TEMPO 2
#define LMP_LED_MODE_NOTIFICATION 6
#define LMP_LED_MODE_TIMER 9

typedef struct {
    uint8_t payload[LMP_LONG_PAYLOAD_MAX];
    uint8_t payload_len;
    uint8_t message_type;
    uint8_t address_type;
    uint8_t connection_type;
    uint8_t encryption;
    uint8_t seq_id;
    uint8_t mesh_addr[2];
    bool has_mesh_addr;
} lmp_msg_t;

/* Decoded view of one inbound frame.
 *
 * payload/payload_len is always the full 15 byte chunk that survived the CRC.
 * The app indexes into that chunk directly and only treats payload[0] as a
 * length, and it does so inconsistently: DEVICE_DATA_SET counts itself while
 * pairing commands count the bytes after it. declared_len therefore carries
 * payload[0] for handlers that care, and nothing in the decoder trusts it. */
typedef struct {
    uint8_t frame;
    uint8_t encryption;
    uint8_t message_type;
    uint8_t seq_id;
    uint8_t payload[LMP_PAYLOAD_LEN];
    uint8_t payload_len;
    uint8_t declared_len;
    bool crc_ok;
} lmp_rx_t;

/* Copies at most LMP_LONG_PAYLOAD_MAX bytes; longer payloads are clamped, so
 * callers that build more than 45 bytes must check their own length first. */
void lmp_msg_init(lmp_msg_t *msg, const uint8_t *payload, size_t payload_len);

void lmp_msg_set_encryption(lmp_msg_t *msg, uint8_t encryption);

/* Body encryption: AES-ECB of the nonce padded to 16 bytes used as a keystream,
 * XORed over crc||payload. key must be 16 bytes. */
void lmp_encrypt_body(uint8_t body[16], const uint8_t *key, const uint8_t *nonce);

/* Serialises a short frame. Returns the number of bytes written, 0 on bad args. */
size_t lmp_encode_short(const lmp_msg_t *msg, const uint8_t *key, const uint8_t *nonce,
                        uint8_t *out, size_t out_size);

/* Number of long-frame chunks needed for a payload of payload_len bytes
 * (1 when the payload fits a short frame). */
uint8_t lmp_chunks_needed(size_t payload_len);

/* Serialises one long-frame chunk. Returns the frame length, 0 on bad args.
 * Chunk 0 carries msg->seq_id, later chunks use FRAME_LONG_CONTINUED. */
size_t lmp_encode_long(const lmp_msg_t *msg, const uint8_t *key, const uint8_t *nonce,
                       uint8_t chunk_index, uint8_t *out, size_t out_size);

/* Decodes an inbound short frame. key/nonce may be NULL for cleartext frames. */
bool lmp_decode_short(const uint8_t *data, size_t len, const uint8_t *key,
                      const uint8_t *nonce, lmp_rx_t *out);

/* Decodes one inbound long-frame chunk. out->frame carries the frame type and
 * chunk/chunks receive the index and count so the caller can reassemble. */
bool lmp_decode_long(const uint8_t *data, size_t len, const uint8_t *key, const uint8_t *nonce,
                     lmp_rx_t *out, uint8_t *chunk, uint8_t *chunks);

size_t lmp_device_data_payload(bool is_on, uint8_t level, uint8_t dev_index,
                                uint8_t led_mode, uint8_t api_version,
                                uint16_t transition, uint8_t *out);

/* Tunable-white light (device type 404): separate cold/warm brightness bytes. */
size_t lmp_tunable_white_payload(bool is_on, uint8_t cold_white, uint8_t warm_white,
                                 uint8_t dev_index, uint8_t led_mode, uint8_t api_version,
                                 uint16_t transition, uint8_t *out);

/* State query, as the app builds it: a declared length of 14 followed by the
 * command, the device index and 0xff filler, so the light answers with a
 * DEVICE_DATA status record. */
size_t lmp_device_data_get_payload(uint8_t dev_index, uint8_t *out);

size_t lmp_simple_payload(uint8_t command, uint8_t arg, uint8_t *out);

/* [1, command]: the declared length byte counts the bytes after itself, which
 * is how the app builds pairing and mesh payloads such as [1, UNREGISTER]. */
size_t lmp_cmd_payload(uint8_t command, uint8_t *out);

/* Reads the frame type and encryption mode out of a header without decrypting,
 * so the caller can pick a key first. Both frame layouts put them in byte 0. */
bool lmp_frame_header(const uint8_t *data, size_t len, uint8_t *frame, uint8_t *encryption,
                      uint8_t *message_type, uint8_t *seq_id);

void lmp_dump(const char *label, const uint8_t *data, size_t len);

/* Decoded DEVICE_DATA record from a status/event notification.
 *
 * The app walks the notification payload as a chain of records: a length byte
 * that counts the bytes after itself, an opcode, the device index, then the
 * record body. processDeviceEvent reads the body at fixed offsets 3..9 and
 * never consults the length, so these are absolute payload offsets that only
 * line up for a record starting at offset 0. */
typedef struct {
    uint8_t dev_index;
    uint8_t is_on;    /* bits 0..3 of the flags byte */
    uint8_t led_mode; /* bits 4..7 of the flags byte */
    uint8_t level;
    uint32_t timestamp; /* big endian, applied only when not older than the last one */
} lmp_state_t;

/* Parses the first DEVICE_DATA record out of an LMP notification payload.
 * Returns false for any other opcode, a device that is not dev_index, or a
 * record the app would have skipped (its gate byte at offset 7 must be zero). */
bool lmp_parse_device_state(const uint8_t *payload, size_t payload_len, uint8_t dev_index,
                            lmp_state_t *out);

#ifdef __cplusplus
}
#endif
