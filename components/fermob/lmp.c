#include "lmp.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/aes.h"

static const char *TAG = "lmp";

void lmp_msg_init(lmp_msg_t *msg, const uint8_t *payload, size_t payload_len) {
    memset(msg, 0, sizeof(*msg));
    if (payload_len > LMP_LONG_PAYLOAD_MAX) {
        payload_len = LMP_LONG_PAYLOAD_MAX;
    }
    if (payload != NULL && payload_len > 0) {
        memcpy(msg->payload, payload, payload_len);
    }
    msg->payload_len = (uint8_t)payload_len;
    msg->message_type = LMP_MSG_CMD_NO_ACK;
    msg->address_type = LMP_ADDR_LOCAL;
    msg->connection_type = LMP_CONX_DIRECT;
    msg->encryption = LMP_ENC_NONE;
}

void lmp_msg_set_encryption(lmp_msg_t *msg, uint8_t encryption) {
    msg->encryption = encryption;
}

void lmp_encrypt_body(uint8_t body[16], const uint8_t *key, const uint8_t *nonce) {
    mbedtls_aes_context aes;
    uint8_t keystream[16];
    uint8_t block[16];

    memcpy(block, nonce, 16);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
        LMP_LOGE(TAG, "aes setkey failed");
        return;
    }
    if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, block, keystream) != 0) {
        LMP_LOGE(TAG, "aes ecb failed");
        return;
    }
    mbedtls_aes_free(&aes);

    for (int i = 0; i < 16; i++) {
        body[i] ^= keystream[i];
    }
}

/* Checksum of the app's m_BLEParsingService.computeCRC(). */
static uint8_t xor_crc(const uint8_t *data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
    }
    return crc;
}

/* Chunk padding, verbatim from the app's buildPayload(): a single 0x00 while the
 * chunk is short, then 0xff until it is LMP_PAYLOAD_LEN bytes. */
static void build_body(const lmp_msg_t *msg, const uint8_t *payload, size_t payload_len,
                       const uint8_t *key, const uint8_t *nonce,
                       uint8_t body[LMP_SHORT_BODY_LEN]) {
    uint8_t chunk[LMP_PAYLOAD_LEN];
    size_t len = payload_len > LMP_PAYLOAD_LEN ? LMP_PAYLOAD_LEN : payload_len;

    memcpy(chunk, payload, len);
    if (len < LMP_PAYLOAD_LEN) {
        chunk[len++] = 0x00;
        while (len < LMP_PAYLOAD_LEN) {
            chunk[len++] = 0xff;
        }
    }

    body[0] = xor_crc(chunk, LMP_PAYLOAD_LEN);
    memcpy(body + 1, chunk, LMP_PAYLOAD_LEN);

    if (msg->encryption != LMP_ENC_NONE && key != NULL && nonce != NULL) {
        lmp_encrypt_body(body, key, nonce);
    }
}

static uint8_t frame_byte(const lmp_msg_t *msg, uint8_t frame_type) {
    uint8_t frame = (uint8_t)((msg->message_type << 5) & 0xE0);
    frame |= (uint8_t)((msg->encryption << 3) & 0x18);
    frame |= (uint8_t)(frame_type & 0x07);
    return frame;
}

size_t lmp_encode_short(const lmp_msg_t *msg, const uint8_t *key, const uint8_t *nonce,
                        uint8_t *out, size_t out_size) {
    uint8_t frame_type;

    if (msg == NULL || out == NULL || out_size < LMP_SHORT_FRAME_LEN) {
        return 0;
    }

    frame_type = (msg->address_type == LMP_ADDR_SHORT) ? LMP_FRAME_LMP_SHORT
                                                       : LMP_FRAME_LOCAL_SHORT;

    out[0] = frame_byte(msg, frame_type);
    out[1] = msg->seq_id;
    out[2] = 0;
    out[3] = 0;

    if (msg->address_type == LMP_ADDR_SHORT && msg->connection_type == LMP_CONX_MESH &&
        msg->has_mesh_addr) {
        out[3] = msg->mesh_addr[0];
        out[2] = msg->mesh_addr[1];
    }

    build_body(msg, msg->payload, msg->payload_len, key, nonce, out + 4);
    return LMP_SHORT_FRAME_LEN;
}

uint8_t lmp_chunks_needed(size_t payload_len) {
    /* Matches the app: 5 bytes of long-frame overhead (header 2 + chunk 2) plus the
     * payload, compared against the BLE service MTU of 20. */
    size_t total = 5 + payload_len;
    if (total <= LMP_MTU) {
        return 1;
    }
    return (uint8_t)(total % 20 == 0 ? total / 20 : total / 20 + 1);
}

size_t lmp_encode_long(const lmp_msg_t *msg, const uint8_t *key, const uint8_t *nonce,
                       uint8_t chunk_index, uint8_t *out, size_t out_size) {
    uint8_t chunks;
    uint8_t frame_type;

    if (msg == NULL || out == NULL || out_size < LMP_LONG_FRAME_LEN) {
        return 0;
    }

    chunks = lmp_chunks_needed(msg->payload_len);
    if (chunks < 2 || chunk_index >= chunks) {
        return 0;
    }
    /* The app chunks frame bytes, not payload bytes, so its count can promise
     * fewer 15 byte chunks than the payload actually needs. Refuse instead of
     * silently dropping the tail. */
    if ((size_t)chunks * LMP_PAYLOAD_LEN < msg->payload_len) {
        return 0;
    }

    frame_type = (chunk_index == 0)
                     ? ((msg->address_type == LMP_ADDR_SHORT) ? LMP_FRAME_LMP_LONG_START
                                                              : LMP_FRAME_LOCAL_LONG_START)
                     : LMP_FRAME_LONG_CONTINUED;

    out[0] = frame_byte(msg, frame_type);
    out[1] = msg->seq_id;
    out[2] = chunk_index;
    out[3] = chunks;

    build_body(msg, msg->payload + (size_t)chunk_index * LMP_PAYLOAD_LEN,
               msg->payload_len - (size_t)chunk_index * LMP_PAYLOAD_LEN, key, nonce, out + 4);
    return LMP_LONG_FRAME_LEN;
}

bool lmp_decode_short(const uint8_t *data, size_t len, const uint8_t *key,
                      const uint8_t *nonce, lmp_rx_t *out) {
    uint8_t body[LMP_SHORT_BODY_LEN];

    if (data == NULL || out == NULL || len < LMP_SHORT_FRAME_LEN) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->frame = data[0] & 0x07;
    out->encryption = (data[0] >> 3) & 0x03;
    out->message_type = (data[0] >> 5) & 0x07;
    out->seq_id = data[1];

    if (out->frame != LMP_FRAME_LOCAL_SHORT && out->frame != LMP_FRAME_LMP_SHORT) {
        return false;
    }

    memcpy(body, data + 4, LMP_SHORT_BODY_LEN);

    if (out->encryption != LMP_ENC_NONE && key != NULL && nonce != NULL) {
        lmp_encrypt_body(body, key, nonce);
    }

    out->crc_ok = (xor_crc(body + 1, LMP_PAYLOAD_LEN) == body[0]);
    memcpy(out->payload, body + 1, LMP_PAYLOAD_LEN);
    out->payload_len = LMP_PAYLOAD_LEN;
    out->declared_len = out->payload[0];
    return true;
}

bool lmp_decode_long(const uint8_t *data, size_t len, const uint8_t *key, const uint8_t *nonce,
                     lmp_rx_t *out, uint8_t *chunk, uint8_t *chunks) {
    uint8_t body[LMP_SHORT_BODY_LEN];

    if (data == NULL || out == NULL || len < LMP_LONG_FRAME_LEN) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->frame = data[0] & 0x07;
    out->encryption = (data[0] >> 3) & 0x03;
    out->message_type = (data[0] >> 5) & 0x07;
    out->seq_id = data[1];

    if (out->frame != LMP_FRAME_LOCAL_LONG_START && out->frame != LMP_FRAME_LMP_LONG_START &&
        out->frame != LMP_FRAME_LONG_CONTINUED) {
        return false;
    }

    if (chunk != NULL) {
        *chunk = data[2];
    }
    if (chunks != NULL) {
        *chunks = data[3];
    }

    memcpy(body, data + 4, LMP_SHORT_BODY_LEN);

    if (out->encryption != LMP_ENC_NONE && key != NULL && nonce != NULL) {
        lmp_encrypt_body(body, key, nonce);
    }

    out->crc_ok = (xor_crc(body + 1, LMP_PAYLOAD_LEN) == body[0]);
    memcpy(out->payload, body + 1, LMP_PAYLOAD_LEN);
    out->payload_len = LMP_PAYLOAD_LEN;
    out->declared_len = out->payload[0];
    return true;
}

size_t lmp_device_data_payload(bool is_on, uint8_t level, uint8_t dev_index, uint8_t led_mode,
                               uint8_t api_version, uint16_t transition, uint8_t *out) {
    size_t len = 0;
    uint8_t flags = is_on ? 1 : 0;

    out[len++] = 0;
    out[len++] = LMP_CMD_DEVICE_DATA_SET;
    out[len++] = dev_index;

    if (api_version > LMP_API_V1) {
        flags |= (uint8_t)((led_mode & 0x0F) << 4);
    }
    out[len++] = flags;
    out[len++] = level;
    out[len++] = (uint8_t)(transition & 0xFF);
    out[len++] = (uint8_t)((transition >> 8) & 0xFF);

    if (api_version < LMP_API_V2) {
        out[len++] = (uint8_t)(led_mode & 0xFF);
    }

    /* Byte 0 is the index of the last byte written, not the byte count: the
     * builder in the app ends with n[0] = t where t is the running index. The
     * light uses the same convention in everything it sends (a 19 byte key ACK
     * declares 18, MODULE_INFO_GET declares 2), and it drops a DEVICE_DATA_SET
     * whose declared length is one too high. */
    out[0] = (uint8_t)(len - 1);
    return len;
}

size_t lmp_tunable_white_payload(bool is_on, uint8_t cold_white, uint8_t warm_white,
                                 uint8_t dev_index, uint8_t led_mode, uint8_t api_version,
                                 uint16_t transition, uint8_t *out) {
    size_t len = 0;
    uint8_t flags = is_on ? 1 : 0;

    out[len++] = 0;
    out[len++] = LMP_CMD_DEVICE_DATA_SET;
    out[len++] = dev_index;
    if (led_mode == LMP_LED_MODE_TEMPO || led_mode == LMP_LED_MODE_NOTIFICATION) {
        flags = 1;
    }
    if (api_version > LMP_API_V1) {
        flags |= (uint8_t)((led_mode & 0x0f) << 4);
    }
    out[len++] = flags;
    out[len++] = cold_white;
    out[len++] = warm_white;
    out[len++] = (uint8_t)transition;
    out[len++] = (uint8_t)(transition >> 8);
    if (api_version < LMP_API_V2) {
        out[len++] = led_mode;
    }
    out[0] = (uint8_t)(len - 1);
    return len;
}

size_t lmp_device_data_get_payload(uint8_t dev_index, uint8_t *out) {
    size_t len = 0;

    out[len++] = 14;
    out[len++] = LMP_CMD_DEVICE_DATA_GET;
    out[len++] = dev_index;
    while (len < 15) {
        out[len++] = 0xff;
    }
    return len;
}

size_t lmp_simple_payload(uint8_t command, uint8_t arg, uint8_t *out) {
    out[0] = 2;
    out[1] = command;
    out[2] = arg;
    return 3;
}

size_t lmp_cmd_payload(uint8_t command, uint8_t *out) {
    out[0] = 1;
    out[1] = command;
    return 2;
}

bool lmp_frame_header(const uint8_t *data, size_t len, uint8_t *frame, uint8_t *encryption,
                      uint8_t *message_type, uint8_t *seq_id) {
    if (data == NULL || len < LMP_LONG_FRAME_LEN) {
        return false;
    }
    if (frame != NULL) {
        *frame = data[0] & 0x07;
    }
    if (encryption != NULL) {
        *encryption = (data[0] >> 3) & 0x03;
    }
    if (message_type != NULL) {
        *message_type = (data[0] >> 5) & 0x07;
    }
    if (seq_id != NULL) {
        *seq_id = data[1];
    }
    return true;
}

bool lmp_parse_device_state(const uint8_t *payload, size_t payload_len, uint8_t dev_index,
                            lmp_state_t *out) {
    uint8_t flags;

    if (payload == NULL || out == NULL || payload_len < 10) {
        return false;
    }
    /* A state query is answered with a plain CMD_ACK whose first TLV is
     * LMP_STATUS_ACK; the app hands that payload to the same decoder as a
     * pushed DEVICE_DATA record and never looks at the opcode, so neither does
     * this. */
    if (payload[0] == 0) {
        return false; /* a zero length byte terminates the record chain */
    }
    if (payload[1] != LMP_STATUS_DEVICE_DATA && payload[1] != LMP_EVENT_DEVICE_DATA &&
        payload[1] != LMP_STATUS_ACK) {
        return false;
    }
    if (payload[2] != dev_index) {
        return false;
    }
    if (payload[7] != 0) {
        return false; /* the app's gate byte: anything else and it drops the record */
    }

    flags = payload[8];
    out->dev_index = payload[2];
    out->timestamp = ((uint32_t)payload[3] << 24) | ((uint32_t)payload[4] << 16) |
                     ((uint32_t)payload[5] << 8) | (uint32_t)payload[6];
    out->is_on = (uint8_t)(flags & 0x0F);
    out->led_mode = (uint8_t)((flags & 0xF0) >> 4);
    out->level = payload[9];
    return true;
}

void lmp_dump(const char *label, const uint8_t *data, size_t len) {
    char hex[LMP_LONG_FRAME_LEN * 3 + 1];
    size_t pos = 0;

    for (size_t i = 0; i < len && i < LMP_LONG_FRAME_LEN; i++) {
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02x ", data[i]);
    }
    LMP_LOGI(TAG, "%s [%u] %s", label, (unsigned)len, hex);
}
