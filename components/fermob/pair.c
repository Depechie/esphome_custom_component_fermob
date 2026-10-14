#include "pair.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"

#include "lmp.h"

static const char *TAG = "fermob.pair";

/* Steps mirror the app's fAckSuccess chain. */
typedef enum {
    ST_PROBE = 0,     /* REGISTER arg 0 over cleartext */
    ST_FETCH_PUBKEY,  /* AUTHKEY_GET arg 0 over cleartext (adopt mode only) */
    ST_NONCE,         /* NONCE_GENERATE, or NONCE_SET with our nonce */
    ST_CRYPT_PUBLIC,  /* CRYPT_SET PUBLIC_KEY, still cleartext */
    ST_AUTHKEY,       /* AUTHKEY_GENERATE, or AUTHKEY_SET, encrypted public */
    ST_CRYPT_PRIVATE, /* CRYPT_SET PRIVATE_KEY, encrypted public */
    ST_MODULE_INFO,   /* MODULE_INFO_GET, encrypted private */
    ST_DEVICE_INFO,   /* DEVICE_INFO_GET, encrypted private */
    ST_REGISTER,      /* REGISTER arg 1, encrypted private */
    ST_COUNT,
} pair_step_t;

static const char *const STEP_NAME[ST_COUNT] = {
    "REGISTER(0) probe", "AUTHKEY_GET public key", "nonce", "CRYPT_SET public",
    "authkey",          "CRYPT_SET private",     "MODULE_INFO_GET",
    "DEVICE_INFO_GET",  "REGISTER(1)",
};

/* One outbound command. A long payload needs its chunks written over several
 * scheduler turns, so the request outlives the call that created it. Pairing is
 * strictly sequential - one command in flight, the next one only after its ACK -
 * so a single static slot is enough and no allocation is needed. */
typedef struct {
    lmp_msg_t msg;
    uint8_t chunks;
    uint8_t chunk;
    const uint8_t *key;
    const uint8_t *nonce;
    bool in_use;
} pair_send_t;

typedef struct {
    pair_state_t state;
    pair_mode_t mode;
    pair_step_t step;
    uint8_t seq;
    bool have_seq;
    uint32_t ack_deadline_ms;
    pair_secrets_t secrets;

    /* Inbound long-frame reassembly. */
    uint8_t rx_buf[LMP_LONG_PAYLOAD_MAX];
    uint8_t rx_seen[LMP_LONG_PAYLOAD_MAX / LMP_PAYLOAD_LEN];
    uint8_t rx_chunks;

    /* MODULE_INFO_GET answer. */
    pair_module_info_t module_info;
} pair_ctx_t;

static pair_io_t s_io = {0};
static bool s_io_ready = false;
static pair_ctx_t s_pair = {.state = PAIR_IDLE, .mode = PAIR_MODE_ADOPT, .step = ST_PROBE};
static pair_send_t s_send = {0};

static void pair_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[192];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LMP_LOGI(TAG, "%s", buf);
}

/* ---------------------------------------------------------------- secrets -- */

static void to_hex(const uint8_t *data, size_t len, char *out, size_t out_size) {
    size_t pos = 0;
    out[0] = '\0';
    for (size_t i = 0; i < len && pos + 3 < out_size; i++) {
        pos += snprintf(out + pos, out_size - pos, "%02x", data[i]);
    }
}

static bool parse_hex(const char *hex, uint8_t *out, size_t out_len) {
    if (hex == NULL || strlen(hex) != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            return false;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

void pair_set_io(const pair_io_t *io) {
    if (io == NULL) {
        s_io_ready = false;
        return;
    }
    s_io = *io;
    s_io_ready = io->write != NULL && io->next_seq != NULL && io->is_ready != NULL &&
                 io->now_ms != NULL && io->defer != NULL && io->load_secrets != NULL &&
                 io->save_secrets != NULL && io->erase_secrets != NULL &&
                 io->save_module_info != NULL;
    if (!s_io_ready) {
        LMP_LOGE(TAG, "pair_set_io got an incomplete io table");
    }
}

static void save_secrets(void) {
    if (!s_io_ready) {
        return;
    }
    s_io.save_secrets(s_io.ctx, &s_pair.secrets);
}

bool pair_init(void) {
    if (!s_io_ready) {
        LMP_LOGE(TAG, "pair_init without a complete io table");
        return false;
    }
    s_io.load_secrets(s_io.ctx, &s_pair.secrets);
    pair_log("secrets restored: pub %s priv %s nonce %s", s_pair.secrets.have_pub ? "yes" : "no",
             s_pair.secrets.have_priv ? "yes" : "no", s_pair.secrets.have_nonce ? "yes" : "no");
    return pair_secrets_known();
}

bool pair_secrets_known(void) {
    return s_pair.secrets.have_pub && s_pair.secrets.have_priv && s_pair.secrets.have_nonce;
}

/* Drops the installation secrets so a light can be paired again from scratch,
 * e.g. after an unregister or a factory reset. */
bool pair_forget(void) {
    if (s_pair.state == PAIR_RUNNING) {
        pair_log("cannot forget secrets while pairing");
        return false;
    }
    memset(&s_pair.secrets, 0, sizeof(s_pair.secrets));
    s_pair.state = PAIR_IDLE;
    if (s_io_ready) {
        s_io.erase_secrets(s_io.ctx);
    }
    pair_log("forgot the stored public key, private key and nonce");
    return true;
}

const uint8_t *pair_public_key(void) {
    return s_pair.secrets.have_pub ? s_pair.secrets.pub : NULL;
}

const uint8_t *pair_private_key(void) {
    return s_pair.secrets.have_priv ? s_pair.secrets.priv : NULL;
}

const uint8_t *pair_nonce(void) {
    return s_pair.secrets.have_nonce ? s_pair.secrets.nonce : NULL;
}

const uint8_t *pair_key_for(uint8_t encryption, const uint8_t **nonce_out) {
    const uint8_t *nonce = s_pair.secrets.have_nonce ? s_pair.secrets.nonce : NULL;
    if (nonce_out != NULL) {
        *nonce_out = nonce;
    }
    switch (encryption) {
    case LMP_ENC_PUBLIC_KEY:
        return s_pair.secrets.have_pub ? s_pair.secrets.pub : NULL;
    case LMP_ENC_PRIVATE_KEY:
        return s_pair.secrets.have_priv ? s_pair.secrets.priv : NULL;
    default:
        return NULL;
    }
}

bool pair_set_secret(const char *name, const char *hex32) {
    if (name == NULL || hex32 == NULL) {
        return false;
    }
    if (strcmp(name, "pub") == 0) {
        if (!parse_hex(hex32, s_pair.secrets.pub, PAIR_KEY_LEN)) {
            return false;
        }
        s_pair.secrets.have_pub = true;
    } else if (strcmp(name, "priv") == 0) {
        if (!parse_hex(hex32, s_pair.secrets.priv, PAIR_KEY_LEN)) {
            return false;
        }
        s_pair.secrets.have_priv = true;
    } else if (strcmp(name, "nonce") == 0) {
        if (!parse_hex(hex32, s_pair.secrets.nonce, PAIR_KEY_LEN)) {
            return false;
        }
        s_pair.secrets.have_nonce = true;
    } else {
        return false;
    }
    save_secrets();
    return true;
}

void pair_print_keys(void) {
    char hex[PAIR_KEY_LEN * 2 + 1];
    if (!pair_secrets_known()) {
        pair_log("no complete secret set stored");
        return;
    }
    to_hex(s_pair.secrets.pub, PAIR_KEY_LEN, hex, sizeof(hex));
    pair_log("pub   %s", hex);
    to_hex(s_pair.secrets.priv, PAIR_KEY_LEN, hex, sizeof(hex));
    pair_log("priv  %s", hex);
    to_hex(s_pair.secrets.nonce, PAIR_KEY_LEN, hex, sizeof(hex));
    pair_log("nonce %s", hex);
}

/* ---------------------------------------------------------------- outbound -- */

static void send_chunk(void *arg) {
    uint8_t frame[LMP_LONG_FRAME_LEN];
    size_t n;

    if (!s_send.in_use) {
        return;
    }

    n = (s_send.chunks == 1) ? lmp_encode_short(&s_send.msg, s_send.key, s_send.nonce, frame, sizeof(frame))
                             : lmp_encode_long(&s_send.msg, s_send.key, s_send.nonce, s_send.chunk,
                                               frame, sizeof(frame));
    if (n == 0) {
        pair_log("encode failed on chunk %u/%u", s_send.chunk + 1, s_send.chunks);
        s_send.in_use = false;
        s_pair.state = PAIR_FAILED;
        s_pair.have_seq = false;
        return;
    }
    if (!s_io.write(s_io.ctx, frame, n)) {
        pair_log("write failed on chunk %u/%u", s_send.chunk + 1, s_send.chunks);
        s_send.in_use = false;
        s_pair.state = PAIR_FAILED;
        s_pair.have_seq = false;
        return;
    }

    s_send.chunk++;
    if (s_send.chunk >= s_send.chunks) {
        s_send.in_use = false;
        return;
    }
    /* The app sleeps 40 ms between chunks; the light drops fragments that
     * arrive back to back. */
    s_io.defer(s_io.ctx, 40, send_chunk, NULL);
}

static bool send_payload(const uint8_t *payload, size_t payload_len, uint8_t message_type,
                         uint8_t encryption, const char *what) {
    const uint8_t *nonce = NULL;
    const uint8_t *key;

    if (s_send.in_use) {
        pair_log("refusing %s: a command is still being sent", what);
        return false;
    }

    /* The encoder only encrypts when it has both halves, so a missing nonce would
     * send a plaintext body under an encrypted header and the light would answer
     * with an unexplained CRC error. Refuse instead. */
    key = pair_key_for(encryption, &nonce);
    if (encryption != LMP_ENC_NONE && (key == NULL || nonce == NULL)) {
        pair_log("refusing to send an encrypted cmd: %s key %s, nonce %s",
                 encryption == LMP_ENC_PRIVATE_KEY ? "private" : "public",
                 key == NULL ? "missing" : "known", nonce == NULL ? "missing" : "known");
        return false;
    }

    memset(&s_send, 0, sizeof(s_send));
    lmp_msg_init(&s_send.msg, payload, payload_len);
    s_send.msg.message_type = message_type;
    s_send.msg.encryption = encryption;
    s_send.msg.seq_id = s_io.next_seq(s_io.ctx);
    s_pair.seq = s_send.msg.seq_id;
    s_pair.have_seq = true;

    /* Logged here, after the id is drawn, so the number is the one on the wire
     * and the ACK that comes back can be matched against it. */
    if (what != NULL) {
        pair_log("-> %s cmd %u enc %u seq %u", what, payload[1], encryption, s_send.msg.seq_id);
    }

    s_send.key = key;
    s_send.nonce = nonce;
    s_send.chunks = lmp_chunks_needed(s_send.msg.payload_len);
    s_send.chunk = 0;
    s_send.in_use = true;
    send_chunk(NULL);
    return s_pair.state != PAIR_FAILED;
}

/* Pairing payloads declare a length that counts the bytes after it, as in the
 * app: [2, CRYPT_SET, PUBLIC_KEY] or [17, CRYPT_NONCE_SET, <16 nonce>]. */
static bool send_cmd(pair_step_t step, uint8_t command, const uint8_t *data, size_t data_len,
                     uint8_t encryption) {
    uint8_t payload[LMP_LONG_PAYLOAD_MAX];

    if (2 + data_len > sizeof(payload)) {
        pair_log("payload for cmd %u too long", command);
        return false;
    }
    payload[0] = (uint8_t)(1 + data_len);
    payload[1] = command;
    if (data_len > 0) {
        memcpy(payload + 2, data, data_len);
    }
    return send_payload(payload, 2 + data_len, LMP_MSG_CMD_ACK, encryption, STEP_NAME[step]);
}

static void fail(const char *why, int code);
static pair_step_t awaiting_step(void);

void pair_tick(void) {
    if (!s_io_ready || s_pair.state != PAIR_RUNNING || !s_pair.have_seq) {
        return;
    }
    if (s_io.now_ms(s_io.ctx) - s_pair.ack_deadline_ms > (uint32_t)PAIR_ACK_TIMEOUT_MS) {
        /* step is already advanced past the command in flight. */
        pair_log("no ACK for %s after %d ms", STEP_NAME[awaiting_step()], PAIR_ACK_TIMEOUT_MS);
        fail("the light stopped responding", -1);
    }
}

/* ----------------------------------------------------------------- machine -- */

/* The step whose ACK is outstanding: step is advanced before sending, so the
 * command in flight is the previous one. */
static pair_step_t awaiting_step(void) {
    return (s_pair.step > ST_PROBE) ? (pair_step_t)(s_pair.step - 1) : ST_PROBE;
}

static uint8_t step_ack_data(const pair_step_t step) {
    switch (step) {
    case ST_FETCH_PUBKEY:
        return PAIR_KEY_LEN;
    case ST_NONCE:
    case ST_AUTHKEY:
        /* Sharing installs these instead of asking for them. */
        return s_pair.mode == PAIR_MODE_ADOPT ? PAIR_KEY_LEN : 0;
    default:
        return 0;
    }
}

static bool send_step(pair_step_t step) {
    switch (step) {
    case ST_PROBE:
        return send_cmd(step, LMP_CMD_REGISTER, (const uint8_t[]){0}, 1, LMP_ENC_NONE);

    case ST_FETCH_PUBKEY:
        return send_cmd(step, LMP_CMD_AUTHKEY_GET, (const uint8_t[]){0}, 1, LMP_ENC_NONE);

    case ST_NONCE:
        if (s_pair.mode == PAIR_MODE_SHARE) {
            if (!s_pair.secrets.have_nonce) {
                pair_log("no nonce to share; generate one first");
                return false;
            }
            return send_cmd(step, LMP_CMD_NONCE_SET, s_pair.secrets.nonce, PAIR_KEY_LEN, LMP_ENC_NONE);
        }
        return send_cmd(step, LMP_CMD_NONCE_GENERATE, NULL, 0, LMP_ENC_NONE);

    case ST_CRYPT_PUBLIC:
        return send_cmd(step, LMP_CMD_CRYPT_SET, (const uint8_t[]){LMP_ENC_PUBLIC_KEY}, 1, LMP_ENC_NONE);

    case ST_AUTHKEY:
        if (s_pair.mode == PAIR_MODE_SHARE) {
            if (!s_pair.secrets.have_priv) {
                pair_log("no private key to share; generate one first");
                return false;
            }
            {
                uint8_t arg[1 + PAIR_KEY_LEN];
                arg[0] = 1;
                memcpy(arg + 1, s_pair.secrets.priv, PAIR_KEY_LEN);
                return send_cmd(step, LMP_CMD_AUTHKEY_SET, arg, sizeof(arg), LMP_ENC_PUBLIC_KEY);
            }
        }
        return send_cmd(step, LMP_CMD_AUTHKEY_GENERATE, (const uint8_t[]){1}, 1, LMP_ENC_PUBLIC_KEY);

    case ST_CRYPT_PRIVATE:
        return send_cmd(step, LMP_CMD_CRYPT_SET, (const uint8_t[]){LMP_ENC_PRIVATE_KEY}, 1,
                        LMP_ENC_PUBLIC_KEY);

    case ST_MODULE_INFO:
        return send_cmd(step, LMP_CMD_MODULE_INFO_GET, NULL, 0, LMP_ENC_PRIVATE_KEY);

    case ST_DEVICE_INFO:
        return send_cmd(step, LMP_CMD_DEVICE_INFO_GET, NULL, 0, LMP_ENC_PRIVATE_KEY);

    case ST_REGISTER:
        return send_cmd(step, LMP_CMD_REGISTER, (const uint8_t[]){1}, 1, LMP_ENC_PRIVATE_KEY);

    default:
        return false;
    }
}

static void harvest(const uint8_t *data, size_t data_len, uint8_t *slot, bool *have,
                    const char *name) {
    char hex[PAIR_KEY_LEN * 2 + 1];
    if (data_len < PAIR_KEY_LEN) {
        pair_log("short ACK for %s: %u bytes, need %u", name, (unsigned)data_len,
                 (unsigned)PAIR_KEY_LEN);
        return;
    }
    memcpy(slot, data, PAIR_KEY_LEN);
    *have = true;
    to_hex(slot, PAIR_KEY_LEN, hex, sizeof(hex));
    pair_log("<- %s = %s", name, hex);
    save_secrets();
}

/* MODULE_INFO_GET answers with a TLV chain: [length, opcode, value...], where
 * the length counts the opcode and its value and a zero length ends it. The
 * app walks exactly this, keeping only the two fields that change what it puts
 * on the wire afterwards: the mesh short address that goes into the frame
 * header, and the API version that decides the DEVICE_DATA_SET layout. */
static void parse_module_info(const uint8_t *payload, size_t len) {
    size_t offset = 0;

    memset(&s_pair.module_info, 0, sizeof(s_pair.module_info));
    while (offset < len) {
        uint8_t tlv_len = payload[offset];
        uint8_t opcode;

        if (tlv_len == 0) {
            break;
        }
        if (offset + 1 + tlv_len > len) {
            pair_log("MODULE_INFO record runs past the answer");
            return;
        }
        opcode = payload[offset + 1];
        if (opcode == LMP_PARAM_SHORT_ADDRESS && tlv_len >= 3) {
            /* Keep the TLV bytes in wire order. The display representation is
             * reversed, but frame bytes 2 and 3 use the original order. */
            s_pair.module_info.short_address =
                (uint16_t)((payload[offset + 2] << 8) | payload[offset + 3]);
            s_pair.module_info.have_short_address = true;
        } else if (opcode == LMP_PARAM_MODULE_API_VERSION && tlv_len >= 2) {
            s_pair.module_info.api_version = payload[offset + 2];
            s_pair.module_info.have_api_version = true;
        }
        offset += tlv_len + 1;
    }
    if (s_pair.module_info.have_short_address) {
        pair_log("<- module short address %04x, api version %u", s_pair.module_info.short_address,
                 s_pair.module_info.api_version);
    } else {
        pair_log("<- module info carried no short address, mesh commands stay addressed to 0000");
    }
    /* Persisted before REGISTER(1): if this pairing attempt fails from here on,
     * the next boot still knows how to address the light. */
    if (s_io_ready && s_io.save_module_info != NULL) {
        s_io.save_module_info(s_io.ctx);
    }
}

static void finish(void) {
    s_pair.state = PAIR_DONE;
    s_pair.have_seq = false;
    s_pair.ack_deadline_ms = 0;
    /* The ESPHome backend only marks persisted keys confirmed after the final
     * REGISTER(1) ACK. Earlier key writes are retained for retry, not control. */
    save_secrets();
    pair_log("pairing complete, traffic is now encrypted with the private key");
}

static void next_step(void);

/* code is the light's ACK status, or -1 when there was no ACK to quote. */
static void fail(const char *why, int code) {
    if (code >= 0) {
        pair_log("pairing failed: %s (ack code %d)", why, code);
    } else {
        pair_log("pairing failed: %s", why);
    }
    s_pair.state = PAIR_FAILED;
    s_pair.have_seq = false;
    s_send.in_use = false;
}

static void next_step(void) {
    pair_step_t step = s_pair.step;

    if (step >= ST_COUNT) {
        finish();
        return;
    }
    /* Advance before sending: the ACK handler maps an inbound ACK back onto
     * s_pair.step - 1, and a light that answers within send_step would otherwise
     * have this frame's step overwritten on the way back up. */
    s_pair.step = (pair_step_t)(step + 1);
    s_pair.ack_deadline_ms = s_io.now_ms(s_io.ctx);
    if (!send_step(step)) {
        s_pair.state = PAIR_FAILED;
        s_pair.have_seq = false;
    }
}

/* ACK payload layout, as the app reads it: [length, LMP_STATUS_ACK, status,
 * data...]. The app harvests the secrets at fixed offsets with payload.splice(3,
 * 16), so the data length comes from the step, never from payload[0]. This takes
 * the raw reassembled buffer: a key ACK spans two frames and is 30 bytes on the
 * wire. Returns true when the frame belonged to pairing and was handled here, so
 * the caller knows not to look at it again. */
static bool handle_ack(const uint8_t *payload, size_t payload_len, uint8_t seq) {
    uint8_t status = 0;
    pair_step_t done;
    size_t data_len;
    const uint8_t *data;

    if (s_pair.state != PAIR_RUNNING) {
        /* Not ours: an answer to the hub's own state query looks exactly like
         * this, so it has to fall through rather than be swallowed. */
        return false;
    }
    if (payload_len < 3) {
        pair_log("<- ACK too short (%u bytes)", (unsigned)payload_len);
        return true;
    }
    /* The app keeps a queue keyed by the header id and looks the ACK up with
     * getId(), so a reply for another command is not ours to act on. */
    if (!s_pair.have_seq || seq != s_pair.seq) {
        pair_log("<- ACK for seq %u ignored, awaiting %u", seq, s_pair.seq);
        return true;
    }
    status = payload[2];
    s_pair.have_seq = false;

    if (status != LMP_ERR_SUCCESS) {
        pair_log("<- %s rejected with status %u (%s)", STEP_NAME[awaiting_step()], status,
                 status == LMP_ERR_INVALID_COMMAND       ? "invalid command"
                 : status == LMP_ERR_INVALID_PARAMETER ? "invalid parameter"
                 : status == LMP_ERR_NOT_SUPPORTED      ? "not supported"
                                                       : "unknown");
        fail("light rejected the command", status);
        return true;
    }

    done = awaiting_step();
    /* payload[1] is LMP_STATUS_ACK (128) in every answer the light gives: the
     * ACK payload is a TLV chain, not an echo of the command. The app never
     * compares it, so neither does this. */

    data = payload + 3;
    data_len = payload_len - 3;
    if (data_len < step_ack_data(done)) {
        pair_log("<- short ACK for %s: %u bytes, need %u", STEP_NAME[done], (unsigned)data_len,
                 step_ack_data(done));
        fail("light did not return the expected key material", -1);
        return true;
    }

    if (done == ST_FETCH_PUBKEY) {
        /* Both modes need the light's public key: it is what the light
         * encrypts with, and no command sets it. */
        harvest(data, data_len, s_pair.secrets.pub, &s_pair.secrets.have_pub, "public key");
    } else if (s_pair.mode == PAIR_MODE_ADOPT) {
        /* Sharing installs the nonce and private key rather than harvesting
         * them: the light never reports them back. */
        if (done == ST_NONCE) {
            harvest(data, data_len, s_pair.secrets.nonce, &s_pair.secrets.have_nonce, "nonce");
        } else if (done == ST_AUTHKEY) {
            harvest(data, data_len, s_pair.secrets.priv, &s_pair.secrets.have_priv, "private key");
        }
    } else if (done == ST_MODULE_INFO) {
        parse_module_info(payload, payload_len);
    }

    next_step();
    return true;
}

static bool handle_payload(const uint8_t *payload, size_t len, uint8_t message_type, uint8_t seq) {
    if (len < 2 || message_type != LMP_MSG_ACK) {
        return false;
    }
    return handle_ack(payload, len, seq);
}

/* Pairing ends after the light pushes an LMP_STATUS_DEVICE_INFO record in a
 * STATUS/EVENT frame naming the last device in the list. */
static void handle_device_info(const uint8_t *payload, size_t len) {
    size_t offset = 0;

    /* TLV chain: [length, opcode, value...], where length counts the opcode and
     * its value, and a zero length byte ends the chain. */
    while (offset < len) {
        uint8_t tlv_len = payload[offset];
        uint8_t opcode;

        if (tlv_len == 0) {
            break;
        }
        if (offset + 1 + tlv_len > len) {
            pair_log("DEVICE_INFO record runs past the frame");
            return;
        }
        opcode = payload[offset + 1];
        if (opcode == LMP_STATUS_DEVICE_INFO && tlv_len >= 5) {
            uint8_t total = payload[offset + 2];
            uint8_t index = payload[offset + 3];
            uint16_t device_type = (uint16_t)(payload[offset + 4] | (payload[offset + 5] << 8));
            pair_set_device_type(device_type);
            if (s_io_ready && s_io.save_module_info != NULL) {
                s_io.save_module_info(s_io.ctx);
            }
            pair_log("<- DEVICE_INFO device %u of %u, type %u", index, total, device_type);
            if (s_pair.state == PAIR_RUNNING && awaiting_step() == ST_DEVICE_INFO &&
                total != 0 && index == (uint8_t)(total - 1)) {
                next_step();
            }
            return;
        }
        offset += tlv_len + 1;
    }
    pair_log("<- a status frame arrived with no DEVICE_INFO record in it");
}

/* ---------------------------------------------------------------- inbound -- */

static void rx_reset(void) {
    memset(s_pair.rx_buf, 0, sizeof(s_pair.rx_buf));
    memset(s_pair.rx_seen, 0, sizeof(s_pair.rx_seen));
    s_pair.rx_chunks = 0;
}

bool pair_handle_frame(const uint8_t *data, size_t len) {
    lmp_rx_t rx;
    uint8_t frame = 0;
    uint8_t enc = 0;
    uint8_t message_type = 0;
    uint8_t seq = 0;
    const uint8_t *key;
    const uint8_t *nonce = NULL;
    uint8_t chunk = 0;
    uint8_t chunks = 0;
    size_t total;
    bool handled;

    if (!lmp_frame_header(data, len, &frame, &enc, &message_type, &seq)) {
        return false;
    }
    /* Only ACKs and status/event frames are reassembled here. Short status and
     * event frames are left to the hub, which parses the DEVICE_DATA records. */
    if (message_type != LMP_MSG_ACK && message_type != LMP_MSG_STATUS && message_type != LMP_MSG_EVENT) {
        return false;
    }

    key = pair_key_for(enc, &nonce);

    if (frame == LMP_FRAME_LOCAL_SHORT || frame == LMP_FRAME_LMP_SHORT) {
        if (!lmp_decode_short(data, len, key, nonce, &rx) || !rx.crc_ok) {
            pair_log("short frame bad crc (enc %u, key %s)", enc, key == NULL ? "none" : "known");
            return false;
        }
        if (message_type == LMP_MSG_STATUS || message_type == LMP_MSG_EVENT) {
            handle_device_info(rx.payload, rx.payload_len);
            return false;
        }
        return handle_payload(rx.payload, rx.payload_len, rx.message_type, seq);
    }

    if (!lmp_decode_long(data, len, key, nonce, &rx, &chunk, &chunks) || !rx.crc_ok) {
        pair_log("long chunk %u bad crc", chunk);
        return false;
    }
    if (chunks == 0 || chunks > LMP_LONG_PAYLOAD_MAX / LMP_PAYLOAD_LEN || chunk >= chunks) {
        pair_log("long chunk %u/%u out of range", chunk, chunks);
        return false;
    }

    if (chunk == 0) {
        rx_reset();
        s_pair.rx_chunks = chunks;
    } else if (s_pair.rx_chunks != chunks) {
        rx_reset();
        return false;
    }
    memcpy(s_pair.rx_buf + (size_t)chunk * LMP_PAYLOAD_LEN, rx.payload, LMP_PAYLOAD_LEN);
    s_pair.rx_seen[chunk] = 1;
    for (uint8_t i = 0; i < chunks; i++) {
        if (!s_pair.rx_seen[i]) {
            return true;
        }
    }

    /* The last chunk carries one 0x00 then 0xff padding bytes, but a key may
     * legitimately end in 0xff, so the buffer is handed over whole and the ACK
     * handler reads its fixed width instead of guessing where data ends. */
    total = (size_t)chunks * LMP_PAYLOAD_LEN;
    pair_log("reassembled %u bytes from %u chunks (declared %u)", (unsigned)total, chunks,
             s_pair.rx_buf[0]);
    handled = handle_payload(s_pair.rx_buf, total, message_type, seq);
    if (message_type != LMP_MSG_ACK) {
        handle_device_info(s_pair.rx_buf, total);
    }
    rx_reset();
    return handled;
}

/* -------------------------------------------------------------------- api -- */

pair_state_t pair_state(void) {
    return s_pair.state;
}

const pair_module_info_t *pair_module_info(void) {
    return &s_pair.module_info;
}

void pair_set_module_info(uint16_t short_address, uint8_t api_version) {
    s_pair.module_info.short_address = short_address;
    s_pair.module_info.have_short_address = true;
    s_pair.module_info.api_version = api_version;
    s_pair.module_info.have_api_version = true;
}

void pair_set_device_type(uint16_t device_type) {
    s_pair.module_info.device_type = device_type;
    s_pair.module_info.have_device_type = true;
}

const char *pair_state_name(void) {
    switch (s_pair.state) {
    case PAIR_IDLE:
        return "idle";
    case PAIR_RUNNING:
        return "running";
    case PAIR_DONE:
        return "done";
    default:
        return "failed";
    }
}

uint8_t pair_encryption_mode(void) {
    return pair_secrets_known() ? LMP_ENC_PRIVATE_KEY : LMP_ENC_NONE;
}

/* Sharing needs a nonce and a private key up front. Generating them here keeps a
 * brand new installation one command instead of three. */
static void ensure_share_secrets(void) {
    if (!s_pair.secrets.have_nonce) {
        esp_fill_random(s_pair.secrets.nonce, PAIR_KEY_LEN);
        s_pair.secrets.have_nonce = true;
        pair_log("generated a new nonce to share");
    }
    if (!s_pair.secrets.have_priv) {
        esp_fill_random(s_pair.secrets.priv, PAIR_KEY_LEN);
        s_pair.secrets.have_priv = true;
        pair_log("generated a new private key to share");
    }
    save_secrets();
}

bool pair_start(pair_mode_t mode) {
    if (!s_io_ready) {
        pair_log("cannot pair without a complete io table");
        return false;
    }
    if (s_pair.state == PAIR_RUNNING) {
        pair_log("pairing already running");
        return false;
    }
    if (!s_io.is_ready(s_io.ctx)) {
        pair_log("not connected to a light");
        return false;
    }

    s_pair.mode = mode;
    s_pair.step = ST_PROBE;
    s_pair.state = PAIR_RUNNING;
    s_pair.rx_chunks = 0;
    memset(s_pair.rx_seen, 0, sizeof(s_pair.rx_seen));
    pair_log("pairing started in %s mode", mode == PAIR_MODE_SHARE ? "share" : "adopt");
    if (mode == PAIR_MODE_SHARE) {
        ensure_share_secrets();
    }
    next_step();

    /* A light that answers inside the write can finish the chain before this
     * returns, so only an outright failure is a refusal. */
    return s_pair.state != PAIR_FAILED;
}

void pair_stop(void) {
    if (s_pair.state == PAIR_RUNNING) {
        pair_log("pairing aborted");
    }
    s_pair.state = PAIR_IDLE;
    s_pair.have_seq = false;
    s_send.in_use = false;
    rx_reset();
}
