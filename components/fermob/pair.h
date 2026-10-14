/* Linkio/Fermob pairing state machine.
 *
 * The app never reads keys back with NONCE_GET/AUTHKEY_GET during pairing. It
 * sends REGISTER(0) to probe the light, then walks the light through
 * CRYPT_NONCE_GENERATE / CRYPT_AUTHKEY_GENERATE (or pushes a known nonce and
 * private key) while harvesting the public key, nonce and private key out of
 * the ACKs. Every step is CMD_WITH_ACK, and the next command is only sent once
 * the current one is acknowledged.
 *
 * Everything the state machine needs from the outside arrives through pair_io_t:
 * the link to write frames on, monotonic time, deferred callbacks for the gap
 * between long-frame chunks, and persistence for the installation secrets. That
 * keeps this file free of ESPHome, FreeRTOS and NVS calls.
 *
 * Nothing here has been validated against hardware yet; every step is logged so
 * a real session can be compared against this sequence.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAIR_KEY_LEN 16

typedef enum {
    PAIR_IDLE,
    PAIR_RUNNING,
    PAIR_DONE,
    PAIR_FAILED,
} pair_state_t;

typedef enum {
    /* The app's normal "add a module" path (performPairingProcedure defaults
     * firstModulePaired to true): the light generates its own key material and
     * this controller harvests the public key, nonce and private key from the
     * AUTHKEY_GET, NONCE_GENERATE and AUTHKEY_GENERATE acknowledgements. Needs
     * nothing stored up front. */
    PAIR_MODE_ADOPT,
    /* The app's very first module (firstModulePaired false): this controller
     * pushes its own nonce and private key with NONCE_SET and AUTHKEY_SET so
     * several lights end up sharing one installation key. Missing keys are
     * generated and stored. The light's public key is still read with
     * AUTHKEY_GET, because that is what it encrypts with and there is no
     * command to set it. */
    PAIR_MODE_SHARE,
} pair_mode_t;

/* How long a pairing command may go unanswered before the run is abandoned. */
#define PAIR_ACK_TIMEOUT_MS 4000

/* The installation secrets, as one blob so persistence stays a single call. */
typedef struct {
    uint8_t pub[PAIR_KEY_LEN];
    uint8_t priv[PAIR_KEY_LEN];
    uint8_t nonce[PAIR_KEY_LEN];
    bool have_pub;
    bool have_priv;
    bool have_nonce;
} pair_secrets_t;

typedef struct {
    /* Passed back to every callback, so the hub can be reached from the static
     * transport below. */
    void *ctx;

    /* Writes one 20 byte frame. False when the link refused it. */
    bool (*write)(void *ctx, const uint8_t *data, size_t len);
    /* Sequence id to stamp on the next outbound frame. */
    uint8_t (*next_seq)(void *ctx);
    /* True once the characteristic is connected, discovered and writable. */
    bool (*is_ready)(void *ctx);
    /* Monotonic milliseconds, for the ACK deadline. */
    uint32_t (*now_ms)(void *ctx);
    /* Runs fn(ctx_arg) on the caller's scheduler after delay_ms. Long payloads
     * need their chunks spaced out, and the light expects the same pacing the
     * app's 40 ms inter-chunk delay produced. */
    void (*defer)(void *ctx, uint32_t delay_ms, void (*fn)(void *), void *ctx_arg);

    void (*load_secrets)(void *ctx, pair_secrets_t *out);
    void (*save_secrets)(void *ctx, const pair_secrets_t *in);
    void (*erase_secrets)(void *ctx);
    /* Called as soon as MODULE_INFO_GET has been parsed, so a reboot can address
     * the light without pairing it again. */
    void (*save_module_info)(void *ctx);
} pair_io_t;

/* What MODULE_INFO_GET reports about the light. The app needs both: mesh
 * commands carry the module's short address in the frame header, and the
 * DEVICE_DATA_SET layout depends on the API version. */
typedef struct {
    uint16_t short_address;
    uint16_t device_type;
    uint8_t api_version;
    bool have_short_address;
    bool have_api_version;
    bool have_device_type;
} pair_module_info_t;

/* Valid after a pairing run has read MODULE_INFO_GET, and empty before it. */
const pair_module_info_t *pair_module_info(void);

/* Restores a previously read MODULE_INFO after a reboot, so mesh commands can be
 * addressed correctly before the light is paired again. */
void pair_set_module_info(uint16_t short_address, uint8_t api_version);
void pair_set_device_type(uint16_t device_type);

/* Must be called before pair_init(). The table is copied, but the pointers it
 * holds are borrowed for the lifetime of the process. */
void pair_set_io(const pair_io_t *io);

/* Loads the installation secrets. Call once from setup. */
bool pair_init(void);

/* Drives the ACK deadline; call it regularly from the main loop. */
void pair_tick(void);

/* Runs the ACK-chained pairing sequence against a ready link. */
bool pair_start(pair_mode_t mode);

void pair_stop(void);

pair_state_t pair_state(void);
const char *pair_state_name(void);

/* Encryption mode outbound frames should use once pairing completed. */
uint8_t pair_encryption_mode(void);

/* Key/nonce for a frame with the given encryption mode, NULL for LMP_ENC_NONE. */
const uint8_t *pair_key_for(uint8_t encryption, const uint8_t **nonce_out);

/* Feeds a raw inbound frame: decodes short frames and reassembles long frames
 * using the key named by the frame header. Returns true when it consumed the
 * frame as part of the pairing exchange. */
bool pair_handle_frame(const uint8_t *data, size_t len);

bool pair_secrets_known(void);
bool pair_forget(void);
const uint8_t *pair_public_key(void);
const uint8_t *pair_private_key(void);
const uint8_t *pair_nonce(void);

/* name is "pub", "priv" or "nonce"; hex32 is 32 hex characters. */
bool pair_set_secret(const char *name, const char *hex32);

/* Logs the stored triple, for capturing it from the log. */
void pair_print_keys(void);

#ifdef __cplusplus
}
#endif
