#pragma once

#include "esphome/core/component.h"
#include "esphome/core/preferences.h"
#include "esphome/core/defines.h"

#include "esphome/components/esp32_ble_client/ble_client_base.h"
#include "esphome/components/esp32_ble_client/ble_service.h"

#include "lmp.h"
#include "pair.h"

namespace esphome {
namespace fermob {

// Fermob's own BLE service and the single characteristic every LMP frame goes
// in and out of. Long as well as short frames fit because the MTU is fixed at 20
// used by the Fermob BLE protocol.
static const uint16_t FERMOB_SERVICE_UUID16 = 0x41C1;
static const uint16_t FERMOB_CHARACTERISTIC_UUID16 = 0x5002;
static const uint8_t FERMOB_MTU = LMP_MTU;
static const uint8_t FERMOB_DEVICE_INDEX = 0;

// How long to wait for a write to complete before treating the link as broken.
// The light answers a write well inside this.
static const uint32_t WRITE_TIMEOUT_MS = 5000;
// How long after connect before the first LMP command is sent.
static const uint32_t CONNECT_SETTLE_MS = 1000;
// Seconds between state queries while connected. The light pushes notifications
// when something changes locally (a button, the app, power cycling), but a poll
// also recovers the state after a reconnect, which is when the hub entity
// otherwise starts blind.
static const uint32_t POLL_INTERVAL_S = 300;

struct FermobSecretBlob {
  uint8_t magic[4];
  uint8_t flags;
  uint8_t pub[PAIR_KEY_LEN];
  uint8_t priv[PAIR_KEY_LEN];
  uint8_t nonce[PAIR_KEY_LEN];
};

/* MODULE_INFO_GET results, kept in their own preference so the secret blob
 * format never has to change underneath an installed node. Mesh commands carry
 * the short address in the frame header, and the light answers a query aimed at
 * the wrong address with a non-zero status rather than silence. */
struct FermobModuleBlob {
  uint8_t magic[4];
  uint16_t short_address;
  uint8_t api_version;
};

struct FermobDeviceBlob {
  uint8_t magic[4];
  uint16_t device_type;
};

enum FermobDeviceState : uint8_t {
  FERMOB_STATE_IDLE = 0,
  FERMOB_STATE_SCANNING,
  FERMOB_STATE_CONNECTING,
  FERMOB_STATE_PAIRING,
  FERMOB_STATE_CONNECTED,
  FERMOB_STATE_ERROR,
};

enum FermobPairingMode : uint8_t {
  FERMOB_PAIRING_ADOPT = PAIR_MODE_ADOPT,
  FERMOB_PAIRING_SHARE = PAIR_MODE_SHARE,
};

class FermobHub : public esphome::esp32_ble_client::BLEClientBase {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return esphome::setup_priority::DATA; }

  // ESPBTClient
  bool parse_device(const esphome::esp32_ble_tracker::ESPBTDevice &device) override;
  void on_scan_end() override {}

  bool gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;
  void on_service_discovery_done(int error);
  void on_write_result(uint16_t handle, int error);
  void on_notify_state(uint16_t handle, bool enabled, int error);
  void on_notify_data(uint16_t handle, const uint8_t *data, uint16_t len);

  // Advertisements arrive on the tracker's loop while this component may be
  // disabled, so the pending device is parked here and picked up in loop().
  void enqueue_device(const esphome::esp32_ble_tracker::ESPBTDevice &device);
  void clear_pending_device();

  void set_address(uint64_t address) {
    this->connect_address_ = address;
    this->address_configured_ = true;
    esphome::esp32_ble_client::BLEClientBase::set_address(address);
  }
  void set_connect_address(uint64_t address) { this->connect_address_ = address; }
  uint64_t get_connect_address() const { return this->connect_address_; }
  void set_active(bool active) { this->active_ = active; }
  void set_address_type(uint8_t address_type) { this->set_remote_addr_type(static_cast<esp_ble_addr_type_t>(address_type)); }
  void set_pairing(FermobPairingMode mode) { this->pairing_mode_ = static_cast<pair_mode_t>(mode); }
  void set_retry_interval(uint32_t interval) { this->retry_interval_ = interval; }
  void set_led_mode(uint8_t led_mode) { this->led_mode_ = led_mode; }

  // True when the light itself last reported exactly this state, which means a
  // write asking for it is the hub's own report echoing back, not a request.
  bool matches_reported_state(bool on) const {
    return this->has_state_ && this->reported_on_ == on && this->reported_level_ == this->level_;
  }

  bool is_active() const { return this->active_; }
  bool is_connected() const { return this->connected_; }
  bool is_pairing() const { return pair_state() == PAIR_RUNNING; }
  bool is_paired() const { return this->paired_; }

  // pair.h is shared with the standalone firmware and cannot know about
  // preferences; these are the seam it calls into.
  void load_secrets(pair_secrets_t *out);
  void save_secrets(const pair_secrets_t *in);
  void erase_secrets();
  void load_module_info();
  void save_module_info();

  void start_pairing();
  void stop_pairing();
  void forget();

  void set_state(bool on, bool publish = true);
  void toggle();
  void set_level(uint8_t level);
  uint8_t get_level() const { return this->level_; }
  uint8_t get_led_mode() const { return this->led_mode_; }
  void set_led_mode_from_user(uint8_t led_mode);

  // Brightness as a 0-255 ramp, mapped onto the light's own 0-100 scale.
  void set_brightness(uint8_t brightness);
  uint8_t get_brightness() const { return this->brightness_; }
  void publish_state(bool optimistic);

  // The light platform reports the entity's state here; the hub decides when the
  // change is worth another DEVICE_DATA_SET.
  using StateListener = void (*)(void *ctx, bool on, uint8_t brightness);
  void add_state_listener(StateListener listener, void *ctx) {
    this->state_listener_ = listener;
    this->state_listener_ctx_ = ctx;
  }

  // False while nothing is stored, so an encrypted command is never sent into
  // a light that will answer only with a CRC error.
  bool has_secrets_() const;
  std::string connect_address_str() const;
  std::string unique_id_prefix() const;

 protected:
  void set_hub_state(FermobDeviceState state);
  void send_control(const uint8_t *payload, size_t len);
  bool write_frame(const uint8_t *data, size_t len);
  void ensure_connected_();
  void start_connect_();
  void subscribe_notifications_();
  void send_device_data_get_();
  void reset_link_();

  // pair.h transport, bound to this component.
  static bool io_write_(void *ctx, const uint8_t *data, size_t len);
  static uint8_t io_next_seq_(void *ctx);
  static bool io_is_ready_(void *ctx);
  static uint32_t io_now_ms_(void *ctx);
  static void io_defer_(void *ctx, uint32_t delay_ms, void (*fn)(void *), void *ctx_arg);
  static void io_load_(void *ctx, pair_secrets_t *out);
  static void io_save_(void *ctx, const pair_secrets_t *in);
  static void io_erase_(void *ctx);
  static void io_save_module_(void *ctx);

  // Latest DEVICE_DATA record, and whether anything has arrived yet.
  bool has_state_{false};
  uint32_t last_timestamp_{0};
  uint8_t level_{0};
  uint8_t brightness_{0};
  uint8_t led_mode_{0};
  uint8_t cold_white_{0};
  uint8_t warm_white_{0};
  bool on_{false};
  // What the light was last told, so a repeated request is not repeated on the
  // wire. Cleared whenever the link drops or a pairing run replaces the keys.
  bool sent_state_{false};
  bool sent_on_{false};
  uint8_t sent_level_{0};
  // What the light itself pushed, as opposed to what was asked for. Only the
  // DEVICE_DATA record updates these.
  bool reported_on_{false};
  uint8_t reported_level_{0};
  StateListener state_listener_{nullptr};
  void *state_listener_ctx_{nullptr};
  bool connected_{false};
  bool device_seen_{false};
  bool paired_{false};
  bool restored_pairing_complete_{false};
  bool active_{false};
  bool discovered_{false};
  bool notifying_{false};
  bool pending_subscribe_{false};
  bool found_logged_{false};
  uint32_t connected_ms_{0};
  uint32_t last_poll_ms_{0};
  uint32_t last_pair_attempt_ms_{0};
  uint32_t last_attempt_ms_{0};
  bool pair_attempted_{false};
  uint32_t retry_interval_{15000};
  uint16_t char_handle_{0};
  uint16_t cccd_handle_{0};
  uint8_t seq_id_{0};
  FermobDeviceState state_{FERMOB_STATE_IDLE};
  pair_mode_t pairing_mode_{PAIR_MODE_SHARE};
  uint64_t connect_address_{0};
  // Packed uint64 the way ESPHome's MACAddress parser hands it over: AA:BB:CC:DD:EE:FF
  // is 0xAABBCCDDEEFF, and address_uint64() packs an advertisement's first byte
  // into the same end, so both paths agree.
  bool address_configured_{false};

  ESPPreferenceObject pref_;
  ESPPreferenceObject module_pref_;
  ESPPreferenceObject device_pref_;

  struct {
    bool pending{false};
    uint64_t address{0};
    uint8_t address_type{0};
    int rssi{0};
  } pending_device_;
};

}  // namespace fermob
}  // namespace esphome
