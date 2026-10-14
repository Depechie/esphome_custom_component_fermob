#include "fermob.h"

#include "esphome/core/log.h"

#include <cinttypes>
#include <cstdarg>

namespace esphome {
namespace fermob {

static const char *const TAG = "fermob";
static const uint32_t FERMOB_PREF_KEY = 0xFEEB0001;
static const uint32_t FERMOB_MODULE_PREF_KEY = 0xFEEB0002;
static const uint32_t FERMOB_DEVICE_PREF_KEY = 0xFEEB0003;

static ble_device_base::ESPBTUUID fermob_service_uuid() {
  return ble_device_base::ESPBTUUID::from_raw("41C15000-6DEF-11E5-BCDE-0002A5D5C51B");
}

static ble_device_base::ESPBTUUID fermob_characteristic_uuid() {
  return ble_device_base::ESPBTUUID::from_uint16(FERMOB_CHARACTERISTIC_UUID16);
}

static ble_device_base::ESPBTUUID cccd_uuid() { return ble_device_base::ESPBTUUID::from_uint16(0x2902); }

extern "C" void fermob_log(int level, const char *tag, int line, const char *format, ...) {
  va_list args;
  va_start(args, format);
  esphome::esp_log_vprintf_(level, tag, line, format, args);
  va_end(args);
}

static bool uuid_has_word(const ble_device_base::ESPBTUUID &uuid, uint16_t value) {
  uint8_t hi = static_cast<uint8_t>(value >> 8);
  uint8_t lo = static_cast<uint8_t>(value & 0xff);
  return uuid == ble_device_base::ESPBTUUID::from_uint16(value) || uuid.contains(hi, lo) || uuid.contains(lo, hi);
}

// ---------------------------------------------------------------- pair io --

bool FermobHub::io_write_(void *ctx, const uint8_t *data, size_t len) {
  auto *self = static_cast<FermobHub *>(ctx);
  return self->write_frame(data, len);
}

uint8_t FermobHub::io_next_seq_(void *ctx) {
  auto *self = static_cast<FermobHub *>(ctx);
  return self->seq_id_++;
}

bool FermobHub::io_is_ready_(void *ctx) {
  auto *self = static_cast<FermobHub *>(ctx);
  return self->connected_ && self->discovered_ && self->char_handle_ != 0;
}

uint32_t FermobHub::io_now_ms_(void *ctx) {
  return esphome::millis();
}

void FermobHub::io_defer_(void *ctx, uint32_t delay_ms, void (*fn)(void *), void *ctx_arg) {
  // pair.c defers the next chunk of a long payload. Routing that through the hub
  // keeps a single scheduler and a single writer: a write is only accepted once
  // the previous completion came back, so overlapping sends cannot interleave.
  auto *self = static_cast<FermobHub *>(ctx);
  self->set_timeout("fermob_pair_chunk", delay_ms, [self, fn, ctx_arg]() { fn(ctx_arg); });
}

void FermobHub::io_load_(void *ctx, pair_secrets_t *out) {
  static_cast<FermobHub *>(ctx)->load_secrets(out);
}

void FermobHub::io_save_(void *ctx, const pair_secrets_t *in) {
  static_cast<FermobHub *>(ctx)->save_secrets(in);
}

void FermobHub::io_erase_(void *ctx) {
  static_cast<FermobHub *>(ctx)->erase_secrets();
}

void FermobHub::io_save_module_(void *ctx) { static_cast<FermobHub *>(ctx)->save_module_info(); }

// ------------------------------------------------------------------ setup --

void FermobHub::setup() {
  esp32_ble_client::BLEClientBase::setup();
  this->pref_ = global_preferences->make_preference<FermobSecretBlob>(FERMOB_PREF_KEY);
  this->module_pref_ = global_preferences->make_preference<FermobModuleBlob>(FERMOB_MODULE_PREF_KEY);
  this->device_pref_ = global_preferences->make_preference<FermobDeviceBlob>(FERMOB_DEVICE_PREF_KEY);
  this->load_module_info();

  pair_io_t io{};
  io.ctx = this;
  io.write = FermobHub::io_write_;
  io.next_seq = FermobHub::io_next_seq_;
  io.is_ready = FermobHub::io_is_ready_;
  io.now_ms = FermobHub::io_now_ms_;
  io.defer = FermobHub::io_defer_;
  io.load_secrets = FermobHub::io_load_;
  io.save_secrets = FermobHub::io_save_;
  io.erase_secrets = FermobHub::io_erase_;
  io.save_module_info = FermobHub::io_save_module_;
  pair_set_io(&io);

  // Merely loading the secrets does not mean they belong to *this* light: they
  // are the installation keys, shared across every light on the account. So
  // readiness is proven by the light accepting an encrypted command, and
  // pairing fills any gap when it does not.
  bool have_secrets = pair_init();
  this->paired_ = have_secrets && this->restored_pairing_complete_;
  if (this->paired_) {
    ESP_LOGI(TAG, "installation secrets loaded, probing the light to confirm them");
  } else if (have_secrets) {
    ESP_LOGW(TAG, "incomplete or legacy pairing keys loaded; resuming pairing instead of sending encrypted polls");
  } else {
    ESP_LOGI(TAG, "no installation secrets stored yet, the light will need pairing");
  }

  this->set_hub_state(FERMOB_STATE_IDLE);
}

void FermobHub::dump_config() {
  ESP_LOGCONFIG(TAG, "Fermob:");
  ESP_LOGCONFIG(TAG, "  Address: %s", this->address_configured_ ? "configured" : "first advertisement");
  ESP_LOGCONFIG(TAG, "  Pairing mode: %s", this->pairing_mode_ == PAIR_MODE_SHARE ? "share" : "adopt");
  ESP_LOGCONFIG(TAG, "  Retry interval: %" PRIu32 "s", this->retry_interval_ / 1000);
  ESP_LOGCONFIG(TAG, "  Secrets: %s", this->paired_ ? "paired" : this->has_secrets_() ? "incomplete" : "absent");
  ESP_LOGCONFIG(TAG, "  State: %s", this->connected_ ? "connected" : "disconnected");
}

void FermobHub::loop() {
  esp32_ble_client::BLEClientBase::loop();
  // pairing.c's ACK deadline is a free-running timer, not a component state
  // machine, so it has to be fed from the loop.
  pair_tick();

  if (!this->active_) {
    return;
  }

  if (this->pending_device_.pending) {
    this->pending_device_.pending = false;
    // A light that advertises again while connected is just noise; the address
    // is only consumed while idle.
    if (!this->connected_) {
      bool learned_new_address = !this->address_configured_ || this->connect_address_ != this->pending_device_.address;
      this->connect_address_ = this->pending_device_.address;
      this->set_remote_addr_type(static_cast<esp_ble_addr_type_t>(this->pending_device_.address_type));
      this->address_configured_ = true;
      if (!this->found_logged_) {
        ESP_LOGI(TAG, "found light %s (rssi %d)", this->connect_address_str().c_str(),
                 this->pending_device_.rssi);
        this->found_logged_ = true;
      }
      if (learned_new_address) {
        this->last_attempt_ms_ = 0;
      }
    }
  }

  if (this->connected_) {
    // Wait a beat after the link comes up before the first command. The light
    // answers the cleartext state query before it will accept anything
    // encrypted, so an immediate write loses the answer.
    if (esphome::millis() - this->connected_ms_ < CONNECT_SETTLE_MS) {
      return;
    }

    // Pairing ACKs arrive as notifications on the same characteristic, so the
    // subscription must be active before the first REGISTER(0) is sent.
    if (!this->notifying_ && !this->is_pairing()) {
      this->subscribe_notifications_();
      return;
    }

    // A light we have never paired with stays silent on encrypted traffic.
    // Pair once, then keep it: re-pairing a live link would drop the light off
    // the account every reconnect.
    if (!this->paired_ && !this->is_pairing()) {
      if (!this->pair_attempted_ || esphome::millis() - this->last_pair_attempt_ms_ >= this->retry_interval_) {
        ESP_LOGW(TAG, "no confirmed pairing for this light, starting pairing");
        this->start_pairing();
      }
      return;
    }

    // Recover the state after a reconnect, and as a floor under the light's own
    // notifications.
    if (!this->is_pairing() && esphome::millis() - this->last_poll_ms_ > POLL_INTERVAL_S * 1000) {
      this->send_device_data_get_();
    }
    return;
  }

  // Connection attempts are driven by ESP32BLETracker promoting this client
  // after parse_device() marks the matching advertisement as DISCOVERED.
}

void FermobHub::ensure_connected_() {
  if (this->state_ == FERMOB_STATE_CONNECTING) {
    return;
  }
  if (!this->address_configured_) {
    return;
  }
  if (esphome::millis() - this->last_attempt_ms_ < this->retry_interval_) {
    return;
  }
  this->start_connect_();
}

void FermobHub::start_connect_() {
  this->last_attempt_ms_ = esphome::millis();
  this->discovered_ = false;
  this->notifying_ = false;
  this->char_handle_ = 0;
  this->cccd_handle_ = 0;
  this->set_hub_state(FERMOB_STATE_CONNECTING);

  ESP_LOGI(TAG, "connecting to %s", this->connect_address_str().c_str());
  esp32_ble_client::BLEClientBase::set_state(esp32_ble_tracker::ClientState::DISCOVERED);
}

void FermobHub::set_hub_state(FermobDeviceState state) {
  this->state_ = state;
  this->publish_state(false);
}

// --------------------------------------------------------------- scanning --

bool FermobHub::parse_device(const esphome::esp32_ble_tracker::ESPBTDevice &device) {
  auto service_uuids = device.get_service_uuids();
  // Only Fermob's own service is of interest. It is the useful discriminator
  // even after a light has already been paired.
  bool match = false;
  if (this->address_configured_) {
    match = device.address_uint64() == this->connect_address_;
  }
  if (!match) {
    for (auto &uuid : service_uuids) {
      if (uuid == fermob_service_uuid() || uuid_has_word(uuid, FERMOB_SERVICE_UUID16)) {
        match = true;
        break;
      }
    }
  }
  if (!match) {
    return false;
  }
  this->enqueue_device(device);
  if (!this->active_ || this->state() != esp32_ble_tracker::ClientState::IDLE) {
    return false;
  }
  this->set_remote_addr_type(device.get_address_type());
  esp32_ble_client::BLEClientBase::set_state(esp32_ble_tracker::ClientState::DISCOVERED);
  return true;
}

void FermobHub::enqueue_device(const esphome::esp32_ble_tracker::ESPBTDevice &device) {
  this->pending_device_.pending = true;
  this->pending_device_.address = device.address_uint64();
  this->pending_device_.rssi = device.get_rssi();
}

void FermobHub::clear_pending_device() {
  this->pending_device_.pending = false;
}

std::string FermobHub::connect_address_str() const {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           static_cast<uint8_t>(this->connect_address_ >> 40),
           static_cast<uint8_t>(this->connect_address_ >> 32),
           static_cast<uint8_t>(this->connect_address_ >> 24),
           static_cast<uint8_t>(this->connect_address_ >> 16),
           static_cast<uint8_t>(this->connect_address_ >> 8),
           static_cast<uint8_t>(this->connect_address_));
  return std::string(buf);
}

// ------------------------------------------------------------- connection --

bool FermobHub::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                    esp_ble_gattc_cb_param_t *param) {
  bool handled = esp32_ble_client::BLEClientBase::gattc_event_handler(event, gattc_if, param);
  if (!handled) {
    return false;
  }

  switch (event) {
    case ESP_GATTC_SEARCH_CMPL_EVT:
      if (param->search_cmpl.conn_id == this->get_conn_id()) {
        this->on_service_discovery_done(param->search_cmpl.status);
      }
      break;
    case ESP_GATTC_CLOSE_EVT:
      ESP_LOGI(TAG, "disconnected");
      this->reset_link_();
      break;
    case ESP_GATTC_WRITE_CHAR_EVT:
      if (param->write.conn_id == this->get_conn_id()) {
        this->on_write_result(param->write.handle, param->write.status);
      }
      break;
    case ESP_GATTC_WRITE_DESCR_EVT:
      if (param->write.conn_id == this->get_conn_id()) {
        this->on_write_result(param->write.handle, param->write.status);
      }
      break;
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
      this->on_notify_state(param->reg_for_notify.handle, param->reg_for_notify.status == ESP_GATT_OK,
                            param->reg_for_notify.status);
      break;
    case ESP_GATTC_NOTIFY_EVT:
      if (param->notify.conn_id == this->get_conn_id()) {
        this->on_notify_data(param->notify.handle, param->notify.value, param->notify.value_len);
      }
      break;
    default:
      break;
  }

  return true;
}

void FermobHub::reset_link_() {
  this->connected_ = false;
  this->discovered_ = false;
  this->notifying_ = false;
  this->char_handle_ = 0;
  this->cccd_handle_ = 0;
  this->has_state_ = false;
  this->last_timestamp_ = 0;
  // What the light was last told is only true for as long as the link is.
  this->sent_state_ = false;
  this->cancel_timeout("fermob_pair_chunk");
  this->release_services();
  // A link that dropped mid-pairing leaves the light half-configured: it holds
  // our keys but never saw the final REGISTER. Pairing is idempotent enough to
  // rerun, so the next attempt does exactly that rather than assuming success.
  pair_stop();
  this->set_hub_state(FERMOB_STATE_IDLE);
}

void FermobHub::on_service_discovery_done(int error) {
  if (error != 0) {
    ESP_LOGW(TAG, "service discovery failed: %d", error);
    this->reset_link_();
    return;
  }

  this->connected_ = true;
  this->connected_ms_ = esphome::millis();
  ESP_LOGI(TAG, "connected (mtu %u)", this->mtu_);
  if (this->mtu_ < FERMOB_MTU) {
    ESP_LOGE(TAG, "negotiated mtu %u is below the %u this protocol needs", this->mtu_, FERMOB_MTU);
    this->disconnect();
    this->reset_link_();
    return;
  }

  ESP_LOGI(TAG, "GATT table: services=%u", static_cast<unsigned>(this->services_.size()));
  for (auto *service : this->services_) {
    char service_uuid[ble_device_base::UUID_STR_LEN];
    service->parse_characteristics();
    ESP_LOGI(TAG, "GATT service %s handle=%u..%u chars=%u", service->uuid.to_str(service_uuid), service->start_handle,
             service->end_handle, static_cast<unsigned>(service->characteristics.size()));
    for (auto *ch : service->characteristics) {
      char char_uuid[ble_device_base::UUID_STR_LEN];
      ch->parse_descriptors();
      ESP_LOGI(TAG, "  characteristic %s handle=%u props=0x%02x desc=%u", ch->uuid.to_str(char_uuid), ch->handle,
               ch->properties, static_cast<unsigned>(ch->descriptors.size()));
      for (auto *desc : ch->descriptors) {
        char desc_uuid[ble_device_base::UUID_STR_LEN];
        ESP_LOGI(TAG, "    descriptor %s handle=%u", desc->uuid.to_str(desc_uuid), desc->handle);
      }
    }

    if (service->uuid != fermob_service_uuid() && !uuid_has_word(service->uuid, FERMOB_SERVICE_UUID16)) {
      continue;
    }
    for (auto *ch : service->characteristics) {
      if (ch->uuid != fermob_characteristic_uuid() && !uuid_has_word(ch->uuid, FERMOB_CHARACTERISTIC_UUID16)) {
        continue;
      }
      this->char_handle_ = ch->handle;
      for (auto *desc : ch->descriptors) {
        if (desc->uuid == cccd_uuid() || uuid_has_word(desc->uuid, 0x2902)) {
          this->cccd_handle_ = desc->handle;
        }
      }
      break;
    }
  }

  if (this->char_handle_ == 0) {
    ESP_LOGE(TAG, "service %04X found but not characteristic %04X", FERMOB_SERVICE_UUID16,
             FERMOB_CHARACTERISTIC_UUID16);
    this->disconnect();
    this->reset_link_();
    return;
  }

  this->discovered_ = true;
  ESP_LOGI(TAG, "found characteristic %04X (handle %u)%s", FERMOB_CHARACTERISTIC_UUID16,
           this->char_handle_, this->cccd_handle_ == 0 ? ", no CCCD: state updates only" : "");
  this->set_hub_state(FERMOB_STATE_CONNECTED);
}

void FermobHub::subscribe_notifications_() {
  if (this->pending_subscribe_ || this->notifying_) {
    return;
  }
  if (this->cccd_handle_ == 0) {
    // Without a CCCD the light still answers a state query, so control works;
    // only the push updates are lost. Polling covers that.
    ESP_LOGW(TAG, "no CCCD for %04X, falling back to polling", FERMOB_CHARACTERISTIC_UUID16);
    this->send_device_data_get_();
    return;
  }
  uint8_t cccd[2] = {0x01, 0x00};
  int err = this->register_for_notify(this->char_handle_);
  if (err != 0) {
    ESP_LOGW(TAG, "notification registration refused: %d", err);
    return;
  }
  this->pending_subscribe_ = true;
}

void FermobHub::on_notify_state(uint16_t handle, bool enabled, int error) {
  if (handle != this->char_handle_ || !this->pending_subscribe_) {
    return;
  }
  if (error != 0 || !enabled) {
    this->pending_subscribe_ = false;
    ESP_LOGW(TAG, "notification registration failed: %d", error);
    return;
  }
  ESP_LOGI(TAG, "notification registration accepted for handle %u", handle);
}

void FermobHub::on_write_result(uint16_t handle, int error) {
  if (error != 0) {
    ESP_LOGW(TAG, "write to handle %u failed: %d", handle, error);
    if (handle == this->char_handle_ && this->is_pairing()) {
      ESP_LOGW(TAG, "pairing write failed, aborting");
      pair_stop();
    }
    return;
  }
  if (handle == this->char_handle_) {
    ESP_LOGD(TAG, "characteristic write accepted on handle %u", handle);
  }
  if (handle == this->cccd_handle_ && this->pending_subscribe_) {
    this->pending_subscribe_ = false;
    this->notifying_ = true;
    ESP_LOGI(TAG, "subscribed to state notifications");
    this->send_device_data_get_();
  }
}

// ---------------------------------------------------------------- inbound --

void FermobHub::on_notify_data(uint16_t handle, const uint8_t *data, uint16_t len) {
  if (handle != this->char_handle_) {
    ESP_LOGW(TAG, "notification on unexpected handle %u (want %u), %u bytes", handle, this->char_handle_, len);
    lmp_dump("rx", data, len);
    return;
  }
  lmp_dump("rx", data, len);

  // Pairing owns every ACK, and it is handed the raw frame so it can pick the
  // key out of the header itself.
  if (pair_handle_frame(data, len)) {
    if (pair_state() == PAIR_DONE) {
      this->paired_ = true;
      // A fresh pairing may have installed new keys, so nothing the light was
      // told before is still true.
      this->sent_state_ = false;
      this->set_hub_state(FERMOB_STATE_CONNECTED);
      this->send_device_data_get_();
    } else if (pair_state() == PAIR_FAILED) {
      this->set_hub_state(FERMOB_STATE_ERROR);
    }
    return;
  }

  // Everything else carries a DEVICE_DATA record, either in a pushed status or
  // event frame or in the ACK to the state query.
  lmp_rx_t rx;
  uint8_t frame = 0;
  uint8_t enc = 0;
  uint8_t type = 0;
  uint8_t seq = 0;
  const uint8_t *nonce = nullptr;
  const uint8_t *key = nullptr;
  if (!lmp_frame_header(data, len, &frame, &enc, &type, &seq)) {
    return;
  }
  key = pair_key_for(enc, &nonce);
  if (!lmp_decode_short(data, len, key, nonce, &rx)) {
    ESP_LOGV(TAG, "frame did not decode (enc %u, key %s)", enc, key == nullptr ? "none" : "known");
    return;
  }
  if (!rx.crc_ok) {
    ESP_LOGW(TAG, "inbound frame failed its checksum (enc %u, key %s)", enc,
             key == nullptr ? "none" : "known");
    return;
  }
  // The light answers a DEVICE_DATA_GET with a plain CMD_ACK whose payload
  // carries the same record it pushes as STATUS/EVENT, and the app reads
  // offsets 7/8/9 of both the same way. Pairing has already declined the frame
  // by this point, so anything here is the hub's own.
  if (rx.message_type != LMP_MSG_STATUS && rx.message_type != LMP_MSG_EVENT &&
      rx.message_type != LMP_MSG_ACK) {
    return;
  }

  lmp_state_t st;
  if (!lmp_parse_device_state(rx.payload, rx.payload_len, FERMOB_DEVICE_INDEX, &st)) {
    if (rx.message_type == LMP_MSG_ACK) {
      // An ACK to one of our own commands. Pairing declined it already, so this
      // is ours: the light is reporting what it made of it.
      uint8_t status = rx.payload_len > 2 ? rx.payload[2] : 0xFF;
      ESP_LOGI(TAG, "command ACK seq=%u status=%u", rx.seq_id, status);
    }
    ESP_LOGD(TAG, "frame (msgtype %u, enc %u) carried no usable device record", rx.message_type, enc);
    return;
  }

  // The app ignores records older than the last one it applied, which keeps a
  // backlog from replaying stale state after a reconnect.
  if (this->last_timestamp_ != 0 && st.timestamp < this->last_timestamp_) {
    ESP_LOGV(TAG, "ignoring an older record (%u < %u)", st.timestamp, this->last_timestamp_);
    return;
  }
  this->last_timestamp_ = st.timestamp;

  this->has_state_ = true;
  this->on_ = st.is_on != 0;
  this->level_ = st.level;
  this->led_mode_ = st.led_mode;
  this->reported_on_ = this->on_;
  this->reported_level_ = st.level;
  if (pair_module_info()->have_device_type && pair_module_info()->device_type == 404 && rx.payload_len > 10) {
    this->cold_white_ = rx.payload[9];
    this->warm_white_ = rx.payload[10];
    this->level_ = this->cold_white_ > this->warm_white_ ? this->cold_white_ : this->warm_white_;
    this->reported_level_ = this->level_;
  }
  // 0-100 on the light, 0-255 here.
  this->brightness_ = static_cast<uint8_t>((this->level_ * 255) / 100);
  ESP_LOGD(TAG, "light reported on=%s level=%u led_mode=%u", YESNO(this->on_), this->level_,
           this->led_mode_);
  this->publish_state(false);
}

// ---------------------------------------------------------------- outbound --

bool FermobHub::write_frame(const uint8_t *data, size_t len) {
  if (!this->connected_ || this->char_handle_ == 0) {
    ESP_LOGW(TAG, "write skipped, not connected");
    return false;
  }
  lmp_dump("tx", data, len);
  ESP_LOGI(TAG, "tx frame len=%u handle=%u", static_cast<unsigned>(len), this->char_handle_);
  int err = esp_ble_gattc_write_char(this->get_gattc_if(), this->get_conn_id(), this->char_handle_, len,
                                     const_cast<uint8_t *>(data), ESP_GATT_WRITE_TYPE_RSP,
                                     ESP_GATT_AUTH_REQ_NONE);
  if (err != 0) {
    ESP_LOGW(TAG, "write refused by the stack: %d", err);
    return false;
  }
  return true;
}

void FermobHub::send_device_data_get_() {
  uint8_t payload[LMP_PAYLOAD_LEN];
  this->last_poll_ms_ = esphome::millis();

  if (this->is_pairing()) {
    // Pairing sends nothing but its own chain; a query in the middle of it
    // would eat the sequence id the ACK matcher is waiting on.
    return;
  }
  if (!this->paired_ || !this->has_secrets_()) {
    if (!this->pair_attempted_ || esphome::millis() - this->last_pair_attempt_ms_ >= this->retry_interval_) {
      this->start_pairing();
    }
    return;
  }

  size_t len = lmp_device_data_get_payload(FERMOB_DEVICE_INDEX, payload);
  lmp_msg_t msg;
  lmp_msg_init(&msg, payload, len);
  /* The app asks for state with CMD_WITH_ACK, and the light only answers a
   * command that expects one. A no-ack frame is simply ignored. */
  msg.message_type = LMP_MSG_CMD_ACK;
  msg.address_type = LMP_ADDR_SHORT;
  msg.connection_type = LMP_CONX_MESH;
  msg.encryption = pair_encryption_mode();
  msg.seq_id = this->seq_id_++;
  const pair_module_info_t *info = pair_module_info();
  if (info->have_short_address) {
    msg.mesh_addr[0] = (uint8_t)(info->short_address & 0xFF);
    msg.mesh_addr[1] = (uint8_t)(info->short_address >> 8);
    msg.has_mesh_addr = true;
  }
  ESP_LOGD(TAG, "state query to module %04x (api version %u)", info->short_address, info->api_version);

  const uint8_t *nonce = nullptr;
  const uint8_t *key = pair_key_for(msg.encryption, &nonce);
  uint8_t frame[LMP_LONG_FRAME_LEN];
  size_t n = lmp_encode_short(&msg, key, nonce, frame, sizeof(frame));
  if (n == 0) {
    ESP_LOGW(TAG, "could not encode the state query");
    return;
  }
  this->write_frame(frame, n);
}

// ---------------------------------------------------------------- controls --

void FermobHub::set_state(bool on, bool publish) {
  if (this->connected_) {
    // The light takes one DEVICE_DATA_SET per change. ESPHome calls write_state
    // again on every step of a transition, so without this a single tap in Home
    // Assistant becomes hundreds of writes the light has no way to keep up with.
    if (this->sent_state_ && this->sent_on_ == on && this->sent_level_ == this->level_) {
      this->on_ = on;
      if (publish) {
        this->publish_state(true);
      }
      return;
    }

    // Below API_V2 the LED mode rides in a seventh payload byte instead of the
    // top nibble of the flags byte, so the layout depends on what MODULE_INFO_GET
    // reported. Assume V2 until a pairing run has said otherwise.
    const pair_module_info_t *info = pair_module_info();
    uint8_t api_version = info->have_api_version ? info->api_version : LMP_API_V2;
    uint8_t payload[LMP_PAYLOAD_LEN];
    size_t len;
    if (info->have_device_type && info->device_type == 404) {
      uint8_t cold = this->level_;
      uint8_t warm = this->level_;
      uint8_t max_channel = this->cold_white_ > this->warm_white_ ? this->cold_white_ : this->warm_white_;
      if (max_channel != 0) {
        cold = (uint16_t(this->level_) * this->cold_white_) / max_channel;
        warm = (uint16_t(this->level_) * this->warm_white_) / max_channel;
      }
      len = lmp_tunable_white_payload(on, cold, warm, FERMOB_DEVICE_INDEX, this->led_mode_,
                                     api_version, LMP_DEFAULT_TRANSITION, payload);
    } else {
      len = lmp_device_data_payload(on, this->level_, FERMOB_DEVICE_INDEX, this->led_mode_,
                                    api_version, LMP_DEFAULT_TRANSITION, payload);
    }
    this->send_control(payload, len);
    this->sent_state_ = true;
    this->sent_on_ = on;
    this->sent_level_ = this->level_;
    // The light confirms with a DEVICE_DATA record, so the authoritative state
    // comes back on its own. Until it does, show what was asked for.
    this->on_ = on;
    if (publish) {
      this->publish_state(true);
    }
    return;
  }
  // Not connected: remember the intent so it lands once the link is back.
  this->on_ = on;
  if (publish) {
    this->publish_state(true);
  }
}

void FermobHub::send_control(const uint8_t *payload, size_t len) {
  if (!this->paired_ || !this->has_secrets_()) {
    ESP_LOGW(TAG, "refusing to send an encrypted command without stored secrets");
    return;
  }
  lmp_msg_t msg;
  lmp_msg_init(&msg, payload, len);
  msg.message_type = LMP_MSG_CMD_NO_ACK;
  msg.address_type = LMP_ADDR_SHORT;
  msg.connection_type = LMP_CONX_MESH;
  msg.encryption = pair_encryption_mode();
  msg.seq_id = this->seq_id_++;

  const pair_module_info_t *info = pair_module_info();
  if (info->have_short_address) {
    msg.mesh_addr[0] = (uint8_t)(info->short_address & 0xFF);
    msg.mesh_addr[1] = (uint8_t)(info->short_address >> 8);
    msg.has_mesh_addr = true;
  }

  const uint8_t *nonce = nullptr;
  const uint8_t *key = pair_key_for(msg.encryption, &nonce);
  uint8_t frame[LMP_LONG_FRAME_LEN];
  size_t n = msg.payload_len > LMP_PAYLOAD_LEN ? 0 : lmp_encode_short(&msg, key, nonce, frame, sizeof(frame));
  if (n == 0) {
    ESP_LOGW(TAG, "could not encode the command");
    return;
  }
  this->write_frame(frame, n);
}

void FermobHub::toggle() {
  this->set_state(!this->on_);
}

void FermobHub::set_level(uint8_t level) {
  this->level_ = level;
  this->set_state(this->on_, false);
}

void FermobHub::set_brightness(uint8_t brightness) {
  this->brightness_ = brightness;
  this->level_ = static_cast<uint8_t>((brightness * 100) / 255);
}

void FermobHub::set_led_mode_from_user(uint8_t led_mode) {
  this->led_mode_ = led_mode;
  this->set_state(this->on_, false);
}

// ---------------------------------------------------------------- pairing --

bool FermobHub::has_secrets_() const { return pair_secrets_known(); }

void FermobHub::start_pairing() {
  if (this->is_pairing()) {
    ESP_LOGW(TAG, "pairing already running");
    return;
  }
  if (!this->connected_) {
    ESP_LOGW(TAG, "cannot pair while disconnected");
    return;
  }
  ESP_LOGI(TAG, "starting pairing in %s mode", this->pairing_mode_ == PAIR_MODE_SHARE ? "share"
                                                                                      : "adopt");
  ESP_LOGI(TAG, "pair preflight connected=%s discovered=%s notifying=%s char=%u state=%s", YESNO(this->connected_),
           YESNO(this->discovered_), YESNO(this->notifying_), this->char_handle_, pair_state_name());
  this->pair_attempted_ = true;
  this->last_pair_attempt_ms_ = esphome::millis();
  this->set_hub_state(FERMOB_STATE_PAIRING);
  bool started = pair_start(this->pairing_mode_);
  ESP_LOGI(TAG, "pair_start returned %s, state=%s", YESNO(started), pair_state_name());
  if (!started) {
    ESP_LOGW(TAG, "pairing did not start");
    this->set_hub_state(FERMOB_STATE_ERROR);
  }
}

void FermobHub::stop_pairing() { pair_stop(); }

void FermobHub::forget() {
  if (this->is_pairing()) {
    ESP_LOGW(TAG, "stopping active pairing to forget installation keys");
    pair_stop();
    this->cancel_timeout("fermob_pair_chunk");
  }
  if (pair_forget()) {
    this->paired_ = false;
    // Leave a window to inspect the erased preference before automatically
    // pairing again (SHARE will save a freshly generated nonce/private key).
    this->pair_attempted_ = true;
    this->last_pair_attempt_ms_ = esphome::millis();
    ESP_LOGW(TAG, "forgot the installation secrets; checking persisted preference");
    this->publish_state(false);
  } else {
    ESP_LOGW(TAG, "could not forget keys while pairing is running");
  }
}

// ------------------------------------------------------------ preferences --

void FermobHub::load_secrets(pair_secrets_t *out) {
  *out = {};
  this->restored_pairing_complete_ = false;
  FermobSecretBlob blob{};
  if (!this->pref_.load(&blob)) {
    ESP_LOGW(TAG, "stored secret blob is unreadable");
    return;
  }
  if (memcmp(blob.magic, "FMPB", 4) != 0) {
    ESP_LOGW(TAG, "stored secret blob has the wrong magic");
    return;
  }
  memcpy(out->pub, blob.pub, PAIR_KEY_LEN);
  memcpy(out->priv, blob.priv, PAIR_KEY_LEN);
  memcpy(out->nonce, blob.nonce, PAIR_KEY_LEN);
  out->have_pub = blob.flags & 0x04;
  out->have_priv = blob.flags & 0x02;
  out->have_nonce = blob.flags & 0x01;
  this->restored_pairing_complete_ = (blob.flags & 0x08) != 0;
}

void FermobHub::save_secrets(const pair_secrets_t *in) {
  FermobSecretBlob blob{};
  memcpy(blob.magic, "FMPB", 4);
  // SHARE mode saves generated keys before REGISTER(0) receives an ACK. They
  // are useful for retrying the same installation, but are not proof of pairing.
  blob.flags = (in->have_nonce ? 0x01 : 0) | (in->have_priv ? 0x02 : 0) | (in->have_pub ? 0x04 : 0) |
               (pair_state() == PAIR_DONE ? 0x08 : 0);
  memcpy(blob.pub, in->pub, PAIR_KEY_LEN);
  memcpy(blob.priv, in->priv, PAIR_KEY_LEN);
  memcpy(blob.nonce, in->nonce, PAIR_KEY_LEN);
  if (!this->pref_.save(&blob)) {
    ESP_LOGW(TAG, "storing the secrets failed");
  }
  global_preferences->sync();
}

void FermobHub::erase_secrets() {
  FermobSecretBlob blob{};
  bool saved = this->pref_.save(&blob);
  global_preferences->sync();
  FermobSecretBlob readback{};
  bool cleared = this->pref_.load(&readback) && memcmp(&readback, &blob, sizeof(blob)) == 0;
  ESP_LOGI(TAG, "forget preference write=%s readback=%s", YESNO(saved), YESNO(cleared));
}

void FermobHub::load_module_info() {
  FermobModuleBlob blob{};
  if (this->module_pref_.load(&blob) && memcmp(blob.magic, "FMMI", 4) == 0) {
    pair_set_module_info(blob.short_address, blob.api_version);
    ESP_LOGI(TAG, "module short address %04x, api version %u", blob.short_address, blob.api_version);
  }
  FermobDeviceBlob device{};
  if (this->device_pref_.load(&device) && memcmp(device.magic, "FMDT", 4) == 0) {
    pair_set_device_type(device.device_type);
    ESP_LOGI(TAG, "device type %u", device.device_type);
  }
}

void FermobHub::save_module_info() {
  const pair_module_info_t *info = pair_module_info();
  if (info->have_short_address) {
    FermobModuleBlob blob{};
    memcpy(blob.magic, "FMMI", 4);
    blob.short_address = info->short_address;
    blob.api_version = info->api_version;
    if (!this->module_pref_.save(&blob)) {
      ESP_LOGW(TAG, "storing the module info failed");
    }
  }
  if (info->have_device_type) {
    FermobDeviceBlob device{};
    memcpy(device.magic, "FMDT", 4);
    device.device_type = info->device_type;
    if (!this->device_pref_.save(&device)) {
      ESP_LOGW(TAG, "storing the device type failed");
    }
  }
  global_preferences->sync();
}

void FermobHub::publish_state(bool optimistic) {
  if (this->state_listener_ == nullptr) {
    return;
  }
  // optimistic means "this is what was asked for, the light has not confirmed";
  // the entity shows it either way, and the light's own push overwrites it as
  // soon as it lands.
  (void) optimistic;
  this->state_listener_(this->state_listener_ctx_, this->on_, this->brightness_);
}

std::string FermobHub::unique_id_prefix() const {
  if (this->address_configured_) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x",
             static_cast<uint8_t>(this->connect_address_ >> 40),
             static_cast<uint8_t>(this->connect_address_ >> 32),
             static_cast<uint8_t>(this->connect_address_ >> 24),
             static_cast<uint8_t>(this->connect_address_ >> 16),
             static_cast<uint8_t>(this->connect_address_ >> 8),
             static_cast<uint8_t>(this->connect_address_));
    return std::string(buf);
  }
  return "fermob";
}

}  // namespace fermob
}  // namespace esphome
