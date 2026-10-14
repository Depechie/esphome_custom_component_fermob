#include "fermob_light.h"

#include "esphome/core/log.h"

namespace esphome {
namespace fermob {

static const char *const TAG = "fermob.light";

esphome::light::LightTraits FermobLight::get_traits() {
  auto traits = esphome::light::LightTraits();
  traits.set_supported_color_modes({esphome::light::ColorMode::BRIGHTNESS});
  return traits;
}

void FermobLight::write_state(esphome::light::LightState *state) {
  if (this->hub_ == nullptr) {
    return;
  }

  // Read the *requested* values, not current_values. The brightness a caller
  // asked for lives in remote_values; current_values reports what the entity is
  // showing, which is 0 while the light is off, so turning a light on at 60%
  // from the off state would send level 0 and look like nothing happened.
  const esphome::light::LightColorValues &requested = state->remote_values;
  bool on = requested.is_on();
  // get_brightness(), not as_brightness(): the latter multiplies by the on/off
  // state and so reports 0 whenever the light is off.
  float brightness = requested.get_brightness();
  if (brightness <= 0.0f) {
    // Off: keep the last level so a later turn_on without an explicit
    // brightness comes back at the brightness it was left on.
    brightness = this->last_brightness_;
  }
  this->last_brightness_ = brightness;

  this->hub_->set_brightness(static_cast<uint8_t>(brightness * 255.0f));

  // If the light has already told us it is in exactly this state, this write is
  // the hub relaying that report back into the entity, not a request. Deciding
  // it by comparison rather than with a "while publishing" flag matters:
  // LightCall::perform() only schedules write_state when something actually
  // changed, so a flag set around perform() would stay set forever and swallow
  // every real command after it.
  if (!this->hub_->matches_reported_state(on)) {
    this->hub_->set_state(on);
  }
}

void FermobLight::on_hub_state(void *ctx, bool on, uint8_t brightness) {
  static_cast<FermobLight *>(ctx)->publish(on, brightness);
}

void FermobLight::publish(bool on, uint8_t brightness) {
  if (this->state_ == nullptr) {
    return;
  }

  // Only act on a real change. The hub publishes on every link state change,
  // not only on state changes, and each perform() would otherwise queue another
  // write_state.
  bool current_on = this->state_->remote_values.is_on();
  if (this->published_ && current_on == on &&
      static_cast<uint8_t>(this->state_->remote_values.get_brightness() * 255.0f + 0.5f) == brightness) {
    return;
  }

  // Transition length 0: the light does its own fading from the transition byte
  // in DEVICE_DATA_SET, so an ESPHome transformer on top would only produce a
  // run of identical writes.
  auto call = this->state_->make_call();
  call.set_state(on);
  call.set_brightness(brightness / 255.0f);
  call.set_transition_length(0);
  this->published_ = true;
  call.perform();
}

}  // namespace fermob
}  // namespace esphome