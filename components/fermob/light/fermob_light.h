#pragma once

#include "../fermob.h"

#include "esphome/components/light/light_output.h"

namespace esphome {
namespace fermob {

class FermobLight : public esphome::light::LightOutput {
 public:
  void set_hub(FermobHub *hub) {
    this->hub_ = hub;
    // The hub is the only thing that learns what the light really is doing, so
    // it reports back through this listener rather than the light polling the
    // link on its own.
    hub->add_state_listener(FermobLight::on_hub_state, this);
  }

 protected:
  void setup_state(esphome::light::LightState *state) override {
    this->state_ = state;
    this->published_ = false;
  }
  esphome::light::LightTraits get_traits() override;
  void write_state(esphome::light::LightState *state) override;

  // Hub callback.
  static void on_hub_state(void *ctx, bool on, uint8_t brightness);

 private:
  void publish(bool on, uint8_t brightness);

  FermobHub *hub_{nullptr};
  esphome::light::LightState *state_{nullptr};
  // Set once the hub has reported something, so the first publish is not
  // suppressed as a no-op against an entity that has never had a value.
  bool published_{false};
  // Kept so a turn_off does not throw the brightness away.
  float last_brightness_{1.0f};
};

}  // namespace fermob
}  // namespace esphome