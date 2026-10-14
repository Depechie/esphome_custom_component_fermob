#pragma once

#include "../fermob.h"

#include "esphome/components/button/button.h"
#include "esphome/core/component.h"

namespace esphome {
namespace fermob {

enum FermobButtonType : uint8_t {
  FERMOB_BUTTON_PAIR = 0,
  FERMOB_BUTTON_FORGET = 1,
};

class FermobButton : public esphome::button::Button, public esphome::Component {
 public:
  void set_hub(FermobHub *hub) { this->hub_ = hub; }
  void set_type(FermobButtonType type) { this->type_ = type; }

  void setup() override {}
  float get_setup_priority() const override { return esphome::setup_priority::AFTER_CONNECTION; }
  void dump_config() override;

 protected:
  void press_action() override;
  FermobHub *hub_{nullptr};
  FermobButtonType type_{FERMOB_BUTTON_PAIR};
};

}  // namespace fermob
}  // namespace esphome
