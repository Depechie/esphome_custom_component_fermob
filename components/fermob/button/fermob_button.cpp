#include "fermob_button.h"

#include "esphome/core/log.h"

namespace esphome {
namespace fermob {

static const char *const TAG = "fermob.button";

void FermobButton::dump_config() {
  switch (this->type_) {
  case FERMOB_BUTTON_FORGET:
    LOG_BUTTON("", "Forget", this);
    break;
  default:
    LOG_BUTTON("", "Pair", this);
    break;
  }
}

void FermobButton::press_action() {
  if (this->hub_ == nullptr) {
    return;
  }
  switch (this->type_) {
  case FERMOB_BUTTON_FORGET:
    this->hub_->forget();
    break;
  default:
    this->hub_->start_pairing();
    break;
  }
}

}  // namespace fermob
}  // namespace esphome
