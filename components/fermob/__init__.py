"""Linkio/Fermob PureLine BLE light, plus a Home Assistant Bluetooth proxy.

The hub owns one GATT client slot, separate from the slots bluetooth_proxy
claims, so a single ESP32-S3 can both drive the light and relay BLE
advertisements for other devices.
"""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import esp32_ble, esp32_ble_tracker
from esphome.const import (
    CONF_ACTIVE,
    CONF_ADDRESS,
    CONF_ID,
)

CODEOWNERS = ["@fermob"]
AUTO_LOAD = ["esp32_ble_client", "esp32_ble_tracker"]
MULTI_CONF = False

CONF_FERMOB_ID = "fermob_id"
CONF_PAIRING_MODE = "pairing_mode"
CONF_LED_MODE = "led_mode"
CONF_RETRY_INTERVAL = "retry_interval"

fermob_ns = cg.esphome_ns.namespace("fermob")
FermobHub = fermob_ns.class_("FermobHub", cg.Component)

PairMode = fermob_ns.enum("FermobPairingMode")
PAIR_MODES = {
    "ADOPT": PairMode.FERMOB_PAIRING_ADOPT,
    "SHARE": PairMode.FERMOB_PAIRING_SHARE,
}

FermobButtonType = fermob_ns.enum("FermobButtonType")
BUTTON_TYPES = {
    "PAIR": FermobButtonType.FERMOB_BUTTON_PAIR,
    "FORGET": FermobButtonType.FERMOB_BUTTON_FORGET,
}


def validate_address(value):
    """Accepts AA:BB:CC:DD:EE:FF.

    MACAddress packs AA first into the most significant byte, which is the same
    end ESPBTDevice::address_uint64() puts an advertisement's first byte in, so
    a configured address and one learned from a scan compare equal.
    """
    value = cv.string_strict(value)
    parts = value.split(":")
    if len(parts) != 6:
        raise cv.Invalid("a MAC address needs six colon separated octets")
    if any(len(part) != 2 for part in parts):
        raise cv.Invalid("each octet needs two hex digits, e.g. AA:BB:CC:DD:EE:FF")
    return ":".join(part.upper() for part in parts)


# Every entity platform points back at the one hub, so this is the single place
# that reference is declared.
FERMOB_HUB_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_FERMOB_ID): cv.use_id(FermobHub),
    }
)


def fermob_schema(schema):
    return schema.extend(FERMOB_HUB_SCHEMA)


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(FermobHub),
            cv.Optional(CONF_ACTIVE, default=True): cv.boolean,
            cv.Optional(CONF_ADDRESS): validate_address,
            cv.Optional(CONF_PAIRING_MODE, default="share"): cv.enum(
                PAIR_MODES, upper=True
            ),
            cv.Optional(CONF_RETRY_INTERVAL, default="15s"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_LED_MODE, default=0): cv.int_range(min=0, max=15),
        }
    )
    .extend(esp32_ble_tracker.ESP_BLE_DEVICE_SCHEMA)
    .extend(cv.COMPONENT_SCHEMA),
    esp32_ble.consume_connection_slots(1, "fermob"),
    cv.only_on(["esp32"]),
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await esp32_ble_tracker.register_client(var, config)

    cg.add(var.set_active(config[CONF_ACTIVE]))
    if address := config.get(CONF_ADDRESS):
        from esphome.core import MACAddress

        cg.add(var.set_address(MACAddress(*[int(p, 16) for p in address.split(":")]).as_hex))
    cg.add(var.set_pairing(config[CONF_PAIRING_MODE]))
    cg.add(var.set_retry_interval(config[CONF_RETRY_INTERVAL].total_milliseconds))
    cg.add(var.set_led_mode(config[CONF_LED_MODE]))
