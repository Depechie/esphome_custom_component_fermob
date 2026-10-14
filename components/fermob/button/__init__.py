import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import button
from esphome.const import (
    CONF_ID,
    CONF_TYPE,
    ENTITY_CATEGORY_CONFIG,
)

from .. import CONF_FERMOB_ID, BUTTON_TYPES, fermob_ns, fermob_schema

DEPENDENCIES = ["fermob"]

FermobButton = fermob_ns.class_("FermobButton", cg.Component, button.Button)

CONFIG_SCHEMA = fermob_schema(
    button.button_schema(
        FermobButton,
        icon="mdi:link-variant",
        entity_category=ENTITY_CATEGORY_CONFIG,
    ).extend({cv.Required(CONF_TYPE): cv.enum(BUTTON_TYPES, upper=True)})
)


async def to_code(config):
    var = await button.new_button(config)
    await cg.register_component(var, config)
    hub = await cg.get_variable(config[CONF_FERMOB_ID])
    cg.add(var.set_hub(hub))
    cg.add(var.set_type(config[CONF_TYPE]))
