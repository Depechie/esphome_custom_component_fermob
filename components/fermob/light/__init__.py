import esphome.codegen as cg
from esphome.components import light

from .. import CONF_FERMOB_ID, FermobHub, fermob_schema, fermob_ns

DEPENDENCIES = ["fermob"]

# A LightOutput, not a Component: it has no setup or dump_config of its own, it
# only needs setup_state() to capture the LightState and write_state() to drive
# the hub.
FermobLight = fermob_ns.class_("FermobLight", light.LightOutput)

CONFIG_SCHEMA = fermob_schema(
    light.light_schema(FermobLight, light.LightType.BRIGHTNESS_ONLY)
)


async def to_code(config):
    var = await light.new_light(config)
    hub = await cg.get_variable(config[CONF_FERMOB_ID])
    cg.add(var.set_hub(hub))
