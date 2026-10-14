# ESPHome Fermob Light

ESPHome external component for controlling a Fermob Bluetooth light from Home
Assistant with an ESP32-S3.

This project was built and tested with the Fermob MOOON! floor lamp, H. 134 cm:
https://www.fermob.com/en_int/floor-lamp-mooon-lamp-h-134-cm.html

The ESP32-S3 connects directly to the light over BLE/GATT and exposes a normal
ESPHome `light` entity in Home Assistant. You can turn the light on and off and
control brightness from Home Assistant. The same ESP32 can still run
`bluetooth_proxy:` for unrelated BLE devices.

## Status

Tested with:

- Fermob MOOON! floor lamp, H. 134 cm
- ESP32-S3 DevKitC style board
- ESPHome 2026.9.1, ESP-IDF framework
- Home Assistant ESPHome integration

Verified:

- BLE scan, connect and GATT discovery
- Fermob pairing handshake
- Encrypted control frames
- Home Assistant light entity
- On/off control
- Brightness control

Still to validate more broadly:

- Long-running connection stability
- Coexistence with `bluetooth_proxy:` under real household load
- Other Fermob/Linkio light models

## How It Works

```text
Home Assistant
  |
  | ESPHome API
  v
ESP32-S3 running this external component
  |
  | direct BLE/GATT connection
  v
Fermob light
```

This is not a Home Assistant custom integration and it does not send arbitrary
GATT writes through the stock ESPHome Bluetooth Proxy API. The Fermob connection
is owned by the ESPHome component running on the ESP32.

## Hardware

Recommended:

- ESP32-S3 board with stable USB serial/JTAG
- 2.4 GHz Wi-Fi network supported by ESPHome
- Fermob MOOON! BLE light in range of the ESP32-S3

Notes:

- Keep the ESP32 close to the light for first pairing.
- Mesh Wi-Fi systems can be problematic for ESP32 boards. If you see repeated
  `Auth Expired` Wi-Fi disconnects, test with a simple 2.4 GHz access point or
  phone hotspot first.
- A connected Fermob light usually stops advertising, so only one central device
  can actively hold the BLE connection at a time.

## Installation

1. Copy `examples/fermob-light.example.yaml` into your ESPHome configuration
   directory, or use it as a base for a new ESPHome device.
2. Set `wifi_ssid` and `wifi_password` in your ESPHome `secrets.yaml`.
3. Adjust the board if your ESP32-S3 is not `esp32-s3-devkitc-1`.
4. Optional: set the light BLE address in the `fermob:` block. If omitted, the
   component connects to the first supported Fermob light it sees.
5. Compile and flash the ESP32-S3.

Example compile command from this repository:

```sh
esphome compile examples/fermob-light.example.yaml
```

Example upload command:

```sh
esphome upload examples/fermob-light.example.yaml --device /dev/cu.usbmodem101
```

Use the serial device that belongs to your board.

## Example Configuration

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/YOUR_GITHUB_USER/esphome-fermob-light
    components: [fermob]

esp32_ble:
  max_connections: 4

esp32_ble_tracker:

bluetooth_proxy:
  active: true

fermob:
  id: fermob_hub
  pairing_mode: share

light:
  - platform: fermob
    id: fermob_light
    name: Fermob Light
    fermob_id: fermob_hub

button:
  - platform: fermob
    name: Pair Fermob Light
    fermob_id: fermob_hub
    type: pair
  - platform: fermob
    name: Forget Fermob Keys
    fermob_id: fermob_hub
    type: forget
```

For local development from a checkout, use:

```yaml
external_components:
  - source:
      type: local
      path: components
    components: [fermob]
```

## First Pairing

The component pairs automatically when it connects to a light without confirmed
keys. Watch the logs after flashing:

```sh
esphome logs examples/fermob-light.example.yaml --device /dev/cu.usbmodem101
```

Successful logs include lines like:

```text
found light ...
connected
subscribed to state notifications
starting pairing in share mode
pairing complete, traffic is now encrypted with the private key
light reported on=NO ...
```

When Home Assistant discovers the ESPHome node, add it through the normal ESPHome
integration. You should see:

- `Fermob Light`
- `Pair Fermob Light`
- `Forget Fermob Keys`

## Important: Pairing Keys

In `pairing_mode: share`, the ESP32 creates the installation keys and writes them
to the light. The ESP32 stores its copy in ESPHome preferences/NVS.

Do not erase the ESP32 NVS while the light is paired. If the ESP32 loses its keys,
the light will keep using keys the ESP32 no longer has. Recovery requires a
factory reset of the light and a fresh pairing.

Use the `Forget Fermob Keys` button only when you intentionally want to discard
the ESP32 keys and re-pair after resetting the light.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No light found | Light is powered, close to ESP32, advertising, and not already connected elsewhere |
| Pairing fails | Factory reset the light and try again; only one central should connect |
| Light responds from phone but not ESP32 | Make sure the phone is disconnected; a connected light stops advertising |
| Wi-Fi repeatedly disconnects with `Auth Expired` | Test a simple 2.4 GHz AP or hotspot; some mesh APs reject ESP32 associations |
| Light entity exists but no BLE control | Use serial logs and check for `pairing complete` and `tx [20]` frames |

## Repository Layout

```text
components/fermob/                  ESPHome external component
examples/fermob-light.example.yaml  Complete ESPHome example
docs/                               Extra user docs
```

## Development Notes

This repository intentionally contains only the ESPHome component and user-facing
setup material.

## Disclaimer

This is an independent community project and is not affiliated with Fermob.
Fermob and MOOON! are trademarks of their respective owners.
