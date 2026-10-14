# Install And First Run

This is a short runbook for getting the ESPHome Fermob light component running.

## 1. Prepare ESPHome Secrets

In your ESPHome configuration directory, add Wi-Fi credentials to `secrets.yaml`:

```yaml
wifi_ssid: YOUR_WIFI
wifi_password: YOUR_PASSWORD
```

## 2. Create The ESPHome Device

Use `examples/fermob-light.example.yaml` as a starting point.

If using this repository directly from GitHub, set `external_components` like this:

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/YOUR_GITHUB_USER/esphome-fermob-light
    components: [fermob]
```

If using a local checkout, keep the example's local `components` path.

## 3. Flash The ESP32-S3

Validate the config:

```sh
esphome config examples/fermob-light.example.yaml
```

Flash over USB:

```sh
esphome upload examples/fermob-light.example.yaml --device /dev/cu.usbmodem101
```

Replace `/dev/cu.usbmodem101` with your board's serial device.

## 4. Pair The Light

Pairing starts automatically when the ESP32 connects to a Fermob light without
stored keys.

Watch serial logs:

```sh
esphome logs examples/fermob-light.example.yaml --device /dev/cu.usbmodem101
```

Expected milestones:

```text
found light ...
connected
subscribed to state notifications
starting pairing in share mode
pairing complete, traffic is now encrypted with the private key
```

If pairing does not start, make sure the light is powered, close to the ESP32,
not connected to a phone, and advertising.

## 5. Add To Home Assistant

Home Assistant should discover the ESPHome device. If not, add it manually from:

**Settings** > **Devices & services** > **Add integration** > **ESPHome**

Expected entities:

- `Fermob Light`
- `Pair Fermob Light`
- `Forget Fermob Keys`

## 6. Test Control

From Home Assistant:

1. Turn the light on.
2. Change brightness.
3. Turn the light off.

In logs, outgoing light commands look like:

```text
tx [20] ...
```

The component uses normal ESPHome light services, so Home Assistant automations,
dashboards and scenes work as with any other ESPHome light.

## 7. Re-Pairing

If you reset the light or move it between controllers:

1. Factory reset the light.
2. In Home Assistant, press `Forget Fermob Keys`.
3. Let the ESP32 reconnect and pair again.

Do not erase the ESP32's NVS unless you understand the impact. Losing the stored
keys while the light still has them usually requires a factory reset of the light.
