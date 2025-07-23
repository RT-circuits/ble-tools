# BLE Tools

- `ble_basic_scanner.py`: Rough Python BLE inspector/scanner/monitor that shows service UUIDs and its details from Bluetooth advertisements. PySide6 UI. Real time updates
- `ble_adv_scanner.py`: As above, but with distinction between service UUID's (advertisement AD types 0x02-0x07) and service UUID data (AD types 0x16, 0x20-0x21). Inspection panel for mfg data, service UUIDs and service UUID data

**Requires Python 3.11 or higher**

## Install

```bash
pip install -r requirements.txt
```
(`PySide6` and `bleak`)

## Run

```bash
python ble_basic_scanner.py
python ble_adv_scanner.py
```

## Features

- Scans for BLE devices and shows their service UUID
- Selecting device displays bleak object data. Updates during scanning
- Export advertisements of all scanned devices

## Screenshots

### Basic Scanner
![BLE Basic Scanner](screenshot_basic.png)

### Advanced Scanner
![BLE Advanced Scanner](screenshot_adv.png)

## License

MIT License - see [LICENSE](LICENSE) file for details.
