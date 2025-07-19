# BLE Tools

- `ble_basic_scanner.py`: Rough Python BLE inspector/scanner/monitor that shows service UUIDs and its details from Bluetooth advertisements. PySide6 UI. Real time updates

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python ble_adv_serv_uuid_scanner.py
```

## Features

- Scans for BLE devices and shows their service UUID
- Selecting device displays bleak object data. Updates during scanning
- Export advertisements of all scanned devices

## Screenshot

![BLE Scanner](screenshot.png)

## License

MIT License - see [LICENSE](LICENSE) file for details.
