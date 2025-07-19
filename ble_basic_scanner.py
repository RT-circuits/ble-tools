#!/usr/bin/env python3
"""
BLE Scanner Application
Extracts: Address, Advertised Name, Manufacturer, Service UUIDs, RSSI, Interval, Last Seen
"""

import sys
import asyncio
import time
import platform
import traceback
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
import json

from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                               QWidget, QPushButton, QTableWidget, QTableWidgetItem, 
                               QLabel, QTextEdit, QHeaderView, QMessageBox, QProgressBar,
                               QSplitter, QDialog, QScrollArea, QFrame, QGridLayout)
from PySide6.QtCore import QThread, QTimer, Signal, QObject, Qt
from PySide6.QtGui import QFont, QIcon

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.scanner import AdvertisementData
    from bleak.backends.device import BLEDevice
except ImportError:
    print("Bleak library not found. Please install it with: pip install bleak")
    sys.exit(1)

from manufacturer_ids import get_manufacturer_name


def get_system_info():
    """Get comprehensive system information for debugging"""
    info = []
    info.append("=== SYSTEM INFORMATION ===")
    info.append(f"Platform: {platform.platform()}")
    info.append(f"System: {platform.system()}")
    info.append(f"Release: {platform.release()}")
    info.append(f"Version: {platform.version()}")
    info.append(f"Machine: {platform.machine()}")
    info.append(f"Processor: {platform.processor()}")
    info.append(f"Python Version: {sys.version}")
    info.append(f"Python Executable: {sys.executable}")
    
    # Check Bluetooth status on different platforms
    try:
        if platform.system() == "Darwin":  # macOS
            result = subprocess.run(['system_profiler', 'SPBluetoothDataType'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                info.append("=== BLUETOOTH STATUS (macOS) ===")
                info.append(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
        elif platform.system() == "Linux":
            result = subprocess.run(['hciconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                info.append("=== BLUETOOTH STATUS (Linux) ===")
                info.append(result.stdout)
        elif platform.system() == "Windows":
            result = subprocess.run(['powershell', 'Get-PnpDevice', '-Class', 'Bluetooth'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                info.append("=== BLUETOOTH STATUS (Windows) ===")
                info.append(result.stdout)
    except Exception as e:
        info.append(f"Error getting Bluetooth status: {e}")
    
    return "\n".join(info)


def get_detailed_error_info(error, context=""):
    """Generate detailed error information"""
    error_info = []
    error_info.append("=== DETAILED ERROR INFORMATION ===")
    error_info.append(f"Error Type: {type(error).__name__}")
    error_info.append(f"Error Message: {str(error)}")
    error_info.append(f"Context: {context}")
    error_info.append("")
    error_info.append("=== STACK TRACE ===")
    error_info.append(traceback.format_exc())
    error_info.append("")
    error_info.append(get_system_info())
    return "\n".join(error_info)




class BLEScannerWorker(QObject):
    """Worker thread for BLE scanning"""
    device_found = Signal(dict)
    scan_started = Signal()
    scan_stopped = Signal()
    error_occurred = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.is_scanning = False
        self.scanner = None
        
    async def start_scanning(self):
        """Start BLE scanning"""
        try:
            self.is_scanning = True
            self.scan_started.emit()
            
            # Simple scanning approach without context manager
            scanner = BleakScanner(detection_callback=self.detection_callback)
            self.scanner = scanner
            
            await scanner.start()
            
            # Keep scanning until stopped
            while self.is_scanning:
                await asyncio.sleep(0.1)
                
        except Exception as e:
            detailed_error = get_detailed_error_info(e, "BLE Scanner Worker - start_scanning")
            print(f"BLE SCANNER ERROR (Terminal):\n{detailed_error}")
            self.error_occurred.emit(f"Scanning error: {str(e)}\n\nSee terminal for detailed error information.")
        finally:
            try:
                if self.scanner:
                    await self.scanner.stop()
            except:
                pass
            self.is_scanning = False
            self.scan_stopped.emit()
    
    def detection_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """Callback for when a device is detected"""
        try:
            # Extract manufacturer data
            manufacturer_data = advertisement_data.manufacturer_data
            manufacturer_name = ""
            manufacturer_id = None
            
            if manufacturer_data:
                # Get the first manufacturer ID (usually the only one)
                manufacturer_id = list(manufacturer_data.keys())[0]
                manufacturer_name = get_manufacturer_name(manufacturer_id)
                # If it's unknown, just show the hex ID
                if manufacturer_name.startswith("Unknown"):
                    manufacturer_name = f"0x{manufacturer_id:04X}"
            
            # Extract service UUIDs from both service_uuids and service_data
            service_uuids = advertisement_data.service_uuids or []
            service_data_uuids = list(advertisement_data.service_data.keys()) if advertisement_data.service_data else []
            
            # Combine both sources of service UUIDs
            all_service_uuids = list(set(service_uuids + service_data_uuids))
            
            # Convert 128-bit UUIDs to 16-bit notation if they use SIG base
            converted_uuids = []
            for uuid in all_service_uuids:
                # Check if it's a 128-bit UUID using SIG base
                if len(uuid) == 36 and uuid.endswith('-0000-1000-8000-00805f9b34fb'):
                    # Extract the 16-bit part
                    parts = uuid.split('-')
                    if len(parts) == 5 and parts[0].startswith('0000'):
                        sixteen_bit = parts[0][4:]  # Remove '0000' prefix
                        converted_uuids.append(sixteen_bit)
                    else:
                        converted_uuids.append(uuid)
                else:
                    converted_uuids.append(uuid)
            
            service_uuids_str = "\n".join(converted_uuids) if converted_uuids else ""
            
            # Create service data strings for each UUID
            service_data_strings = []
            for uuid in all_service_uuids:
                if uuid in advertisement_data.service_data:
                    # Get the hex data
                    hex_data = advertisement_data.service_data[uuid].hex().upper()
                    service_data_strings.append(hex_data)
                else:
                    # UUID has no data
                    service_data_strings.append("null")
            
            service_data_str = "\n".join(service_data_strings) if service_data_strings else ""
            
            # Extract RSSI
            rssi = getattr(advertisement_data, 'rssi', 'N/A')
            
            # Clamp RSSI to help with sorting (prevents -100 from sorting at top)
            if isinstance(rssi, (int, float)):
                rssi = max(rssi, -99)
            
            # Current timestamp
            last_seen = datetime.now().strftime("%H:%M:%S")
            
            # Create enhanced service_data with all UUIDs (including those without data)
            enhanced_service_data = {}
            for uuid in all_service_uuids:
                if uuid in advertisement_data.service_data:
                    # UUID has data - convert bytes to hex string
                    enhanced_service_data[uuid] = advertisement_data.service_data[uuid].hex().upper()
                else:
                    # UUID has no data - set to null
                    enhanced_service_data[uuid] = None
            
            device_info = {
                'address': device.address,
                'name': device.name or advertisement_data.local_name or "",
                'manufacturer': manufacturer_name,
                'manufacturer_id': f"0x{manufacturer_id:04X}" if manufacturer_id else "",
                'service_uuids': service_uuids_str,
                'service_data': service_data_str,
                'rssi': int(rssi) if rssi != 'N/A' else -999,  # Convert to int for proper sorting
                'last_seen': last_seen,
                'raw_data': {
                    'manufacturer_data': manufacturer_data,
                    'service_data': enhanced_service_data,
                    'tx_power': advertisement_data.tx_power,
                    'platform_data': advertisement_data.platform_data
                }
            }
            
            self.device_found.emit(device_info)
            
        except Exception as e:
            detailed_error = get_detailed_error_info(e, f"BLE Scanner Worker - detection_callback for device {device.address}")
            print(f"BLE DEVICE PROCESSING ERROR (Terminal):\n{detailed_error}")
            self.error_occurred.emit(f"Error processing device {device.address}: {str(e)}\n\nSee terminal for detailed error information.")
    
    def stop_scanning(self):
        """Stop BLE scanning"""
        self.is_scanning = False


class BLEScannerThread(QThread):
    """Thread wrapper for BLE scanner worker"""
    device_found = Signal(dict)
    scan_started = Signal()
    scan_stopped = Signal()
    error_occurred = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.worker = BLEScannerWorker()
        self.worker.device_found.connect(self.device_found.emit)
        self.worker.scan_started.connect(self.scan_started.emit)
        self.worker.scan_stopped.connect(self.scan_stopped.emit)
        self.worker.error_occurred.connect(self.error_occurred.emit)
    
    def run(self):
        """Run the BLE scanner"""
        try:
            asyncio.run(self.worker.start_scanning())
        except Exception as e:
            detailed_error = get_detailed_error_info(e, "BLE Scanner Thread - run method")
            print(f"BLE THREAD ERROR (Terminal):\n{detailed_error}")
            self.error_occurred.emit(f"Thread error: {str(e)}\n\nSee terminal for detailed error information.")
    
    def stop(self):
        """Stop the scanner"""
        self.worker.stop_scanning()


class ManufacturerDataViewer(QDialog):
    """Dialog for viewing detailed manufacturer data"""
    
    def __init__(self, manufacturer_data, manufacturer_name, parent=None):
        super().__init__(parent)
        self.manufacturer_data = manufacturer_data
        self.manufacturer_name = manufacturer_name
        self.init_ui()
        
    def init_ui(self):
        """Initialize the dialog UI"""
        self.setWindowTitle(f"Manufacturer Data Viewer - {self.manufacturer_name}")
        self.setGeometry(200, 200, 800, 600)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel(f"Manufacturer: {self.manufacturer_name}")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(header_label)
        
        # Scroll area for content
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        if not self.manufacturer_data:
            no_data_label = QLabel("No manufacturer data available")
            no_data_label.setStyleSheet("color: #666; font-style: italic; padding: 20px;")
            scroll_layout.addWidget(no_data_label)
        else:
            # Display manufacturer data for each manufacturer ID
            for manufacturer_id, data_bytes in self.manufacturer_data.items():
                # Create a frame for each manufacturer
                frame = QFrame()
                frame.setFrameStyle(QFrame.Box)
                frame.setStyleSheet("QFrame { border: 1px solid #ccc; margin: 5px; padding: 10px; }")
                frame_layout = QVBoxLayout(frame)
                
                # Manufacturer ID header
                id_label = QLabel(f"Manufacturer ID: 0x{manufacturer_id:04X}")
                id_label.setStyleSheet("font-weight: bold; color: #333;")
                frame_layout.addWidget(id_label)
                
                # Data length
                data_length = len(data_bytes)
                length_label = QLabel(f"Data Length: {data_length} bytes")
                length_label.setStyleSheet("color: #666;")
                frame_layout.addWidget(length_label)
                
                # Raw hex data
                hex_data = data_bytes.hex().upper()
                hex_label = QLabel("Raw Data (Hex):")
                hex_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
                frame_layout.addWidget(hex_label)
                
                hex_text = QTextEdit()
                hex_text.setPlainText(hex_data)
                hex_text.setMaximumHeight(100)
                hex_text.setStyleSheet("font-family: 'Courier New', monospace; font-size: 12px;")
                frame_layout.addWidget(hex_text)
                
                # Formatted hex data (with spaces)
                formatted_hex = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
                formatted_label = QLabel("Formatted Data:")
                formatted_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
                frame_layout.addWidget(formatted_label)
                
                formatted_text = QTextEdit()
                formatted_text.setPlainText(formatted_hex)
                formatted_text.setMaximumHeight(100)
                formatted_text.setStyleSheet("font-family: 'Courier New', monospace; font-size: 12px;")
                frame_layout.addWidget(formatted_text)
                
                # Binary representation
                binary_label = QLabel("Binary Data:")
                binary_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
                frame_layout.addWidget(binary_label)
                
                binary_data = ' '.join(format(byte, '08b') for byte in data_bytes)
                binary_text = QTextEdit()
                binary_text.setPlainText(binary_data)
                binary_text.setMaximumHeight(100)
                binary_text.setStyleSheet("font-family: 'Courier New', monospace; font-size: 11px;")
                frame_layout.addWidget(binary_text)
                
                # ASCII representation (if printable)
                ascii_label = QLabel("ASCII Representation:")
                ascii_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
                frame_layout.addWidget(ascii_label)
                
                ascii_data = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data_bytes)
                ascii_text = QTextEdit()
                ascii_text.setPlainText(ascii_data)
                ascii_text.setMaximumHeight(60)
                ascii_text.setStyleSheet("font-family: 'Courier New', monospace; font-size: 12px;")
                frame_layout.addWidget(ascii_text)
                
                scroll_layout.addWidget(frame)
        
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
        """)
        layout.addWidget(close_button)


class BLEScannerApp(QMainWindow):
    """Main BLE Scanner Application"""
    
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.devices = {}  # Store devices by address
        self.init_ui()
        
        # Start scanning automatically
        QTimer.singleShot(100, self.start_scanning)
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("BLE Advertised Service UUID Monitor")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        

        
        # Control buttons
        button_layout = QHBoxLayout()
        
        # Create flat modern buttons with lighter grey design
        self.scan_button = QPushButton("▶ Start Scan")
        self.scan_button.clicked.connect(self.toggle_scanning)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
            QPushButton:pressed {
                background-color: #616161;
                color: white;
                border-color: #757575;
            }
        """)
        
        self.clear_button = QPushButton("✕ Clear")
        self.clear_button.clicked.connect(self.clear_results)
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
            QPushButton:pressed {
                background-color: #616161;
                color: white;
                border-color: #757575;
            }
        """)
        
        self.export_button = QPushButton("↓ Export")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
            QPushButton:pressed {
                background-color: #616161;
                color: white;
                border-color: #757575;
            }
        """)
        

        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.export_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Status bar
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Create splitter for table and raw data area
        splitter = QSplitter(Qt.Vertical)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Address", "Name", "Manufacturer", "Service UUIDs", "Service Data",
            "RSSI", "Last Seen"
        ])
        
        # Enable sorting
        self.table.setSortingEnabled(True)
        
        # Set column widths - make them interactive
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)  # Address
        header.setSectionResizeMode(1, QHeaderView.Interactive)  # Name
        header.setSectionResizeMode(2, QHeaderView.Interactive)  # Manufacturer
        header.setSectionResizeMode(3, QHeaderView.Interactive)  # Service UUIDs
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Service Data
        header.setSectionResizeMode(5, QHeaderView.Interactive)  # RSSI
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Last Seen
        
        # Set initial column widths
        self.table.setColumnWidth(0, 200)  # Address
        self.table.setColumnWidth(1, 150)  # Name
        self.table.setColumnWidth(2, 180)  # Manufacturer
        self.table.setColumnWidth(3, 200)  # Service UUIDs
        self.table.setColumnWidth(4, 200)  # Service Data
        self.table.setColumnWidth(5, 80)   # RSSI
        self.table.setColumnWidth(6, 100)  # Last Seen
        
        # Set table styling for clean appearance
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        
        # Enable row selection when clicking cells
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        
        # Hide row numbers (first column)
        self.table.verticalHeader().setVisible(False)
        
        # Set custom selection color (blue)
        self.table.setStyleSheet("""
            QTableWidget::item:selected {
                background-color: #007AFF;
                color: white;
            }
        """)
        
        splitter.addWidget(self.table)
        
        # Raw data text area
        self.raw_data_text = QTextEdit()
        self.raw_data_text.setPlaceholderText("Select a device to view raw data...")
        splitter.addWidget(self.raw_data_text)
        
        # Set initial splitter sizes (table gets more space)
        splitter.setSizes([600, 200])
        
        layout.addWidget(splitter)
        
        # Connect table selection
        self.table.itemSelectionChanged.connect(self.show_raw_data)
        self.table.cellClicked.connect(self.on_cell_clicked)
        
    def toggle_scanning(self):
        """Toggle BLE scanning on/off"""
        if self.scanner_thread is None or not self.scanner_thread.isRunning():
            self.start_scanning()
        else:
            self.stop_scanning()
    
    def start_scanning(self):
        """Start BLE scanning"""
        self.scanner_thread = BLEScannerThread()
        self.scanner_thread.device_found.connect(self.add_device)
        self.scanner_thread.scan_started.connect(self.on_scan_started)
        self.scanner_thread.scan_stopped.connect(self.on_scan_stopped)
        self.scanner_thread.error_occurred.connect(self.on_error)
        
        self.scanner_thread.start()
    
    def stop_scanning(self):
        """Stop BLE scanning"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.wait()
    
    def on_scan_started(self):
        """Handle scan started event"""
        self.scan_button.setText("⏹ Stop Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
            QPushButton:pressed {
                background-color: #616161;
                color: white;
                border-color: #757575;
            }
        """)
        self.status_label.setText("Scanning for BLE devices...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
    
    def on_scan_stopped(self):
        """Handle scan stopped event"""
        self.scan_button.setText("▶ Start Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: #ffffff;
                border: 1px solid #9e9e9e;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #9e9e9e;
                color: white;
                border-color: #bdbdbd;
            }
            QPushButton:pressed {
                background-color: #616161;
                color: white;
                border-color: #757575;
            }
        """)
        self.status_label.setText(f"Scan stopped. Found {len(self.devices)} devices.")
        self.progress_bar.setVisible(False)
    
    def on_error(self, error_msg):
        """Handle error events with detailed information"""
        # Extract first line of error message for status bar
        first_line = error_msg.split('\n')[0] if '\n' in error_msg else error_msg
        self.status_label.setText(f"Error: {first_line}")
        
        # Create detailed error dialog
        error_dialog = QMessageBox(self)
        error_dialog.setIcon(QMessageBox.Warning)
        error_dialog.setWindowTitle("BLE Scanner Error - Detailed Information")
        
        # Format the error message for better readability
        formatted_error = error_msg.replace("\\n", "\n")
        error_dialog.setText(f"BLE Scanner encountered an error:\n\n{formatted_error}")
        
        # Add system information to the dialog
        system_info = get_system_info()
        error_dialog.setDetailedText(system_info)
        
        # Add helpful troubleshooting tips
        troubleshooting = """
TROUBLESHOOTING TIPS:

1. BLUETOOTH PERMISSIONS:
   - Ensure Bluetooth is enabled on your system
   - Check if the app has permission to access Bluetooth
   - On macOS: System Preferences > Security & Privacy > Privacy > Bluetooth
   - On Windows: Settings > Privacy > Bluetooth
   - On Linux: Check bluetooth service status

2. HARDWARE ISSUES:
   - Verify Bluetooth adapter is working
   - Try restarting Bluetooth service
   - Check device manager for Bluetooth issues

3. SOFTWARE DEPENDENCIES:
   - Ensure bleak library is installed: pip install bleak
   - Check Python version compatibility
   - Verify PySide6 installation

4. SYSTEM REQUIREMENTS:
   - macOS 10.13+ with Bluetooth 4.0+
   - Windows 10+ with Bluetooth support
   - Linux with bluez and dbus

5. DEBUGGING:
   - Check terminal output for detailed error information
   - Review system information above
   - Try running as administrator/sudo if needed
        """
        error_dialog.setInformativeText(troubleshooting)
        
        error_dialog.exec()
    
    def add_device(self, device_info):
        """Add or update a device in the table"""
        address = device_info['address']
        self.devices[address] = device_info
        
        # Find existing row or create new one
        existing_row = None
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0) and self.table.item(row, 0).text() == address:
                existing_row = row
                break
        
        if existing_row is None:
            # Add new row
            row = self.table.rowCount()
            self.table.insertRow(row)
        else:
            row = existing_row
        
        # Update table items
        self.table.setItem(row, 0, QTableWidgetItem(device_info['address']))
        self.table.setItem(row, 1, QTableWidgetItem(device_info['name']))
        self.table.setItem(row, 2, QTableWidgetItem(device_info['manufacturer']))
        
        # Service UUIDs with word wrapping
        service_uuids_item = QTableWidgetItem(device_info['service_uuids'])
        service_uuids_item.setTextAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.table.setItem(row, 3, service_uuids_item)
        
        # Service Data with word wrapping
        service_data_item = QTableWidgetItem(device_info['service_data'])
        service_data_item.setTextAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.table.setItem(row, 4, service_data_item)
        
        # Handle RSSI display - store as integer for proper sorting
        rssi_item = QTableWidgetItem()
        if device_info['rssi'] != -999:
            rssi_item.setData(Qt.DisplayRole, str(device_info['rssi']))
            rssi_item.setData(Qt.UserRole, device_info['rssi'])  # Store integer for sorting
        else:
            rssi_item.setData(Qt.DisplayRole, 'N/A')
            rssi_item.setData(Qt.UserRole, -999)  # Store integer for sorting
        self.table.setItem(row, 5, rssi_item)
        
        self.table.setItem(row, 6, QTableWidgetItem(device_info['last_seen']))
        
        # Update raw data pane if this device is currently selected
        self.update_raw_data_if_selected(address)
        
        # Update status
        self.status_label.setText(f"Scanning... Found {len(self.devices)} devices")
    

    
    def on_cell_clicked(self, row, column):
        """Handle cell click events"""
        if row >= 0 and self.table.item(row, 0):
            address = self.table.item(row, 0).text()
            if address in self.devices:
                device_info = self.devices[address]
                raw_data = json.dumps(device_info['raw_data'], indent=2, default=str)
                self.raw_data_text.setText(f"raw_data = {raw_data}")
    
    def update_raw_data_if_selected(self, address):
        """Update raw data pane if the given address is currently selected"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        selected_address = self.table.item(row, 0).text()
        
        # If the updated device is the currently selected one, update the raw data
        if selected_address == address and address in self.devices:
            device_info = self.devices[address]
            raw_data = json.dumps(device_info['raw_data'], indent=2, default=str)
            self.raw_data_text.setText(f"raw_data = {raw_data}")
    
    def show_raw_data(self):
        """Show raw data for selected device"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        address = self.table.item(row, 0).text()
        
        if address in self.devices:
            device_info = self.devices[address]
            raw_data = json.dumps(device_info['raw_data'], indent=2, default=str)
            self.raw_data_text.setText(f"raw_data = {raw_data}")
    
    def clear_results(self):
        """Clear all results"""
        self.devices.clear()
        self.table.setRowCount(0)
        self.raw_data_text.clear()
        self.status_label.setText("Results cleared")
        

    
    def export_results(self):
        """Export results to JSON file"""
        if not self.devices:
            QMessageBox.information(self, "Export", "No devices to export")
            return
        
        try:
            filename = f"ble_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(list(self.devices.values()), f, indent=2, default=str)
            
            QMessageBox.information(self, "Export Successful", 
                                  f"Results exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")
    

    
    def closeEvent(self, event):
        """Handle application close event"""
        self.stop_scanning()
        event.accept()


def main():
    """Main application entry point"""
    try:
        app = QApplication(sys.argv)
        app.setStyle('Fusion')  # Use Fusion style for better cross-platform appearance
        
        # Set application properties
        app.setApplicationName("BLE Scanner")
        app.setApplicationVersion("1.0")
        app.setOrganizationName("BLE Scanner App")
        
        # Print startup information
        print("=== BLE SCANNER STARTUP ===")
        print(get_system_info())
        print("=== STARTING APPLICATION ===")
        
        # Create and show the main window
        window = BLEScannerApp()
        window.show()
        
        # Run the application
        sys.exit(app.exec())
        
    except Exception as e:
        detailed_error = get_detailed_error_info(e, "BLE Scanner - main function")
        print(f"BLE SCANNER STARTUP ERROR (Terminal):\n{detailed_error}")
        
        # Try to show error dialog if possible
        try:
            if 'app' in locals():
                error_dialog = QMessageBox()
                error_dialog.setIcon(QMessageBox.Critical)
                error_dialog.setWindowTitle("BLE Scanner Startup Error")
                error_dialog.setText(f"Failed to start BLE Scanner:\n\n{str(e)}")
                error_dialog.setDetailedText(detailed_error)
                error_dialog.exec()
        except:
            pass
        
        sys.exit(1)


if __name__ == "__main__":
    main() 