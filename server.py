#!/usr/bin/env python3
import json
import os
import subprocess
import threading
import time
import gzip
import logging
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver
from urllib.parse import parse_qs, urlparse
import shutil

# Configuration
KISMET_DIR = os.environ.get("KISMET", "/opt/kismet")
CHECK_INTERVAL = 30  # seconds
PORT = 5555
PAGE_SIZE = 100  # Number of devices per page

# Global state
processed_files = {}  # Keep track of processed files and their timestamps
all_devices = {}  # Global device dictionary: MAC -> {device_info, sources: [filenames]}

# HTML template with pagination and search
HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>Kismet Device Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .pagination { margin-top: 20px; text-align: center; }
        .pagination button {
            padding: 8px 16px;
            margin: 0 4px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .pagination button:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
        .search-container {
            margin: 20px 0;
            display: flex;
            gap: 10px;
        }
        .search-container input, .search-container select {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .search-container input { flex-grow: 1; }
        .position-link { color: #0066cc; text-decoration: underline; cursor: pointer; }
        
        /* New styles for file selection */
        .file-selection {
            margin: 20px 0;
            padding: 15px;
            background-color: #f5f5f5;
            border-radius: 4px;
        }
        .file-selection h3 {
            margin-top: 0;
            margin-bottom: 10px;
        }
        .file-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #ddd;
            padding: 10px;
            background: white;
        }
        .file-list label {
            display: block;
            margin: 5px 0;
        }
        .file-controls {
            margin-top: 10px;
            display: flex;
            gap: 10px;
        }
        .file-controls button {
            padding: 5px 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .file-controls button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="status">
            Last update: <span id="lastUpdate">Never</span><br>
            Devices found: <span id="deviceCount">0</span> (Showing page <span id="currentPage">1</span>)
        </div>

        <!-- New file selection section -->
        <div class="file-selection">
            <h3>Kismet Files</h3>
            <div id="fileList" class="file-list">
                <!-- Files will be populated here -->
            </div>
            <div class="file-controls">
                <button onclick="selectAllFiles()">Select All</button>
                <button onclick="deselectAllFiles()">Deselect All</button>
                <button onclick="updateDevices()">Apply Selection</button>
            </div>
        </div>

        <div class="search-container">
            <select id="searchField">
                <option value="all">All Fields</option>
                <option value="type">Type</option>
                <option value="mac">MAC Address</option>
                <option value="vendor">Vendor</option>
                <option value="name">Name</option>
                <option value="channel">Channel</option>
                <option value="comment">Comment</option>
            </select>
            <input type="text" id="searchInput" placeholder="Search devices...">
            <button onclick="downloadCSV()" class="download-btn">Download CSV</button>
        </div>

        <table id="deviceTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Type</th>
                    <th onclick="sortTable(1)">MAC Address</th>
                    <th onclick="sortTable(2)">Vendor</th>
                    <th onclick="sortTable(3)">Name</th>
                    <th onclick="sortTable(4)">First Seen</th>
                    <th onclick="sortTable(5)">Last Seen</th>
                    <th onclick="sortTable(6)">Channel</th>
                    <th onclick="sortTable(7)">Packets</th>
                    <th onclick="sortTable(8)">Comment</th>
                    <th>Position</th>
                    <th>Sources</th>
                </tr>
            </thead>
            <tbody id="deviceList"></tbody>
        </table>

        <div class="pagination">
            <button onclick="changePage(-1)" id="prevButton">Previous</button>
            <span id="pageInfo"></span>
            <button onclick="changePage(1)" id="nextButton">Next</button>
        </div>
    </div>

    <script>
        let currentPage = 1, totalPages = 1, sortColumn = 0, sortAsc = true;
        let selectedFiles = new Set();
        const PAGE_SIZE = 100;

        function createPositionLink(lat, lon) {
            if (lat === 0 && lon === 0) return '';
            return `<a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}&zoom=17" 
                      target="_blank" class="position-link">${lat.toFixed(6)}, ${lon.toFixed(6)}</a>`;
        }

        async function loadFileList() {
            try {
                const response = await fetch('files');
                const files = await response.json();
                const fileList = document.getElementById('fileList');
                fileList.innerHTML = '';
                
                files.forEach(file => {
                    const label = document.createElement('label');
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.value = file;
                    checkbox.checked = selectedFiles.has(file);
                    checkbox.onchange = () => {
                        if (checkbox.checked) {
                            selectedFiles.add(file);
                        } else {
                            selectedFiles.delete(file);
                        }
                    };
                    label.appendChild(checkbox);
                    label.appendChild(document.createTextNode(` ${file}`));
                    fileList.appendChild(label);
                });

                // If no files are selected, select all by default
                if (selectedFiles.size === 0) {
                    selectAllFiles();
                }
            } catch (error) {
                console.error('Error loading file list:', error);
            }
        }

        function selectAllFiles() {
            const checkboxes = document.querySelectorAll('#fileList input[type="checkbox"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = true;
                selectedFiles.add(checkbox.value);
            });
        }

        function deselectAllFiles() {
            const checkboxes = document.querySelectorAll('#fileList input[type="checkbox"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
                selectedFiles.delete(checkbox.value);
            });
        }

        function updateDevices() {
            const searchQuery = document.getElementById('searchInput').value;
            const searchField = document.getElementById('searchField').value;
            const selectedFilesArray = Array.from(selectedFiles);
            const url = `devices?page=${currentPage}&search=${encodeURIComponent(searchQuery)}&field=${searchField}&sort=${sortColumn}&order=${sortAsc ? 'asc' : 'desc'}&files=${encodeURIComponent(JSON.stringify(selectedFilesArray))}`;
            
            fetch(url)
                .then(response => response.json())
                .then(data => {
                    const tbody = document.getElementById('deviceList');
                    tbody.innerHTML = '';
                    
                    data.devices.forEach(device => {
                        const row = tbody.insertRow();
                        row.insertCell(0).textContent = device.type;
                        row.insertCell(1).textContent = device.mac;
                        row.insertCell(2).textContent = device.vendor;
                        row.insertCell(3).textContent = device.name;
                        row.insertCell(4).textContent = device.first_seen;
                        row.insertCell(5).textContent = device.last_seen;
                        row.insertCell(6).textContent = device.channel;
                        row.insertCell(7).textContent = device.packets;
                        row.insertCell(8).textContent = device.comment || '';
                        
                        const positionCell = row.insertCell(9);
                        positionCell.innerHTML = createPositionLink(device.latitude, device.longitude);
                        
                        const sourcesCell = row.insertCell(10);
                        sourcesCell.className = 'sources';
                        device.sources.forEach(source => {
                            sourcesCell.innerHTML += `
                                <a href="${source}">DB</a>
                                <a href="${source.replace('.kismet', '.pcapng')}">PCAP</a> `;
                        });
                    });

                    totalPages = Math.ceil(data.total / PAGE_SIZE);
                    document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
                    document.getElementById('deviceCount').textContent = data.total;
                    document.getElementById('currentPage').textContent = currentPage;
                    document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages}`;
                    document.getElementById('prevButton').disabled = currentPage <= 1;
                    document.getElementById('nextButton').disabled = currentPage >= totalPages;
                })
                .catch(error => console.error('Error:', error));
        }

        function downloadCSV() {
            // Get current search query value from the search input
            const searchQuery = document.getElementById('searchInput').value;
            
            // Get current search field selection (e.g., "all", "type", "mac", etc.)
            const searchField = document.getElementById('searchField').value;
            
            // Convert the Set of selected files to an array
            const selectedFilesArray = Array.from(selectedFiles);
            
            // Construct the URL with all necessary parameters
            const url = `devices?download=true&search=${encodeURIComponent(searchQuery)}&field=${searchField}&sort=${sortColumn}&order=${sortAsc ? 'asc' : 'desc'}&files=${encodeURIComponent(JSON.stringify(selectedFilesArray))}`;
            
            // Trigger the download by redirecting to the URL
            window.location.href = url;
        }

        function changePage(delta) {
            const newPage = currentPage + delta;
            if (newPage >= 1 && newPage <= totalPages) {
                currentPage = newPage;
                updateDevices();
            }
        }

        function sortTable(column) {
            sortColumn = column === sortColumn ? sortColumn : column;
            sortAsc = column === sortColumn ? !sortAsc : true;
            updateDevices();
        }

        const debounce = (func, wait) => {
            let timeout;
            return (...args) => {
                clearTimeout(timeout);
                timeout = setTimeout(() => func.apply(this, args), wait);
            };
        };

        document.getElementById('searchInput').addEventListener('input', 
            debounce(() => { currentPage = 1; updateDevices(); }, 300));
        document.getElementById('searchField').addEventListener('change', 
            () => { currentPage = 1; updateDevices(); });

        // Initial load
        loadFileList();
        updateDevices();
        setInterval(() => {
            loadFileList();
            updateDevices();
        }, 30000);
    </script>
</body>
</html>
"""


def setup_logger():
    # Create logger
    logger = logging.getLogger("my_logger")
    logger.setLevel(logging.DEBUG)

    # Create console handler and set level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter(
        "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Add formatter to handler
    console_handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(console_handler)

    return logger


# Initialize logger
logger = setup_logger()


def store_merged_devices(data):
    filepath = os.path.join(KISMET_DIR, "merged_devices.json.gz")
    with gzip.open(filepath, "wt", encoding="utf-8") as f:
        json.dump(data, f)


def load_merged_devices():
    filepath = os.path.join(KISMET_DIR, "merged_devices.json.gz")
    with gzip.open(filepath, "rt", encoding="utf-8") as f:
        return json.load(f)


class DeviceManager:
    def __init__(self):
        pass

    def load_devices(self):
        """Load existing merged devices file if it exists"""
        try:
            devices = load_merged_devices()
            all_devices.clear()
            for device in devices:
                all_devices[device["mac"]] = device
            print_debug(f"Loaded {len(all_devices)} devices from existing merged file")
        except Exception as e:
            print_debug(f"Error loading merged devices: {str(e)}")

    def save_devices(self):
        """Save current devices to merged file"""
        try:
            store_merged_devices(list(all_devices.values()))
            print_debug("Successfully saved merged devices file")
        except Exception as e:
            print_debug(f"Error saving merged devices: {str(e)}")

    def filter_devices(self, search_query="", search_field="all", sort_column=0, sort_asc=True, selected_files=None):
        """Filter and sort devices based on search criteria and selected files"""
        devices = []
        
        # If no files are selected, return empty list
        if not selected_files:
            return devices
            
        # Load devices from each selected JSON file
        for json_file in selected_files:
            try:
                with open(os.path.join(KISMET_DIR, json_file), 'r') as f:
                    file_devices = json.load(f)
                    for device in file_devices:
                        # Convert device data to our standard format
                        location = (
                            device.get("kismet.device.base.location", {})
                            .get("kismet.common.location.avg_loc", {})
                            .get("kismet.common.location.geopoint", [0, 0])
                        )
                        longitude = location[0] if len(location) > 0 else 0
                        latitude = location[1] if len(location) > 1 else 0

                        device_info = {
                            "type": device.get("kismet.device.base.type", "Unknown"),
                            "mac": device.get("kismet.device.base.macaddr", "Unknown"),
                            "vendor": device.get("kismet.device.base.manuf", "Unknown"),
                            "name": device.get(
                                "kismet.device.base.commonname",
                                device.get("kismet.device.base.name", "Unknown"),
                            ),
                            "last_seen": datetime.fromtimestamp(
                                device.get("kismet.device.base.last_time", 0)
                            ).strftime("%Y-%m-%d %H:%M:%S"),
                            "first_seen": datetime.fromtimestamp(
                                device.get("kismet.device.base.first_time", 0)
                            ).strftime("%Y-%m-%d %H:%M:%S"),
                            "channel": device.get("kismet.device.base.channel", "Unknown"),
                            "packets": device.get("kismet.device.base.packets.total", 0),
                            "longitude": longitude,
                            "latitude": latitude,
                            "comment": device.get("kismet.device.base.crypt", "")
                            + " freq: "
                            + str(device.get("kismet.device.base.frequency", 0) / 1000),
                            "sources": [json_file.replace('.json', '')],
                        }
                        
                        # Add device to our list
                        devices.append(device_info)
            except Exception as e:
                print_debug(f"Error loading devices from {json_file}: {str(e)}")

        # Apply search filter
        if search_query:
            search_query = search_query.lower()
            filtered_devices = []
            for device in devices:
                if search_field == "all":
                    searchable_text = f"{device['type']} {device['mac']} {device['vendor']} {device['name']} {device['channel']} {device['comment']}".lower()
                    if search_query in searchable_text:
                        filtered_devices.append(device)
                else:
                    field_value = str(device.get(search_field, "")).lower()
                    if search_query in field_value:
                        filtered_devices.append(device)
            devices = filtered_devices

        # Sort devices
        sort_key = [
            "type", "mac", "vendor", "name", "first_seen", 
            "last_seen", "channel", "packets", "comment"
        ][sort_column]
        reverse = not sort_asc

        if sort_key in ["first_seen", "last_seen"]:
            devices.sort(
                key=lambda x: datetime.strptime(x[sort_key], "%Y-%m-%d %H:%M:%S"),
                reverse=reverse,
            )
        elif sort_key == "packets":
            devices.sort(key=lambda x: int(x[sort_key]), reverse=reverse)
        else:
            devices.sort(key=lambda x: str(x[sort_key]).lower(), reverse=reverse)

        return devices

def update_merged_devices():
    print_debug("Starting device update cycle")
    device_manager = DeviceManager()

    kismet_files = [f for f in os.listdir(KISMET_DIR) if f.endswith(".kismet")]
    print_debug(f"Found {len(kismet_files)} Kismet files")

    updated = False
    for filename in kismet_files:
        kismet_file = os.path.join(KISMET_DIR, filename)
        json_file = os.path.join(KISMET_DIR, f"{filename}.json")

        try:
            current_mod_time = os.path.getmtime(kismet_file)
        except Exception as e:
            print_debug(f"Error getting modification time for {filename}: {str(e)}")
            continue

        if (
            filename in processed_files
            and processed_files[filename] >= current_mod_time
        ):
            continue

        if convert_kismet_to_json(kismet_file, json_file):
            devices = parse_json_file(json_file, filename)

            for device in devices:
                mac = device["mac"]
                if mac in all_devices:
                    if device["last_seen"] > all_devices[mac]["last_seen"]:
                        if filename not in all_devices[mac]["sources"]:
                            all_devices[mac]["sources"].append(filename)
                        all_devices[mac].update(device)
                        all_devices[mac]["sources"] = list(
                            set(all_devices[mac]["sources"])
                        )
                        updated = True
                else:
                    all_devices[mac] = device
                    updated = True

            processed_files[filename] = current_mod_time

    if updated:
        device_manager.save_devices()


def print_debug(message):
    """Utility function for debug messages with timestamp"""
    logger.info(message)


def convert_kismet_to_json(kismet_file, json_file):
    """Convert Kismet DB file to JSON if needed."""
    print_debug(f"Checking file: {kismet_file}")
    try:
        if os.path.exists(json_file):
            kismet_time = os.path.getmtime(kismet_file)
            json_time = os.path.getmtime(json_file)
            if json_time > kismet_time:
                print_debug(f"Using existing JSON file: {json_file}")
                return True

        if not shutil.which("kismetdb_dump_devices"):
            print_debug(
                f"Error: kismetdb_dump_devices not found in PATH, not converting {kismet_file} to JSON"
            )
            return False

        print_debug(f"Converting {kismet_file} to JSON...")
        cmd = ["kismetdb_dump_devices", "--in", kismet_file, "--out", json_file]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print_debug("Conversion successful")
            return True
        else:
            print_debug(f"Conversion failed: {result.stderr}")
            return False
    except Exception as e:
        print_debug(f"Error during conversion: {str(e)}")
        return False


def parse_ssid_maps(device, device_info, field):
    if field in device["dot11.device"]:
        ssids = ""
        for x in device["dot11.device"][field]:
            if "dot11.probedssid.ssid" in x:
                ssid = x.get("dot11.probedssid.ssid", "")
                if ssid:
                    device_info["comment"] += " Probd: " + ssid

            if "dot11.advertisedssid.ssid" in x:
                ssid = x.get("dot11.advertisedssid.ssid")
                if (
                    ssid not in ssids
                    and not ssid == device["kismet.device.base.commonname"]
                ):
                    ssids += " " + ssid

            wps = ""
            if "dot11.advertisedssid.wps_state" in x:
                state = x.get("dot11.advertisedssid.wps_state")
                if state == 1 or state == 2:
                    state = "enabled"
                elif state == 0:  # disabled
                    continue
                else:
                    state = f"unkn ({state})"
                wps += state
            if "dot11.advertisedssid.wps_manuf" in x:
                wps += " manuf: " + x.get("dot11.advertisedssid.wps_manuf")
            if "dot11.advertisedssid.wps_model_name" in x:
                wps += " model: " + x.get("dot11.advertisedssid.wps_model_name")
            if wps:
                device_info["comment"] += " WPS: " + wps
        if ssids:
            device_info["comment"] += " SSID: " + ssids


def parse_json_file(json_file, source_file):
    """Parse the JSON file and extract device information."""
    print_debug(f"Parsing JSON file: {json_file}")
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
        print_debug(f"Found {len(data)} devices in JSON")
        devices = []
        for device in data:
            # Get location data from the geopoint array [longitude, latitude]
            location = (
                device.get("kismet.device.base.location", {})
                .get("kismet.common.location.avg_loc", {})
                .get("kismet.common.location.geopoint", [0, 0])
            )
            longitude = location[0] if len(location) > 0 else 0
            latitude = location[1] if len(location) > 1 else 0

            device_info = {
                "type": device.get("kismet.device.base.type", "Unknown"),
                "mac": device.get("kismet.device.base.macaddr", "Unknown"),
                "vendor": device.get("kismet.device.base.manuf", "Unknown"),
                "name": device.get(
                    "kismet.device.base.commonname",
                    device.get("kismet.device.base.name", "Unknown"),
                ),
                "last_seen": datetime.fromtimestamp(
                    device.get("kismet.device.base.last_time", 0)
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "first_seen": datetime.fromtimestamp(
                    device.get("kismet.device.base.first_time", 0)
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "channel": device.get("kismet.device.base.channel", "Unknown"),
                "packets": device.get("kismet.device.base.packets.total", 0),
                "longitude": longitude,
                "latitude": latitude,
                "comment": device.get("kismet.device.base.crypt", "")
                + " freq: "
                + str(device.get("kismet.device.base.frequency") / 1000),
                "sources": [source_file],
            }
            devices.append(device_info)

            if "dot11.device" in device:
                parse_ssid_maps(device, device_info, "dot11.device.advertised_ssid_map")
                parse_ssid_maps(device, device_info, "dot11.device.responded_ssid_map")
                parse_ssid_maps(device, device_info, "dot11.device.probed_ssid_map")
                if "dot11.device.associated_client_map" in device["dot11.device"]:
                    device_info["comment"] += " Clt: " + " , ".join(
                        [
                            x
                            for x in device["dot11.device"][
                                "dot11.device.associated_client_map"
                            ]
                        ]
                    )

        print_debug(f"Successfully parsed {len(devices)} devices")
        return devices
    except Exception as e:
        print_debug(f"Error parsing JSON file: {str(e)}")
        return []


class CustomHandler(SimpleHTTPRequestHandler):
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode())

        elif parsed_url.path == "/files":
            kismet_files = [f for f in os.listdir(KISMET_DIR) if f.endswith(".kismet.json")]
            self.send_json_response(kismet_files)

        elif parsed_url.path == "/devices":
            query = parse_qs(parsed_url.query)
            page = int(query.get("page", ["1"])[0])
            search = query.get("search", [""])[0]
            field = query.get("field", ["all"])[0]
            sort_column = int(query.get("sort", ["0"])[0])
            sort_asc = query.get("order", ["asc"])[0] == "asc"
            download = query.get("download", ["false"])[0].lower() == "true"
            
            # Parse selected files from query
            files_param = query.get("files", ["[]"])[0]
            try:
                selected_files = json.loads(files_param)
            except json.JSONDecodeError:
                selected_files = []

            device_manager = DeviceManager()
            filtered_devices = device_manager.filter_devices(
                search, field, sort_column, sort_asc, selected_files
            )

            if download:
                # Prepare CSV response
                self.send_response(200)
                self.send_header("Content-type", "text/csv")
                self.send_header("Content-Disposition", 'attachment; filename="devices.csv"')
                self.end_headers()
                
                # Write CSV header
                headers = ["Type", "MAC Address", "Vendor", "Name", "First Seen", "Last Seen", 
                          "Channel", "Packets", "Comment", "Latitude", "Longitude", "Sources"]
                self.wfile.write(",".join(headers).encode() + b"\n")
                
                # Write device data
                for device in filtered_devices:
                    row = [
                        str(device["type"]),
                        str(device["mac"]),
                        str(device["vendor"]),
                        str(device["name"]),
                        str(device["first_seen"]),
                        str(device["last_seen"]),
                        str(device["channel"]),
                        str(device["packets"]),
                        str(device["comment"]).replace(",", ";"),  # Replace commas in comments
                        str(device["latitude"]),
                        str(device["longitude"]),
                        ";".join(device["sources"])  # Join sources with semicolon
                    ]
                    # Escape quotes and wrap fields in quotes
                    escaped_row = [f'"{field.replace('"', '""')}"' for field in row]
                    self.wfile.write(",".join(escaped_row).encode() + b"\n")
            else:
                # Regular JSON paginated response
                page = int(query.get("page", ["1"])[0])
                start_idx = (page - 1) * PAGE_SIZE
                end_idx = start_idx + PAGE_SIZE

                response_data = {
                    "devices": filtered_devices[start_idx:end_idx],
                    "total": len(filtered_devices),
                    "page": page,
                    "pages": (len(filtered_devices) + PAGE_SIZE - 1) // PAGE_SIZE,
                }

                self.send_json_response(response_data)

        else:
            super().do_GET()


def run_http_server():
    class NoBlockHttpServer(socketserver.ThreadingMixIn, HTTPServer):
        pass

    print_debug(f"Changing to directory: {KISMET_DIR}")
    os.chdir(KISMET_DIR)

    print_debug(f"Starting HTTP server on port {PORT}")
    httpd = NoBlockHttpServer(("", PORT), CustomHandler)
    print_debug("HTTP Server is ready to handle requests")
    httpd.serve_forever()



def update_merged_devices():
    """Modified to handle individual JSON files"""
    print_debug("Starting device update cycle")

    kismet_files = [f for f in os.listdir(KISMET_DIR) if f.endswith(".kismet")]
    print_debug(f"Found {len(kismet_files)} Kismet files")

    for filename in kismet_files:
        kismet_file = os.path.join(KISMET_DIR, filename)
        json_file = os.path.join(KISMET_DIR, f"{filename}.json")

        try:
            current_mod_time = os.path.getmtime(kismet_file)
        except Exception as e:
            print_debug(f"Error getting modification time for {filename}: {str(e)}")
            continue

        if (
            filename in processed_files
            and processed_files[filename] >= current_mod_time
        ):
            continue

        if convert_kismet_to_json(kismet_file, json_file):
            processed_files[filename] = current_mod_time


def monitor_kismet_files():
    print_debug("Starting Kismet file monitor")
    while True:
        try:
            print_debug(
                f"Starting update cycle (will repeat every {CHECK_INTERVAL} seconds)"
            )
            update_merged_devices()
            print_debug("Update cycle completed")
        except Exception as e:
            print_debug(f"Error in monitor cycle: {str(e)}")
        time.sleep(CHECK_INTERVAL)


def main():
    print_debug("Starting Kismet Monitor")

    # Initialize device manager and load existing data
    device_manager = DeviceManager()

    print_debug("Initializing HTTP server thread")
    server_thread = threading.Thread(target=run_http_server, daemon=True)
    server_thread.start()
    print_debug("HTTP server thread started")

    print_debug("Initializing monitoring thread")
    monitor_thread = threading.Thread(target=monitor_kismet_files, daemon=True)
    monitor_thread.start()
    print_debug("Monitoring thread started")

    try:
        print_debug("Main program running - Press Ctrl+C to quit")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print_debug("\nReceived shutdown signal")
        print_debug("Shutting down...")
        # Save devices before shutting down


if __name__ == "__main__":
    KISMET_DIR = os.path.abspath(KISMET_DIR)
    if not os.path.exists(KISMET_DIR) or not os.path.isdir(KISMET_DIR):
        print_debug(f"Target directory {KISMET_DIR} does not seem to be a valid dir")
    else:
        main()
