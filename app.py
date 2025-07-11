from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import re
import pandas as pd
import csv
import os
import subprocess
import tempfile
import threading
import time
import logging
import shutil
from datetime import datetime

# Import the collector functions
from cimc_collector import collect_data_for_server, save_to_csv

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = "cimc_data_collector_secret_key"  # Needed for flash messages

# Define the path to your CSV file
CSV_FILE = "cimc_server_inventory.csv"

# Define the expected column order for the CSV and HTML display
# These match the actual fields collected by cimc_collector.py
FIELDNAMES = [
    "HostName", "Product Name", "No. of CPU", "Type of CPU", "Memory", 
    "Disk Size", "NIC Details", "OS", "Host URL", "Host IP"
]

# Global variable to track collection status
collection_status = {
    "running": False,
    "total": 0,
    "completed": 0,
    "current_server": "",
    "last_update": "",
    "errors": []
}

def save_to_csv_simple(servers, csv_file):
    """Simple CSV save function for web interface - assumes duplicates already checked."""
    if not servers:
        return False
    
    # Define the expected columns
    columns = [
        "HostName", "Product Name", "No. of CPU", "Type of CPU", "Memory", 
        "Disk Size", "NIC Details", "OS", "Host URL", "Host IP"
    ]
    
    try:
        new_df = pd.DataFrame(servers)
        
        # Ensure all required columns exist, fill missing with 'N/A'
        for col in columns:
            if col not in new_df.columns:
                new_df[col] = 'N/A'
        
        # Select only the required columns
        new_df = new_df[columns]
        
        # Check if file exists and append or create
        if os.path.exists(csv_file):
            # File exists, append to it
            existing_df = pd.read_csv(csv_file)
            combined_df = pd.concat([existing_df, new_df], ignore_index=True)
            combined_df.to_csv(csv_file, index=False)
        else:
            # File doesn't exist, create new
            new_df.to_csv(csv_file, index=False)
        
        return True
    except Exception as e:
        logging.error(f"Error saving to CSV: {e}")
        return False

# Helper function to read data from CSV
def read_data():
    """Read server data from CSV with error handling."""
    try:
        if not os.path.exists(CSV_FILE):
            logging.warning(f"CSV file {CSV_FILE} not found. Creating empty inventory.")
            return []
            
        df = pd.read_csv(CSV_FILE)
        
        if df.empty:
            logging.warning(f"CSV file {CSV_FILE} is empty.")
            return []
            
        # Ensure all expected columns are present, fill missing with 'N/A'
        for col in FIELDNAMES:
            if col not in df.columns:
                df[col] = 'N/A'
                
        # Reorder columns to ensure consistent display
        df = df[FIELDNAMES]
        
        # Clean up any NaN values
        df = df.fillna('N/A')
        
        # Clean up whitespace in string columns
        for col in df.columns:
            if df[col].dtype == 'object':  # string columns
                df[col] = df[col].astype(str).str.strip()
        
        logging.info(f"Successfully read {len(df)} records from {CSV_FILE}")
        return df.to_dict(orient='records')  # Convert DataFrame to list of dictionaries for Jinja2
        
    except FileNotFoundError:
        logging.warning(f"CSV file {CSV_FILE} not found.")
        return []  # Return empty list if file doesn't exist
    except pd.errors.EmptyDataError:
        logging.warning(f"CSV file {CSV_FILE} is empty.")
        return []  # Return empty list if file is empty
    except Exception as e:
        logging.error(f"Error reading CSV file: {str(e)}")
        flash(f"Error reading inventory data: {str(e)}", "error")
        return []

# Helper function to write data to CSV
def write_data(data):
    """Write server data to CSV with error handling."""
    try:
        if not data:
            # If no data, create empty CSV with headers
            df = pd.DataFrame(columns=FIELDNAMES)
        else:
            df = pd.DataFrame(data)
            # Ensure all expected columns are present, fill missing with 'N/A'
            for col in FIELDNAMES:
                if col not in df.columns:
                    df[col] = 'N/A'
        
        # Reorder columns to ensure consistent display
        df = df[FIELDNAMES]
        
        # Write to CSV
        df.to_csv(CSV_FILE, index=False)
        logging.info(f"Successfully wrote {len(data)} records to {CSV_FILE}")
        
    except Exception as e:
        logging.error(f"Error writing data to CSV: {str(e)}")
        flash(f"Error saving data: {str(e)}", "error")
        raise

@app.route('/')
def index():
    servers = read_data()
    return render_template('index.html', servers=servers, collection_status=collection_status)

@app.route('/add', methods=['GET', 'POST'])
def add_server():
    if request.method == 'POST':
        try:
            # Get data from the submitted form
            new_server = {}
            errors = []
            
            for field in FIELDNAMES:
                value = request.form.get(field, '').strip()
                
                # Validate required fields
                if not value or value.lower() in ['n/a', 'na', 'null', 'none', '']:
                    if field in ['HostName', 'Product Name', 'Host URL']:  # Essential fields
                        errors.append(f"{field} is required and cannot be empty")
                        continue
                    else:
                        value = 'N/A'  # Set default for optional fields
                
                # Additional validation
                if field == 'HostName':
                    # Check if hostname already exists
                    existing_servers = read_data()
                    if any(server.get('HostName', '').lower() == value.lower() for server in existing_servers):
                        errors.append(f"Server with hostname '{value}' already exists")
                        continue
                        
                new_server[field] = value
            
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template('add_edit.html', server=new_server, fieldnames=FIELDNAMES, action="Add")
            
            # Read existing data and add new server
            servers = read_data()
            servers.append(new_server)
            
            # Write all data back to CSV
            write_data(servers)
            
            flash(f"Server '{new_server['HostName']}' added successfully!", "success")
            logging.info(f"Added new server: {new_server['HostName']}")
            return redirect(url_for('index'))
            
        except Exception as e:
            logging.error(f"Error adding server: {str(e)}")
            flash(f"Error adding server: {str(e)}", "error")
            return render_template('add_edit.html', server={}, fieldnames=FIELDNAMES, action="Add")
    
    # For GET request, show the empty form
    return render_template('add_edit.html', server={}, fieldnames=FIELDNAMES, action="Add")

@app.route('/edit/<hostName>', methods=['GET', 'POST'])
def edit_server(hostName):
    try:
        servers = read_data()
        # Find the server to edit by hostName
        server_to_edit = next((s for s in servers if s['HostName'] == hostName), None)

        if not server_to_edit:
            flash(f"Server '{hostName}' not found!", "error")
            logging.warning(f"Attempted to edit non-existent server: {hostName}")
            return redirect(url_for('index'))

        if request.method == 'POST':
            errors = []
            original_hostname = server_to_edit['HostName']
            
            # Update the server's data with form submissions
            for field in FIELDNAMES:
                value = request.form.get(field, '').strip()
                
                # Validate required fields
                if not value or value.lower() in ['n/a', 'na', 'null', 'none', '']:
                    if field in ['HostName', 'Product Name', 'Host URL']:  # Essential fields
                        errors.append(f"{field} is required and cannot be empty")
                        continue
                    else:
                        value = 'N/A'  # Set default for optional fields
                
                # Check for hostname conflicts (only if hostname changed)
                if field == 'HostName' and value != original_hostname:
                    if any(server.get('HostName', '').lower() == value.lower() and server != server_to_edit for server in servers):
                        errors.append(f"Server with hostname '{value}' already exists")
                        continue
                
                server_to_edit[field] = value
            
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template('add_edit.html', server=server_to_edit, fieldnames=FIELDNAMES, action="Edit")
            
            # Write all data back to CSV (including the updated server)
            write_data(servers)
            
            flash(f"Server '{server_to_edit['HostName']}' updated successfully!", "success")
            logging.info(f"Updated server: {original_hostname} -> {server_to_edit['HostName']}")
            return redirect(url_for('index'))
        
        # For GET request, show the form pre-filled with existing server data
        return render_template('add_edit.html', server=server_to_edit, fieldnames=FIELDNAMES, action="Edit")
        
    except Exception as e:
        logging.error(f"Error editing server {hostName}: {str(e)}")
        flash(f"Error editing server: {str(e)}", "error")
        return redirect(url_for('index'))

def background_collector(cimc_ips, usernames, passwords):
    """Run the collector in background for multiple servers"""
    global collection_status
    collection_status["running"] = True
    collection_status["total"] = len(cimc_ips)
    collection_status["completed"] = 0
    collection_status["errors"] = []
    
    all_servers = []
    failed_servers = []
    skipped_servers = []
    successful_servers = []
    
    # Build a fast lookup set for duplicate detection - only read CSV once
    existing_hostnames = set()
    existing_host_urls = set()
    existing_host_ips = set()
    try:
        if os.path.exists(CSV_FILE):
            df = pd.read_csv(CSV_FILE)
            if 'HostName' in df.columns:
                existing_hostnames = set(df['HostName'].astype(str).str.lower())
            if 'Host URL' in df.columns:
                existing_host_urls = set(df['Host URL'].astype(str).str.lower())
            if 'Host IP' in df.columns:
                # Also track by IP address for more robust duplicate detection
                existing_host_ips = set(df['Host IP'].astype(str).str.lower())
    except (FileNotFoundError, pd.errors.EmptyDataError):
        existing_hostnames = set()
        existing_host_urls = set()
        existing_host_ips = set()
    
    for i, (cimc_ip, username, password) in enumerate(zip(cimc_ips, usernames, passwords)):
        try:
            collection_status["current_server"] = cimc_ip
            collection_status["last_update"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Fast duplicate check BEFORE attempting collection
            # Check if we already have this CIMC IP/hostname in our inventory
            cimc_to_check = cimc_ip.lower()
            if (cimc_to_check in existing_host_urls or 
                cimc_to_check in existing_host_ips or
                cimc_to_check in existing_hostnames):
                # This server is already in inventory, skip it
                skipped_servers.append(cimc_ip)
                collection_status["skipped"] = len(skipped_servers)
            else:
                # New server, attempt to collect data
                servers = collect_data_for_server(cimc_ip, username, password)
                if servers:
                    # Double-check for duplicates by hostname (in case hostname differs from IP)
                    server_is_duplicate = False
                    for server in servers:
                        hostname = server.get('HostName', '').lower()
                        if hostname and hostname in existing_hostnames:
                            server_is_duplicate = True
                            break
                    
                    if server_is_duplicate:
                        # Server already exists by hostname, skip it
                        skipped_servers.append(cimc_ip)
                        collection_status["skipped"] = len(skipped_servers)
                    else:
                        # Truly new server(s), add to collection
                        all_servers.extend(servers)
                        successful_servers.append(cimc_ip)
                        collection_status["successful"] = len(successful_servers)
                        # Update our lookup sets
                        for server in servers:
                            hostname = server.get('HostName', '').lower()
                            host_url = server.get('Host URL', '').lower()
                            host_ip = server.get('Host IP', '').lower()
                            if hostname:
                                existing_hostnames.add(hostname)
                            if host_url:
                                existing_host_urls.add(host_url)
                            if host_ip and host_ip != 'n/a':
                                existing_host_ips.add(host_ip)
                else:
                    # Collection failed for this server
                    failed_servers.append(cimc_ip)
                    collection_status["failed"] = len(failed_servers)
        except Exception as e:
            # Exception during collection
            failed_servers.append(cimc_ip)
            collection_status["failed"] = len(failed_servers)
            logging.error(f"Error collecting data from {cimc_ip}: {str(e)}")
        
        collection_status["completed"] += 1
    
    # Save all collected data (simple append since we already checked duplicates)
    if all_servers:
        save_to_csv_simple(all_servers, CSV_FILE)
    
    # Generate consolidated summary messages
    summary_messages = []
    successful_count = len(successful_servers)
    skipped_count = len(skipped_servers)
    failed_count = len(failed_servers)
    
    # Successful servers summary
    if successful_servers:
        summary_messages.append(f"✅ COLLECTION SUCCESSFUL ({successful_count} servers): {', '.join(successful_servers)}")
    
    # Skipped servers summary
    if skipped_servers:
        summary_messages.append(f"⏭️ SERVERS SKIPPED ({skipped_count} servers): {', '.join(skipped_servers)} - Already present in inventory")
    
    # Failed servers summary with troubleshooting
    if failed_servers:
        summary_messages.append(f"❌ COLLECTION FAILED ({failed_count} servers): {', '.join(failed_servers)}")
        summary_messages.append(
            "🔧 TROUBLESHOOTING FOR FAILED SERVERS: "
            "→ Login to CIMC web interface → Navigate to Dashboard → Admin → Communication Services → "
            "→ Enable 'Redfish Properties' → Save Changes → Wait 1-2 minutes → "
            "→ Verify user permissions in User Management → "
            "→ Test network connectivity and retry collection"
        )
    
    # Add final professional summary
    summary_messages.append(
        f"📊 COLLECTION SUMMARY: {successful_count} collected, {skipped_count} already present, {failed_count} failed (Total: {len(cimc_ips)} servers)"
    )
    
    # Update status with consolidated messages
    collection_status["errors"] = summary_messages
    collection_status["successful"] = successful_count
    collection_status["failed"] = failed_count
    collection_status["skipped"] = skipped_count
    
    # Determine final status based on results - fix the logic here
    if successful_count > 0:
        if failed_count > 0:
            final_status = "completed_partial"  # Some success, some failures
        else:
            final_status = "completed_success"  # All successful (skipped doesn't count as failure)
    elif skipped_count > 0 and failed_count == 0:
        final_status = "completed_skipped"  # All skipped, none failed
    else:
        final_status = "completed_failed"  # All failed, none successful
    
    collection_status["status"] = final_status
    collection_status["running"] = False
    collection_status["current_server"] = "Completed"
    collection_status["last_update"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

@app.route('/collect', methods=['GET', 'POST'])
def collect():
    global collection_status
    
    if request.method == 'POST':
        # Check if collection is already running
        if collection_status["running"]:
            flash("Data collection is already running!", "warning")
            return redirect(url_for('collect'))
        
        # Get form data
        if 'csv_file' in request.files and request.files['csv_file'].filename:
            # CSV file upload method
            file = request.files['csv_file']
            
            # Create a temporary file to store the uploaded CSV
            temp_fd, temp_path = tempfile.mkstemp(suffix='.csv')
            os.close(temp_fd)
            
            try:
                # Save uploaded file to temp location
                file.save(temp_path)
                
                # Read the CSV to get server details
                df = pd.read_csv(temp_path)
                
                # Check required columns
                required_columns = ['CIMC_IP', 'USERNAME', 'PASSWORD']
                if not all(col in df.columns for col in required_columns):
                    missing = [col for col in required_columns if col not in df.columns]
                    flash(f"CSV file is missing required columns: {', '.join(missing)}", "error")
                    return redirect(url_for('collect'))
                
                # Extract data
                cimc_ips = df['CIMC_IP'].tolist()
                usernames = df['USERNAME'].tolist()
                passwords = df['PASSWORD'].tolist()
                
            except Exception as e:
                flash(f"Error reading CSV file: {str(e)}", "error")
                return redirect(url_for('collect'))
            finally:
                # Clean up temp file
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                
        else:
            # Manual input method
            cimc_ip = request.form.get('cimc_ip', '').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not cimc_ip or not username or not password:
                flash("Please provide CIMC IP, username, and password", "error")
                return redirect(url_for('collect'))
            
            cimc_ips = [cimc_ip]
            usernames = [username]
            passwords = [password]
        
        # Start collection in background thread
        thread = threading.Thread(target=background_collector, 
                                 args=(cimc_ips, usernames, passwords))
        thread.daemon = True
        thread.start()
        
        flash("Data collection started in the background!", "success")
        return redirect(url_for('collect'))
    
    # For GET request, show the collection form
    return render_template('collect.html', collection_status=collection_status)

@app.route('/status')
def status():
    """Return current collection status as JSON for AJAX updates"""
    return jsonify(collection_status)

@app.route('/clear-status')
def clear_status():
    """Clear the collection status"""
    global collection_status
    collection_status["errors"] = []
    collection_status["completed"] = 0
    collection_status["total"] = 0
    collection_status["current_server"] = ""
    collection_status["last_update"] = ""
    collection_status["successful"] = 0
    collection_status["failed"] = 0
    collection_status["skipped"] = 0
    collection_status["status"] = ""
    return jsonify({"status": "cleared"})

@app.route('/delete/<hostName>')
def delete_server(hostName):
    """Delete a server from the inventory"""
    try:
        servers = read_data()
        initial_count = len(servers)
        
        # Filter out the server to delete
        updated_servers = [s for s in servers if s['HostName'] != hostName]
        
        if len(updated_servers) == initial_count:
            flash(f"Server '{hostName}' not found!", "error")
            logging.warning(f"Attempted to delete non-existent server: {hostName}")
        else:
            write_data(updated_servers)
            flash(f"Server '{hostName}' deleted successfully!", "success")
            logging.info(f"Deleted server: {hostName}")
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logging.error(f"Error deleting server {hostName}: {str(e)}")
        flash(f"Error deleting server: {str(e)}", "error")
        return redirect(url_for('index'))

@app.template_filter('parse_nic')
def parse_nic_details(nic_details):
    """Parse NIC details and return structured data for dropdown with individual cards - enhanced for remote server compatibility"""
    if not nic_details or nic_details == 'N/A' or nic_details.strip() == '':
        return []
    
    cards = []
    try:
        # Add size check for very large strings that might cause issues
        if len(nic_details) > 20000:  # 20KB limit
            logging.warning(f"Very large NIC details detected: {len(nic_details)} characters, truncating...")
            nic_details = nic_details[:20000] + "... [Data truncated for processing]"
        
        # Split by double pipes (||) to separate different network cards/adapters
        parts = nic_details.split('||') if '||' in nic_details else [nic_details]
        
        # Limit number of parts to prevent overwhelming the UI
        if len(parts) > 20:
            logging.warning(f"Large number of network adapters detected: {len(parts)}, limiting to first 20")
            parts = parts[:20]
            parts.append(f"... and {len(nic_details.split('||')) - 20} more network adapters (truncated for display)")
        
        for i, part in enumerate(parts):
            part = part.strip()
            if not part:
                continue
                
            # Skip truncation indicators
            if "more network adapters" in part and "truncated" in part:
                cards.append({
                    'id': f"card_{i}",
                    'name': part,
                    'category': 'Info',
                    'details': part,
                    'original_name': 'Truncated Info',
                    'clean_name': 'Additional Adapters',
                    'port_count': 0,
                    'connected_ports': 0,
                    'card_type': 'Info',
                    'specs': {},
                    'max_speed': 0,
                    'slot_info': '',
                    'adapter_type': 'Info'
                })
                continue
            
            try:
                # Check if this is the new enhanced format or the old format
                card_name = ""
                port_details = ""
                adapter_type = "Network Adapter"
                slot_info = ""
                
                # Pattern for enhanced format: "Adapter Type (Slot X) - Card Name: Port details"
                enhanced_pattern = r'(.*?)\s*\(Slot\s+([^)]+)\)\s*-\s*(.*?):\s*(.*)'
                enhanced_match = re.match(enhanced_pattern, part)
                
                if enhanced_match:
                    # Enhanced format
                    adapter_type = enhanced_match.group(1).strip()
                    slot_info = enhanced_match.group(2).strip()
                    card_name = enhanced_match.group(3).strip()
                    port_details = enhanced_match.group(4).strip()
                    display_name = f"{adapter_type} (Slot {slot_info}) - {card_name}"
                else:
                    # Check for old format or simpler format: "Card Name: Port details"
                    if ':' in part:
                        card_name_part = part.split(':', 1)[0].strip()
                        port_details = part.split(':', 1)[1].strip()
                        
                        # Check if card_name_part contains adapter type info
                        if ' - ' in card_name_part:
                            # Format like "VIC Adapter (Slot 1) - Cisco UCS VIC 1455"
                            parts_split = card_name_part.split(' - ', 1)
                            if '(' in parts_split[0] and ')' in parts_split[0]:
                                adapter_type = parts_split[0].split('(')[0].strip()
                                slot_match = re.search(r'\(Slot\s+([^)]+)\)', parts_split[0])
                                if slot_match:
                                    slot_info = slot_match.group(1)
                                card_name = parts_split[1].strip()
                                display_name = f"{adapter_type} (Slot {slot_info}) - {card_name}"
                            else:
                                # Simple format like "UCS VIC 1455"
                                card_name = card_name_part
                                display_name = card_name
                        else:
                            # Simple format like "UCS VIC 1455"
                            card_name = card_name_part
                            display_name = card_name
                    else:
                        # No colon, treat entire part as card name
                        card_name = part.strip()
                        display_name = card_name
                        port_details = ""
                
                # Limit individual card name length
                if len(card_name) > 100:
                    card_name = card_name[:97] + "..."
                if len(display_name) > 150:
                    display_name = display_name[:147] + "..."
                
                # Get card specifications for enhanced naming
                try:
                    card_specs = extract_card_specifications(card_name)
                except Exception:
                    card_specs = {}
                
                # Determine category based on adapter type or card name
                category = 'Network'
                card_name_upper = card_name.upper()
                card_type = 'Network'
                
                # Enhanced categorization - using exactly 3 categories
                if 'VIC' in adapter_type.upper() or 'VIC' in card_name_upper or ('CISCO' in card_name_upper and 'VIC' in card_name_upper):
                    category = 'VIC Adapter'
                    card_type = 'VIC Adapter'
                elif any(keyword in card_name_upper for keyword in ['NETWORK', 'ETHERNET', 'NIC', 'INTEL', 'BROADCOM', 'MELLANOX']) and 'VIC' not in card_name_upper:
                    category = 'Network Adapter'
                    card_type = 'Network Adapter'
                else:
                    # All other PCIe devices (storage, graphics, MLOM without VIC, etc.)
                    category = 'PCI Adapters'
                    card_type = 'PCI Adapters'
                
                # Extract port count and connection info with error handling
                port_count = 0
                connected_ports = 0
                max_speed = 0
                
                if port_details and port_details != "No port details available":
                    try:
                        # Count ports by looking for "Port" mentions
                        port_entries = [p.strip() for p in port_details.split('|') if 'Port' in p]
                        port_count = len(port_entries)
                        
                        # Count connected ports and find max speed
                        for port_entry in port_entries:
                            if 'Connected' in port_entry:
                                connected_ports += 1
                                # Extract speed
                                speed_match = re.search(r'(\d+)\s*(Mbps|Gbps)', port_entry)
                                if speed_match:
                                    speed_num = int(speed_match.group(1))
                                    if speed_match.group(2) == 'Gbps':
                                        speed_num *= 1000
                                    max_speed = max(max_speed, speed_num)
                    except Exception:
                        # If port parsing fails, continue with defaults
                        pass
                
                # Add port status info to display name
                status_info = []
                if port_count > 0:
                    status_info.append(f"{port_count} port{'s' if port_count > 1 else ''}")
                if connected_ports > 0:
                    status_info.append(f"{connected_ports} active")
                elif port_count > 0:
                    status_info.append("no active ports")
                
                # Add speed capability from card name if available
                if card_specs.get('speed_capability'):
                    status_info.append(card_specs['speed_capability'])
                
                final_display_name = display_name
                if status_info:
                    status_suffix = f" [{', '.join(status_info)}]"
                    # Ensure final name doesn't exceed reasonable length
                    if len(final_display_name + status_suffix) > 200:
                        final_display_name = final_display_name[:200-len(status_suffix)-3] + "..." + status_suffix
                    else:
                        final_display_name += status_suffix
                
                # Limit the details field to prevent oversized data
                card_details = part.strip()
                if len(card_details) > 1000:
                    card_details = card_details[:997] + "..."
                
                cards.append({
                    'id': f"card_{i}",
                    'name': final_display_name,
                    'category': category,
                    'details': card_details,
                    'original_name': card_name,
                    'clean_name': card_name,  # Store clean card name for header display
                    'port_count': port_count,
                    'connected_ports': connected_ports,
                    'card_type': card_type,
                    'specs': card_specs,
                    'max_speed': max_speed,
                    'slot_info': slot_info,
                    'adapter_type': adapter_type
                })
                
            except Exception as card_error:
                logging.warning(f"Error parsing individual network card {i}: {str(card_error)}")
                # Add a fallback card for this entry
                cards.append({
                    'id': f"card_{i}",
                    'name': f"Network Card {i+1} (Parse Error)",
                    'category': 'Network',
                    'details': part.strip()[:500] + ('...' if len(part.strip()) > 500 else ''),
                    'original_name': f'Network Card {i+1}',
                    'clean_name': f'Network Card {i+1}',
                    'port_count': 0,
                    'connected_ports': 0,
                    'card_type': 'Network',
                    'specs': {},
                    'max_speed': 0,
                    'slot_info': '',
                    'adapter_type': 'Network'
                })
                
    except Exception as e:
        logging.error(f"Error parsing NIC details: {str(e)}")
        # Fallback: create a single card with truncated details
        truncated_details = nic_details[:1000] + ('...' if len(nic_details) > 1000 else '')
        cards = [{
            'id': 'card_0',
            'name': 'Network Details (Parsing Error)',
            'category': 'Network',
            'details': truncated_details,
            'original_name': 'Network Details',
            'clean_name': 'Network Details',
            'port_count': 0,
            'connected_ports': 0,
            'card_type': 'Unknown',
            'specs': {},
            'max_speed': 0,
            'slot_info': '',
            'adapter_type': 'Network'
        }]
    
    return cards

@app.route('/api/server-details')
def get_server_details():
    """API endpoint to get server details for dynamic dropdown - enhanced for remote server compatibility"""
    try:
        hostname = request.args.get('hostname', '').strip()
        host_url = request.args.get('host_url', '').strip()
        card_id = request.args.get('card_id', '').strip()
        
        if not hostname:
            return jsonify({'error': 'Hostname parameter is required'}), 400
        
        servers = read_data()
        # First try to find by HostName (exact match)
        server = next((s for s in servers if s.get('HostName', '').strip() == hostname), None)
        
        # If not found, try to find by Host URL
        if not server:
            server = next((s for s in servers if s.get('Host URL', '').strip() == hostname), None)
        
        # If still not found and host_url is provided, try to match by host_url
        if not server and host_url:
            server = next((s for s in servers if s.get('Host URL', '').strip() == host_url), None)
        
        if not server:
            logging.warning(f"Server details requested for non-existent server. hostname: {hostname}, host_url: {host_url}")
            return jsonify({'error': 'Server not found'}), 404
        
        # Enhanced error handling for NIC details parsing
        try:
            # Parse NIC details to get all available cards
            nic_details_raw = server.get('NIC Details', '')
            
            # Check if NIC details are valid
            if not nic_details_raw or nic_details_raw.strip() == '' or nic_details_raw == 'N/A':
                return jsonify({
                    'cards': [],
                    'selected_card': None,
                    'card_name': 'No Network Cards Available',
                    'details': [],
                    'category': 'Unknown',
                    'error': 'No network card data available for this server'
                })
            
            # Add size check for large NIC details that might cause issues on remote servers
            if len(nic_details_raw) > 10000:  # 10KB limit
                logging.warning(f"Large NIC details data detected for {hostname}: {len(nic_details_raw)} characters")
                # Truncate the data and add a warning
                nic_details_raw = nic_details_raw[:10000] + "... [Data truncated due to size]"
            
            all_cards = parse_nic_details(nic_details_raw)
            
            # If parsing failed or returned empty, provide fallback
            if not all_cards:
                return jsonify({
                    'cards': [{
                        'id': 'fallback_card',
                        'name': 'Network Card Details (Raw)',
                        'category': 'Network',
                        'details': nic_details_raw[:500] + ('...' if len(nic_details_raw) > 500 else ''),
                        'original_name': 'Network Details',
                        'clean_name': 'Network Details',
                        'port_count': 0,
                        'connected_ports': 0,
                        'card_type': 'Network',
                        'specs': {},
                        'max_speed': 0,
                        'slot_info': '',
                        'adapter_type': 'Network'
                    }],
                    'selected_card': None,
                    'card_name': 'Network Details',
                    'details': [{'label': 'Raw Data', 'value': nic_details_raw[:500] + ('...' if len(nic_details_raw) > 500 else '')}],
                    'category': 'Network',
                    'warning': 'Unable to parse network card details, showing raw data'
                })
            
        except Exception as parse_error:
            logging.error(f"Error parsing NIC details for {hostname}: {str(parse_error)}")
            return jsonify({
                'cards': [],
                'selected_card': None,
                'card_name': 'Network Card Parsing Error',
                'details': [],
                'category': 'Unknown',
                'error': f'Error parsing network card data: {str(parse_error)}'
            }), 500
        
        # If card_id is specified, return details for that card
        if card_id:
            selected_card = next((card for card in all_cards if card['id'] == card_id), None)
            if selected_card:
                try:
                    # Parse the card details into structured format
                    parsed_details = parse_card_details(selected_card['details'])
                    
                    return jsonify({
                        'cards': all_cards,
                        'selected_card': selected_card,
                        'card_name': selected_card.get('clean_name', selected_card['original_name']),
                        'details': parsed_details,
                        'category': selected_card['category']
                    })
                except Exception as detail_error:
                    logging.error(f"Error parsing card details for {card_id}: {str(detail_error)}")
                    return jsonify({'error': f'Error parsing details for card {card_id}'}), 500
            else:
                return jsonify({'error': f'Card with ID {card_id} not found'}), 404
        
        # Return all cards with first one selected by default
        default_card = all_cards[0] if all_cards else None
        if default_card:
            try:
                parsed_details = parse_card_details(default_card['details'])
                
                return jsonify({
                    'cards': all_cards,
                    'selected_card': default_card,
                    'card_name': default_card.get('clean_name', default_card['original_name']),
                    'details': parsed_details,
                    'category': default_card['category']
                })
            except Exception as default_error:
                logging.error(f"Error parsing default card details: {str(default_error)}")
                return jsonify({
                    'cards': all_cards,
                    'selected_card': default_card,
                    'card_name': default_card.get('clean_name', default_card['original_name']),
                    'details': [],
                    'category': default_card['category'],
                    'error': 'Error parsing card details'
                })
        else:
            return jsonify({
                'cards': [],
                'selected_card': None,
                'card_name': 'No Network Cards',
                'details': [],
                'category': 'Unknown'
            })
            
    except Exception as e:
        logging.error(f"Error in server details API: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def parse_card_details(details_string):
    """Parse a card details string into structured format with clean, focused information"""
    if not details_string or details_string.strip() == '':
        return []
    
    parsed_details = []
    try:
        # Extract card name and port details
        card_name = ""
        port_details_raw = details_string
        slot_info = ""
        
        # Parse the enhanced format: "Adapter Type (Slot X) - Card Name: Port details"
        if ':' in details_string:
            parts = details_string.split(':', 1)
            card_name_part = parts[0].strip()
            port_details_raw = parts[1].strip()
            
            # Extract slot information from the card name part
            slot_match = re.search(r'\(Slot\s+([^)]+)\)', card_name_part)
            if slot_match:
                slot_info = slot_match.group(1)
                # Remove slot info from card name for cleaner display
                card_name = re.sub(r'\s*\(Slot\s+[^)]+\)\s*', '', card_name_part)
                # Also remove adapter type prefix if present
                if ' - ' in card_name:
                    card_name = card_name.split(' - ', 1)[1]
            else:
                card_name = card_name_part
                # Check if it's in format "Adapter Type - Card Name"
                if ' - ' in card_name:
                    parts = card_name.split(' - ', 1)
                    if len(parts) == 2:
                        card_name = parts[1]
        else:
            # No colon, treat as card name only
            card_name = details_string.strip()
        
        # Add card model as header
        parsed_details.append({
            'name': 'Device',
            'value': card_name,
            'type': 'header'
        })
        
        # Add slot information if available
        if slot_info:
            parsed_details.append({
                'name': 'Slot',
                'value': slot_info,
                'type': 'slot_info'
            })
        
        # Parse port details
        if port_details_raw and port_details_raw != "No port details available":
            # Split by pipe (|) to get individual ports
            port_parts = port_details_raw.split('|') if '|' in port_details_raw else [port_details_raw]
            
            port_details = []
            connected_count = 0
            total_ports = 0
            
            for part in port_parts:
                part = part.strip()
                if part and ':' in part:
                    # Extract port information
                    key_value = part.split(':', 1)
                    if len(key_value) == 2:
                        port_name = key_value[0].strip()
                        port_status = key_value[1].strip()
                        
                        # Only process actual port entries
                        if port_name.startswith('Port '):
                            total_ports += 1
                            
                            # Parse connection status and speed
                            connection_status = 'Unknown'
                            speed_info = ''
                            
                            if 'Connected' in port_status or 'Disconnected' in port_status:
                                connection_status = 'Connected' if 'Connected' in port_status else 'Disconnected'
                                
                                if connection_status == 'Connected':
                                    connected_count += 1
                                
                                # Extract speed information
                                speed_match = re.search(r'(\d+)\s*(Mbps|Gbps)', port_status)
                                if speed_match:
                                    speed_num = int(speed_match.group(1))
                                    speed_unit = speed_match.group(2)
                                    
                                    # Format speed display
                                    if speed_unit == 'Gbps' or (speed_unit == 'Mbps' and speed_num >= 1000):
                                        if speed_unit == 'Mbps':
                                            speed_num = speed_num // 1000
                                        speed_info = f" @ {speed_num} Gbps"
                                    else:
                                        speed_info = f" @ {speed_num} Mbps"
                            
                            # Create clean port display
                            port_value = connection_status
                            if speed_info:
                                port_value += speed_info
                            
                            port_details.append({
                                'name': port_name,
                                'value': port_value,
                                'type': 'port',
                                'status': connection_status.lower()
                            })
            
            # Add port summary
            if total_ports > 0:
                summary_text = f"{total_ports} port{'s' if total_ports > 1 else ''}"
                if connected_count > 0:
                    summary_text += f", {connected_count} connected"
                else:
                    summary_text += ", none connected"
                
                parsed_details.append({
                    'name': 'Port Summary',
                    'value': summary_text,
                    'type': 'port_summary'
                })
                
                # Add individual port details
                parsed_details.extend(port_details)
        else:
            # No port details available
            parsed_details.append({
                'name': 'Port Information',
                'value': 'No port details available',
                'type': 'info'
            })
        
        # If no structured details found, add the whole string as description
        if len(parsed_details) <= 2:  # Only header and slot info
            parsed_details.append({
                'name': 'Description',
                'value': details_string,
                'type': 'info'
            })
            
    except Exception as e:
        logging.error(f"Error parsing card details: {str(e)}")
        # Return minimal error info
        parsed_details = [{
            'name': 'Device',
            'value': 'Parse Error',
            'type': 'error'
        }, {
            'name': 'Raw Data',
            'value': details_string,
            'type': 'info'
        }]
    
    return parsed_details

def extract_card_specifications(card_name):
    """Extract card manufacturer, model, speed, and other details from the card name"""
    specs = {
        'manufacturer': None,
        'model': None,
        'port_count': None,
        'interface_type': None,
        'form_factor': None,
        'speed_capability': None
    }
    
    # List of known manufacturers
    manufacturers = {
        'cisco': 'Cisco',
        'intel': 'Intel',
        'broadcom': 'Broadcom',
        'mellanox': 'Mellanox',
        'qlogic': 'QLogic',
        'emulex': 'Emulex',
        'lsi': 'LSI',
        'nvidia': 'NVIDIA',
        'amd': 'AMD',
        'adaptec': 'Adaptec',
        'hpe': 'HPE',
        'dell': 'Dell',
        'samsung': 'Samsung',
        'micron': 'Micron',
        'seagate': 'Seagate',
        'western digital': 'Western Digital',
        'wd': 'Western Digital'
    }
    
    # Extract manufacturer
    card_lower = card_name.lower()
    for mfr_key, mfr_name in manufacturers.items():
        if mfr_key in card_lower:
            specs['manufacturer'] = mfr_name
            break
    
    # Extract model number
    model_patterns = [
        # Intel NIC models
        r'(X520|X540|X550|X710|X722|E810)',
        # Cisco VIC/MLOM models
        r'(UCSC-MLOM-[A-Za-z0-9\-]+)',
        r'(UCSC-PCIE-[A-Za-z0-9\-]+)',
        # NIC models with form factor
        r'([A-Za-z0-9]+T[0-9]+[GL]+)',  # Like X710T4L
        # PCIe device IDs
        r'([A-Za-z0-9]+-[A-Za-z0-9]+)',  # Generic hyphenated model numbers
    ]
    
    for pattern in model_patterns:
        match = re.search(pattern, card_name)
        if match:
            specs['model'] = match.group(1)
            break
    
    # Extract port count
    port_count_match = re.search(r'(\d+)[xX](\d+)', card_name)  # Formats like 2x10, 2X40
    if port_count_match:
        specs['port_count'] = port_count_match.group(1)
        
        # Also extract speed capability
        speed_num = port_count_match.group(2)
        if speed_num.isdigit():
            specs['speed_capability'] = f"{speed_num} Gbps"
    
    # Check for speed capability
    speed_patterns = [
        r'(\d+)G',  # 10G, 25G, 40G, 100G
        r'(\d+)\s*Gb',  # 10Gb, 25 Gb
        r'(\d+)\s*GbE',  # 10GbE, 25 GbE
    ]
    
    for pattern in speed_patterns:
        match = re.search(pattern, card_name)
        if match and not specs['speed_capability']:
            specs['speed_capability'] = f"{match.group(1)} Gbps"
            break
    
    # Extract interface type
    if 'RJ45' in card_name or 'BASE-T' in card_name or 'T4' in card_name or 'T2' in card_name:
        specs['interface_type'] = 'RJ45/Copper'
    elif 'SFP' in card_name or 'QSFP' in card_name or 'SPF+' in card_name or 'QSFP+' in card_name or 'QSFP28' in card_name:
        specs['interface_type'] = 'Fiber/Optical'
    elif 'FC' in card_name and ('HBA' in card_name or 'FIBER' in card_name.upper()):
        specs['interface_type'] = 'Fiber Channel'
    elif 'NVME' in card_name.upper():
        specs['interface_type'] = 'NVMe'
    elif 'SATA' in card_name.upper():
        specs['interface_type'] = 'SATA'
    elif 'SAS' in card_name.upper():
        specs['interface_type'] = 'SAS'
    
    # Extract form factor
    if 'OCP' in card_name:
        specs['form_factor'] = 'OCP'
        if '3.0' in card_name:
            specs['form_factor'] = 'OCP 3.0'
    elif 'MLOM' in card_name:
        specs['form_factor'] = 'MLOM'
    elif 'MEZZ' in card_name:
        specs['form_factor'] = 'Mezzanine'
    elif 'PCIe' in card_name or 'PCIE' in card_name:
        specs['form_factor'] = 'PCIe'
    
    return specs

# Initialize CSV file if it doesn't exist
def initialize_csv_file():
    """Initialize CSV file with proper headers if it doesn't exist"""
    if not os.path.exists(CSV_FILE):
        try:
            with open(CSV_FILE, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(FIELDNAMES)
            logging.info(f"Created empty inventory file: {CSV_FILE}")
        except Exception as e:
            logging.error(f"Error creating CSV file: {str(e)}")

# Initialize CSV file on startup
initialize_csv_file()

if __name__ == '__main__':
    # Parse command line arguments for port
    import argparse
    parser = argparse.ArgumentParser(description='CIMC Server Inventory')
    parser.add_argument('--port', type=int, default=5001, help='Port to run the application on')
    args = parser.parse_args()
    
    # Start the Flask app
    print(f"Starting CIMC Server Inventory on port {args.port}...")
    app.run(debug=True, port=args.port, host='0.0.0.0')