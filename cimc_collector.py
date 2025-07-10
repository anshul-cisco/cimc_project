import requests
import pandas as pd
import urllib3
import sys
import argparse
import re
import socket
import ipaddress
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_ip_format(ip_string):
    """Check if a string is in valid IPv4 format (x.x.x.x)."""
    if not ip_string or not isinstance(ip_string, str):
        return False
    
    # Basic regex pattern for IPv4 address
    ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(ip_pattern, ip_string.strip())
    
    if not match:
        return False
    
    # Check that each octet is between 0 and 255
    try:
        octets = [int(match.group(i)) for i in range(1, 5)]
        return all(0 <= octet <= 255 for octet in octets)
    except ValueError:
        return False

def validate_config(cimc_ip, username, password):
    """Validate CIMC configuration parameters."""
    if not cimc_ip:
        print("ERROR: Please provide CIMC IP")
        return False
    if not username:
        print("ERROR: Please provide username")
        return False
    if not password:
        print("ERROR: Please provide password")
        return False
    return True

def collect_data_for_server(cimc_ip, username, password):
    """Collect data for a single CIMC server - simplified and working version"""
    
    try:
        print(f"🔍 Starting data collection for {cimc_ip}")
        
        # Set up session
        session = requests.Session()
        session.auth = (username, password)
        session.verify = False
        session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        base_url = f"https://{cimc_ip}/redfish/v1"
        
        # Get systems
        systems_response = session.get(f"{base_url}/Systems", timeout=30)
        if systems_response.status_code != 200:
            print(f"❌ Failed to get systems from {cimc_ip}: {systems_response.status_code}")
            return []
        
        systems_data = systems_response.json()
        if not systems_data.get('Members'):
            print(f"❌ No systems found in {cimc_ip}")
            return []
        
        # Get system info
        system_endpoint = systems_data['Members'][0]['@odata.id']
        system_response = session.get(f"https://{cimc_ip}{system_endpoint}", timeout=30)
        if system_response.status_code != 200:
            print(f"❌ Failed to get system info from {cimc_ip}: {system_response.status_code}")
            return []
        
        system_data = system_response.json()
        
        # Extract basic information
        hostname = system_data.get('HostName', system_data.get('Name', 'N/A'))
        product_name = system_data.get('Model', 'N/A')
        
        # CPU information - prioritize total cores over CPU count
        cpu_summary = system_data.get('ProcessorSummary', {})
        cpu_count = cpu_summary.get('Count', 0)
        cpu_cores = cpu_summary.get('CoreCount', 0)
        cpu_model = cpu_summary.get('Model', 'N/A')
        
        # Calculate total cores: if CoreCount is available, use it directly
        # If not available, try to calculate from individual CPU details
        if cpu_cores > 0:
            num_cpu = cpu_cores  # This is the total cores across all CPUs
        else:
            # Fallback: try to get individual CPU details to calculate total cores
            total_cores = 0
            try:
                processors_endpoint = system_data.get('Processors', {}).get('@odata.id')
                if processors_endpoint:
                    processors_response = session.get(f"https://{cimc_ip}{processors_endpoint}", timeout=30)
                    if processors_response.status_code == 200:
                        processors_data = processors_response.json()
                        for processor_member in processors_data.get('Members', []):
                            processor_response = session.get(f"https://{cimc_ip}{processor_member['@odata.id']}", timeout=30)
                            if processor_response.status_code == 200:
                                processor_data = processor_response.json()
                                # Try different field names for core count
                                # Note: TotalCores might be a string, so convert to int
                                core_count = 0
                                if 'TotalCores' in processor_data:
                                    try:
                                        core_count = int(processor_data['TotalCores'])
                                    except (ValueError, TypeError):
                                        pass
                                elif 'CoreCount' in processor_data:
                                    try:
                                        core_count = int(processor_data['CoreCount'])
                                    except (ValueError, TypeError):
                                        pass
                                elif 'ProcessorCharacteristics' in processor_data and 'CoreCount' in processor_data['ProcessorCharacteristics']:
                                    try:
                                        core_count = int(processor_data['ProcessorCharacteristics']['CoreCount'])
                                    except (ValueError, TypeError):
                                        pass
                                
                                if core_count > 0:
                                    total_cores += core_count
                        
                        if total_cores > 0:
                            num_cpu = total_cores
                        else:
                            num_cpu = cpu_count  # Final fallback to CPU count
                    else:
                        num_cpu = cpu_count  # Final fallback to CPU count
                else:
                    num_cpu = cpu_count  # Final fallback to CPU count
            except Exception as e:
                num_cpu = cpu_count  # Final fallback to CPU count
        
        # Memory information - enhanced to handle various formats
        memory_summary = system_data.get('MemorySummary', {})
        total_memory_gb = 0
        
        # Try different field names for total memory
        if 'TotalSystemMemoryGiB' in memory_summary:
            total_memory_gb = memory_summary.get('TotalSystemMemoryGiB', 0)
        elif 'TotalSystemMemoryGB' in memory_summary:
            total_memory_gb = memory_summary.get('TotalSystemMemoryGB', 0)
        elif 'TotalInstalledSystemMemoryGiB' in memory_summary:
            total_memory_gb = memory_summary.get('TotalInstalledSystemMemoryGiB', 0)
        elif 'TotalInstalledSystemMemoryGB' in memory_summary:
            total_memory_gb = memory_summary.get('TotalInstalledSystemMemoryGB', 0)
        
        # If still no memory info, try to calculate from individual DIMMs
        if total_memory_gb == 0:
            try:
                memory_endpoint = system_data.get('Memory', {}).get('@odata.id')
                if memory_endpoint:
                    memory_response = session.get(f"https://{cimc_ip}{memory_endpoint}", timeout=30)
                    if memory_response.status_code == 200:
                        memory_data = memory_response.json()
                        total_memory_bytes = 0
                        dimm_count = 0
                        
                        for dimm_member in memory_data.get('Members', []):
                            try:
                                dimm_response = session.get(f"https://{cimc_ip}{dimm_member['@odata.id']}", timeout=30)
                                if dimm_response.status_code == 200:
                                    dimm_data = dimm_response.json()
                                    # Check if DIMM is populated
                                    if dimm_data.get('Status', {}).get('State') == 'Enabled':
                                        capacity_mb = dimm_data.get('CapacityMiB', 0)
                                        if capacity_mb > 0:
                                            total_memory_bytes += capacity_mb * 1024 * 1024  # Convert MiB to bytes
                                            dimm_count += 1
                            except:
                                pass
                        
                        if total_memory_bytes > 0:
                            total_memory_gb = total_memory_bytes / (1024**3)  # Convert bytes to GiB
            except:
                pass
        
        # Format memory string with DIMM count
        if total_memory_gb > 0:
            memory_str = f"{total_memory_gb:.2f} GiB"
            
            # Try to get DIMM count
            try:
                memory_endpoint = system_data.get('Memory', {}).get('@odata.id')
                if memory_endpoint:
                    memory_response = session.get(f"https://{cimc_ip}{memory_endpoint}", timeout=30)
                    if memory_response.status_code == 200:
                        memory_data = memory_response.json()
                        dimm_count = len([m for m in memory_data.get('Members', []) if m])
                        if dimm_count > 0:
                            memory_str = f"{total_memory_gb:.2f} GiB ({dimm_count} DIMMs)"
            except:
                pass
        else:
            memory_str = "N/A"
        
        # Storage information - enhanced with multiple methods
        storage_str = "N/A"
        try:
            # Method 1: Try Storage endpoint
            storage_endpoint = system_data.get('Storage', {}).get('@odata.id')
            
            if storage_endpoint:
                storage_response = session.get(f"https://{cimc_ip}{storage_endpoint}", timeout=30)
                
                if storage_response.status_code == 200:
                    storage_data = storage_response.json()
                    total_bytes = 0
                    drive_count = 0
                    
                    for controller_member in storage_data.get('Members', []):
                        controller_response = session.get(f"https://{cimc_ip}{controller_member['@odata.id']}", timeout=30)
                        if controller_response.status_code == 200:
                            controller_data = controller_response.json()
                            drives = controller_data.get('Drives', [])
                            
                            for drive_member in drives:
                                drive_response = session.get(f"https://{cimc_ip}{drive_member['@odata.id']}", timeout=30)
                                if drive_response.status_code == 200:
                                    drive_data = drive_response.json()
                                    capacity_bytes = drive_data.get('CapacityBytes', 0)
                                    
                                    if capacity_bytes:
                                        try:
                                            total_bytes += int(capacity_bytes)
                                            drive_count += 1
                                        except:
                                            pass
                    
                    if total_bytes > 0:
                        if total_bytes >= (1024**4):  # TB
                            storage_str = f"{total_bytes / (1024**4):.2f} TB ({drive_count} drives)"
                        else:  # GB
                            storage_str = f"{total_bytes / (1024**3):.2f} GB ({drive_count} drives)"
            
            # Method 2: Try SimpleStorage endpoint if Storage failed
            if storage_str == "N/A":
                simple_storage_endpoint = system_data.get('SimpleStorage', {}).get('@odata.id')
                
                if simple_storage_endpoint:
                    simple_storage_response = session.get(f"https://{cimc_ip}{simple_storage_endpoint}", timeout=30)
                    
                    if simple_storage_response.status_code == 200:
                        simple_storage_data = simple_storage_response.json()
                        
                        for storage_member in simple_storage_data.get('Members', []):
                            storage_response = session.get(f"https://{cimc_ip}{storage_member['@odata.id']}", timeout=30)
                            if storage_response.status_code == 200:
                                storage_controller_data = storage_response.json()
                                devices = storage_controller_data.get('Devices', [])
                                
                                total_bytes = 0
                                drive_count = 0
                                
                                for device in devices:
                                    capacity_bytes = device.get('CapacityBytes', 0)
                                    if capacity_bytes:
                                        try:
                                            total_bytes += int(capacity_bytes)
                                            drive_count += 1
                                        except:
                                            pass
                                
                                if total_bytes > 0:
                                    if total_bytes >= (1024**4):  # TB
                                        storage_str = f"{total_bytes / (1024**4):.2f} TB ({drive_count} drives)"
                                    else:  # GB
                                        storage_str = f"{total_bytes / (1024**3):.2f} GB ({drive_count} drives)"
                                    break
            
            # Method 3: Try PCIe storage devices as a fallback
            if storage_str == "N/A":
                pcie_devices = system_data.get('PCIeDevices', [])
                if pcie_devices:
                    total_bytes = 0
                    drive_count = 0
                    
                    for pcie_device in pcie_devices:
                        try:
                            pcie_response = session.get(f"https://{cimc_ip}{pcie_device['@odata.id']}", timeout=30)
                            if pcie_response.status_code == 200:
                                pcie_data = pcie_response.json()
                                device_name = pcie_data.get('Name', '').lower()
                                
                                # Check if this is a storage device
                                if any(keyword in device_name for keyword in ['storage', 'sas', 'sata', 'nvme', 'hba', 'raid']):
                                    # Try to get associated storage info
                                    pcie_functions = pcie_data.get('Links', {}).get('PCIeFunction', [])
                                    for func in pcie_functions:
                                        try:
                                            func_response = session.get(f"https://{cimc_ip}{func['@odata.id']}", timeout=30)
                                            if func_response.status_code == 200:
                                                func_data = func_response.json()
                                                # Look for storage-related information
                                                storage_controllers = func_data.get('Links', {}).get('StorageControllers', [])
                                                if storage_controllers:
                                                    # This indicates a storage controller, but we need actual drive info
                                                    pass
                                        except:
                                            pass
                        except:
                            pass
                            
        except Exception as e:
            pass
        
        # Network information - comprehensive collection from multiple sources
        network_str = "N/A"
        nic_details = []
        
        try:
            # Method 1: Try NetworkInterfaces endpoint
            network_endpoint = system_data.get('NetworkInterfaces', {}).get('@odata.id')
            if network_endpoint:
                try:
                    network_response = session.get(f"https://{cimc_ip}{network_endpoint}", timeout=30)
                    if network_response.status_code == 200:
                        network_data = network_response.json()
                        
                        for nic_member in network_data.get('Members', []):
                            try:
                                nic_response = session.get(f"https://{cimc_ip}{nic_member['@odata.id']}", timeout=30)
                                if nic_response.status_code == 200:
                                    nic_data = nic_response.json()
                                    
                                    # Get adapter name and details
                                    adapter_name = nic_data.get('Name', 'Unknown NIC')
                                    adapter_id = nic_data.get('Id', '')
                                    
                                    # Try to get more detailed adapter info
                                    adapter_link = nic_data.get('Links', {}).get('NetworkAdapter', {}).get('@odata.id')
                                    if adapter_link:
                                        adapter_response = session.get(f"https://{cimc_ip}{adapter_link}", timeout=30)
                                        if adapter_response.status_code == 200:
                                            adapter_data = adapter_response.json()
                                            model = adapter_data.get('Model', adapter_data.get('Name', adapter_name))
                                            adapter_name = model
                                            
                                            # Get port information
                                            port_details = []
                                            ports_link = adapter_data.get('NetworkPorts', {}).get('@odata.id')
                                            if ports_link:
                                                ports_response = session.get(f"https://{cimc_ip}{ports_link}", timeout=30)
                                                if ports_response.status_code == 200:
                                                    ports_data = ports_response.json()
                                                    for port_member in ports_data.get('Members', []):
                                                        port_response = session.get(f"https://{cimc_ip}{port_member['@odata.id']}", timeout=30)
                                                        if port_response.status_code == 200:
                                                            port_data = port_response.json()
                                                            port_id = port_data.get('Id', '')
                                                            speed = port_data.get('CurrentLinkSpeedMbps', 0)
                                                            link_status = port_data.get('LinkStatus', 'Unknown')
                                                            
                                                            status = "Connected" if link_status == "Up" else "Disconnected"
                                                            port_detail = f"Port {port_id}: {status}, {speed} Mbps"
                                                            port_details.append(port_detail)
                                    
                                    if port_details:
                                        nic_detail = f"{adapter_name}: {' | '.join(port_details)}"
                                    else:
                                        nic_detail = f"{adapter_name}: No port details available"
                                    
                                    nic_details.append(nic_detail)
                            except:
                                pass
                except:
                    pass
            
            # Method 2: Try PCIeDevices endpoint for network cards
            pcie_devices = system_data.get('PCIeDevices', [])
            if pcie_devices:
                try:
                    for pcie_device in pcie_devices:
                        try:
                            pcie_response = session.get(f"https://{cimc_ip}{pcie_device['@odata.id']}", timeout=30)
                            if pcie_response.status_code == 200:
                                pcie_data = pcie_response.json()
                                device_name = pcie_data.get('Name', '')
                                device_id = pcie_data.get('Id', '')
                                
                                # Check if this is a network device
                                if any(keyword in device_name.lower() for keyword in ['network', 'ethernet', 'nic', 'i350', 'x710', 'e810', 'vic', 'mlom']):
                                    # Determine adapter type based on name and ID
                                    adapter_type = "Network Adapter"
                                    if 'mlom' in device_id.lower() or 'mlom' in device_name.lower():
                                        adapter_type = "MLOM Adapter"
                                    elif 'vic' in device_name.lower():
                                        adapter_type = "VIC Adapter"
                                    elif any(brand in device_name.lower() for brand in ['cisco', 'ucs']):
                                        adapter_type = "UCS Network Adapter"
                                    elif 'intel' in device_name.lower():
                                        adapter_type = "Intel Network Adapter"
                                    
                                    # Get slot/ID info
                                    slot_info = f"Slot {device_id}" if device_id else "Unknown Slot"
                                    
                                    # Try to get associated PCIeFunction for more details
                                    pcie_functions = pcie_data.get('Links', {}).get('PCIeFunction', [])
                                    port_details = []
                                    
                                    if pcie_functions:
                                        for func in pcie_functions:
                                            try:
                                                func_response = session.get(f"https://{cimc_ip}{func['@odata.id']}", timeout=30)
                                                if func_response.status_code == 200:
                                                    func_data = func_response.json()
                                                    # Try to get ethernet interface info
                                                    eth_interfaces = func_data.get('Links', {}).get('EthernetInterfaces', [])
                                                    if eth_interfaces:
                                                        for eth_interface in eth_interfaces:
                                                            try:
                                                                eth_response = session.get(f"https://{cimc_ip}{eth_interface['@odata.id']}", timeout=30)
                                                                if eth_response.status_code == 200:
                                                                    eth_data = eth_response.json()
                                                                    port_id = eth_data.get('Id', '')
                                                                    speed = eth_data.get('SpeedMbps', 0)
                                                                    link_status = eth_data.get('LinkStatus', 'Unknown')
                                                                    
                                                                    status = "Connected" if link_status == "LinkUp" else "Disconnected"
                                                                    port_detail = f"Port {port_id}: {status}, {speed} Mbps"
                                                                    port_details.append(port_detail)
                                                            except:
                                                                pass
                                            except:
                                                pass
                                    
                                    # Format the adapter details
                                    if port_details:
                                        nic_detail = f"{adapter_type} ({slot_info}) - {device_name}: {' | '.join(port_details)}"
                                    else:
                                        nic_detail = f"{adapter_type} ({slot_info}) - {device_name}: No port details available"
                                    
                                    # Avoid duplicates
                                    if not any(device_name in existing for existing in nic_details):
                                        nic_details.append(nic_detail)
                        except:
                            pass
                except:
                    pass
            
            # Method 3: Try EthernetInterfaces endpoint as fallback
            if not nic_details:
                try:
                    ethernet_endpoint = system_data.get('EthernetInterfaces', {}).get('@odata.id')
                    if ethernet_endpoint:
                        ethernet_response = session.get(f"https://{cimc_ip}{ethernet_endpoint}", timeout=30)
                        if ethernet_response.status_code == 200:
                            ethernet_data = ethernet_response.json()
                            
                            for eth_member in ethernet_data.get('Members', []):
                                try:
                                    eth_response = session.get(f"https://{cimc_ip}{eth_member['@odata.id']}", timeout=30)
                                    if eth_response.status_code == 200:
                                        eth_data = eth_response.json()
                                        
                                        interface_name = eth_data.get('Name', 'Unknown Interface')
                                        interface_id = eth_data.get('Id', '')
                                        speed = eth_data.get('SpeedMbps', 0)
                                        link_status = eth_data.get('LinkStatus', 'Unknown')
                                        
                                        status = "Connected" if link_status == "LinkUp" else "Disconnected"
                                        nic_detail = f"Ethernet Interface {interface_id} - {interface_name}: {status}, {speed} Mbps"
                                        nic_details.append(nic_detail)
                                except:
                                    pass
                except:
                    pass
            
            # Format final network string
            if nic_details:
                network_str = " || ".join(nic_details)
            else:
                network_str = "N/A"
                
        except Exception as e:
            network_str = "N/A"
        
        # OS information
        os_str = "N/A"
        try:
            oem_data = system_data.get('Oem', {}).get('Cisco', {})
            os_str = oem_data.get('OperatingSystem', 'N/A')
        except:
            pass
        
        # Host IP - try to resolve
        host_ip = "N/A"
        try:
            if not is_valid_ip_format(cimc_ip):
                host_ip = socket.gethostbyname(cimc_ip)
            else:
                host_ip = cimc_ip
        except:
            pass
        
        # Build server data
        server_data = {
            "HostName": hostname,
            "Product Name": product_name,
            "No. of CPU": num_cpu,
            "Type of CPU": cpu_model,
            "Memory": memory_str,
            "Disk Size": storage_str,
            "NIC Details": network_str,
            "OS": os_str,
            "Host URL": cimc_ip,
            "Host IP": host_ip
        }
        
        print(f"✅ Successfully collected data for {hostname}")
        return [server_data]
    
    except Exception as e:
        print(f"❌ Error collecting data for {cimc_ip}: {e}")
        return []

def collect_from_csv(csv_file):
    """Collect data from CIMC servers listed in a CSV file."""
    all_servers = []
    try:
        df = pd.read_csv(csv_file)
        required_columns = ['CIMC_IP', 'USERNAME', 'PASSWORD']
        
        # Check if all required columns exist
        if not all(col in df.columns for col in required_columns):
            missing = [col for col in required_columns if col not in df.columns]
            print(f"Error: CSV file missing required columns: {', '.join(missing)}")
            print(f"Required columns are: {', '.join(required_columns)}")
            return []
        
        # Process each row in the CSV
        for index, row in df.iterrows():
            cimc_ip = row['CIMC_IP']
            username = row['USERNAME']
            password = row['PASSWORD']
            
            print(f"📡 Processing {index+1}/{len(df)}: {cimc_ip}")
            
            if validate_config(cimc_ip, username, password):
                servers = collect_data_for_server(cimc_ip, username, password)
                all_servers.extend(servers)
            else:
                print(f"❌ Skipping {cimc_ip} - invalid configuration")
        
        return all_servers
    
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return []

def save_to_csv(servers, csv_file="cimc_server_inventory.csv"):
    """Save collected server data to CSV file with smart update handling."""
    if not servers:
        print("No data to save.")
        return False
    
    # Only include columns we actually need
    columns = [
        "HostName", "Product Name", "No. of CPU", "Type of CPU", "Memory", 
        "Disk Size", "NIC Details", "OS", "Host URL", "Host IP"
    ]

    new_df = pd.DataFrame(servers)
    
    # Ensure all required columns exist, fill missing with 'N/A'
    for col in columns:
        if col not in new_df.columns:
            new_df[col] = 'N/A'
    
    # Select only the required columns
    new_df = new_df[columns]

    try:
        # Check if file exists
        try:
            existing_df = pd.read_csv(csv_file)
            
            # Track what happened with each server
            new_servers = []
            updated_servers = []
            unchanged_servers = []
            
            # Process each new server
            for _, new_server in new_df.iterrows():
                hostname = new_server['HostName']
                host_url = new_server['Host URL']
                
                # Check if server already exists (match by both HostName and Host URL)
                existing_match = existing_df[
                    (existing_df['HostName'] == hostname) & 
                    (existing_df['Host URL'] == host_url)
                ]
                
                if len(existing_match) > 0:
                    # Server exists, check if data has changed
                    existing_server = existing_match.iloc[0]
                    
                    # Compare all fields to see if there are any changes
                    has_changes = False
                    changes = []
                    
                    for col in columns:
                        old_value = str(existing_server[col]).strip()
                        new_value = str(new_server[col]).strip()
                        
                        if old_value != new_value:
                            has_changes = True
                            changes.append(f"{col}: '{old_value}' -> '{new_value}'")
                    
                    if has_changes:
                        # Update the existing server in place with proper type handling
                        mask = (existing_df['HostName'] == hostname) & (existing_df['Host URL'] == host_url)
                        for col in columns:
                            # Ensure proper data types to avoid pandas warnings
                            value = new_server[col]
                            if value is None or str(value).lower() == 'nan' or value == '':
                                value = 'N/A'
                            existing_df.loc[mask, col] = value
                        
                        updated_servers.append({
                            'hostname': hostname,
                            'host_url': host_url,
                            'changes': changes
                        })
                        print(f"🔄 UPDATED: {hostname}")
                    else:
                        unchanged_servers.append({
                            'hostname': hostname,
                            'host_url': host_url
                        })
                else:
                    # New server, add to existing dataframe
                    existing_df = pd.concat([existing_df, new_server.to_frame().T], ignore_index=True)
                    new_servers.append({
                        'hostname': hostname,
                        'host_url': host_url
                    })
                    print(f"➕ ADDED: {hostname}")
            
            # Save the updated dataframe
            existing_df.to_csv(csv_file, index=False)
            
            # Print summary
            print(f"\n📊 SUMMARY: {len(new_servers)} added, {len(updated_servers)} updated, {len(unchanged_servers)} unchanged")
                    
        except (FileNotFoundError, pd.errors.EmptyDataError):
            # If file doesn't exist or is empty, save new data
            new_df.to_csv(csv_file, index=False)
            print(f"✅ Created {csv_file} with {len(servers)} server(s)")
        
        return True
        
    except Exception as e:
        print(f"Error saving CSV file: {e}")
        return False



def main():
    """Main function to collect data and save to CSV."""
    parser = argparse.ArgumentParser(description='CIMC Server Inventory Data Collection Tool')
    
    # Create a mutually exclusive group for input method
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument('-s', '--single', action='store_true', 
                            help='Collect data from a single CIMC server')
    input_group.add_argument('-c', '--csv', type=str, 
                            help='Path to CSV file containing CIMC server details')
    
    # Arguments for single server mode
    parser.add_argument('-i', '--ip', type=str, default="",
                       help='CIMC IP address (required with -s)')
    parser.add_argument('-u', '--username', type=str, default="",
                       help='CIMC username (required with -s)')
    parser.add_argument('-p', '--password', type=str, default="",
                       help='CIMC password (required with -s)')
    
    # Output file
    parser.add_argument('-o', '--output', type=str, default="cimc_server_inventory.csv",
                       help='Output CSV file path (default: cimc_server_inventory.csv)')
    
    args = parser.parse_args()
    
    # Check if required arguments are provided for data collection
    if not args.single and not args.csv:
        parser.error("one of the arguments -s/--single -c/--csv is required for data collection")
    
    print("=" * 60)
    print("CIMC Server Inventory Data Collection Tool")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    collected_data = []
    
    if args.single:
        # Collect data from a single CIMC server
        if validate_config(args.ip, args.username, args.password):
            collected_data = collect_data_for_server(args.ip, args.username, args.password)
        else:
            print("❌ Configuration validation failed")
            sys.exit(1)
    
    elif args.csv:
        # Collect data from CIMC servers listed in CSV file
        collected_data = collect_from_csv(args.csv)
    
    if collected_data:
        save_to_csv(collected_data, args.output)
        print(f"\n✅ Collection complete: {len(collected_data)} servers processed")
    else:
        print("❌ No data collected - check connectivity and credentials")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print(f"✅ Collection completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

if __name__ == "__main__":
    main()
