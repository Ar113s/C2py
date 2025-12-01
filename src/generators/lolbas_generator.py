#!/usr/bin/env python3
"""
C2PY - Professional Command & Control Framework
LOLBAS Generator Module
"""

import json
import os
from pathlib import Path

class LOLBASGenerator:
    """
    Generates LOLBAS (Living Off The Land Binaries and Scripts) payloads.
    This class reads from a JSON file containing LOLBAS definitions and
    provides methods to list available binaries and generate payloads.
    """

    def __init__(self, lolbas_data_path=None):
        """
        Initializes the LOLBASGenerator.

        Args:
            lolbas_data_path (str, optional): Path to the LOLBAS JSON data file.
                                              If None, it defaults to a file
                                              within the 'data' directory relative
                                              to the script's location.
        """
        if lolbas_data_path:
            self.lolbas_data_path = Path(lolbas_data_path)
        else:
            # Assume data file is in a 'data' directory relative to this script
            current_dir = Path(__file__).parent
            self.lolbas_data_path = current_dir.parent / "data" / "lolbas_data.json"

        self.lolbas_data = self._load_lolbas_data()

    def _load_lolbas_data(self):
        """
        Loads LOLBAS data from the JSON file.

        Returns:
            dict: A dictionary containing LOLBAS data, or an empty dict if loading fails.
        """
        if not self.lolbas_data_path.exists():
            print(f"ERROR: LOLBAS data file not found at {self.lolbas_data_path}")
            return {}
        try:
            with open(self.lolbas_data_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to decode LOLBAS JSON data: {e}")
            return {}
        except Exception as e:
            print(f"ERROR: An unexpected error occurred while loading LOLBAS data: {e}")
            return {}

    def list_available_binaries(self):
        """
        Lists all available LOLBAS binaries/scripts.

        Returns:
            list: A list of binary/script names (e.g., 'cmd.exe', 'powershell.exe').
        """
        return list(self.lolbas_data.keys())

    def get_binary_details(self, binary_name):
        """
        Retrieves details for a specific LOLBAS binary/script.

        Args:
            binary_name (str): The name of the binary/script (e.g., 'cmd.exe').

        Returns:
            dict: A dictionary containing details for the binary, or None if not found.
        """
        return self.lolbas_data.get(binary_name.lower())

    def generate_payload(self, binary_name, payload_type, lhost, lport, target_file=None):
        """
        Generates a specific LOLBAS payload for a given binary and type.

        Args:
            binary_name (str): The name of the LOLBAS binary/script.
            payload_type (str): The type of payload to generate (e.g., 'download', 'execute').
            lhost (str): The local host IP address for the callback.
            lport (int): The local port for the callback.
            target_file (str, optional): The file to download/execute for certain payloads.

        Returns:
            str: The generated LOLBAS command, or None if the payload type is not found.
        """
        binary_details = self.get_binary_details(binary_name)
        if not binary_details:
            print(f"ERROR: Binary '{binary_name}' not found in LOLBAS data.")
            return None

        payload_template = binary_details.get('payloads', {}).get(payload_type)
        if not payload_template:
            print(f"ERROR: Payload type '{payload_type}' not found for binary '{binary_name}'.")
            return None

        # Replace placeholders in the template
        payload = payload_template.replace("{lhost}", lhost)
        payload = payload.replace("{lport}", str(lport))
        if target_file:
            payload = payload.replace("{target_file}", target_file)

        return payload
    

    def get_binary_path(self, binary_name):
        """
        Retrieves the file path for a specific LOLBAS binary/script.

        Args:
            binary_name (str): The name of the binary/script (e.g., 'cmd.exe').

        Returns:
            str: The file path to the binary, or None if not found.
        """
        binary_details = self.get_binary_details(binary_name)
        if not binary_details:
            print(f"ERROR: Binary '{binary_name}' not found in LOLBAS data.")
            return None

        return binary_details.get('path')

    def get_binary_description(self, binary_name):
        """
        Retrieves the description for a specific LOLBAS binary/script.

        Args:
            binary_name (str): The name of the binary/script (e.g., 'cmd.exe').

        Returns:
            str: The description of the binary, or None if not found.
        """
        binary_details = self.get_binary_details(binary_name)
        if not binary_details:
            print(f"ERROR: Binary '{binary_name}' not found in LOLBAS data.")
            return None

        return binary_details.get('description').strip()
    
    def generate_all_payloads(self, binary_name):
        """
        Generates all available LOLBAS payloads for a given binary.

        Args:
            binary_name (str): The name of the binary/script (e.g., 'cmd.exe').

        Returns:
            list: A list of generated payloads, or an empty list if none found.
        """
        payloads = []
        binary_details = self.get_binary_details(binary_name)
        if not binary_details:
            print(f"ERROR: Binary '{binary_name}' not found in LOLBAS data.")
            return payloads

        for payload_type in binary_details.get('payloads', {}):
            payload = self.generate_payload(binary_name, payload_type, "{lhost}", "{lport}")
            if payload:
                payloads.append(payload)

        return payloads
    
if __name__ == "__main__":
    generator = LOLBASGenerator()
    print("Available LOLBAS binaries:")
    for binary in generator.list_available_binaries():
        print(f"- {binary}")

    # Example usage
    binary_name = "cmd.exe"
    payload_type = "download"
    lhost = "192.168.1.29"
    lport = 9999