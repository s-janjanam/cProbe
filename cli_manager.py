#!/usr/bin/env python3

import sys
import os
from datetime import datetime
from HelperFunctions import MyLogger, get_setting, set_setting

class ProbeCliManager:
    def __init__(self):
        self.logger = MyLogger("cprobe_cli", console=True)
        self.settings = self.load_settings()

    def load_settings(self):
        # Load all settings under 'nprobe'
        return get_setting('nprobe', default={})

    def save_settings(self):
        # Save all 'nprobe' settings
        set_setting(self.settings, 'nprobe')

    def print_header(self):
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        user = os.getenv('USER', 'unknown')
        print(f"\nCurrent Date and Time (UTC): {current_time}")
        print(f"Current User's Login: {user}")
        print("-" * 50)

    def print_menu(self):
        print("\ncProbe Controller Menu")
        print("1. Show Current Settings")
        print("2. Configure Settings")
        print("3. Save Settings")
        print("4. Exit")
        print("-" * 50)

    def show_settings(self):
        import json
        print("\nCurrent nProbe Settings:")
        print(json.dumps(self.settings, indent=2))
        print("-" * 50)

    def configure_settings(self):
        while True:
            print("\nConfiguration Options:")
            print("1.  Set Interface")
            print("2.  Set Target (Collector IP:Port)")
            print("3.  Set Flow Template")
            print("4.  Set Flow Version")
            print("5.  Set Sample Rate")
            print("6.  Set Idle Timeout")
            print("7.  Set Lifetime Timeout")
            print("8.  Set Debug Level")
            print("9.  Set Aggregation")
            print("10. Return to Main Menu")

            choice = input("\nEnter choice (1-10): ").strip()

            # Navigate config structure as per config/config.json
            general = self.settings.get('general', {})
            flow_export = self.settings.get('flow_export', {})
            flow_processing = self.settings.get('flow_processing', {})
            templates = self.settings.get('templates', {})
            logging_cfg = self.settings.get('logging', {})

            if choice == '1':
                interface = input("Enter interface name: ").strip()
                self.settings.setdefault('capture', {})['interface'] = interface

            elif choice == '2':
                collector_ip = input("Enter collector IP: ").strip()
                try:
                    collector_port = int(input("Enter collector port: ").strip())
                except ValueError:
                    print("Invalid port")
                    continue
                self.settings.setdefault('flow_export', {})['collector_ip'] = collector_ip
                self.settings.setdefault('flow_export', {})['collector_port'] = collector_port

            elif choice == '3':
                custom_template = input("Enter custom template string: ").strip()
                self.settings.setdefault('templates', {})['custom_template'] = custom_template
                use_custom = input("Use custom template? (y/n): ").strip().lower() == 'y'
                self.settings.setdefault('templates', {})['use_custom_template'] = use_custom

            elif choice == '4':
                try:
                    version = int(input("Enter flow version (5, 9, or 10): ").strip())
                    self.settings.setdefault('flow_export', {})['netflow_version'] = version
                except ValueError:
                    print("Invalid flow version")

            elif choice == '5':
                try:
                    pkt = int(input("Enter packet sampling rate: ").strip())
                    self.settings.setdefault('flow_processing', {})['packet_sampling_rate'] = pkt
                except ValueError:
                    print("Invalid sample rate")

            elif choice == '6':
                try:
                    timeout = int(input("Enter idle timeout (seconds): ").strip())
                    self.settings.setdefault('flow_export', {})['inactive_timeout'] = timeout
                except ValueError:
                    print("Invalid timeout value")

            elif choice == '7':
                try:
                    timeout = int(input("Enter lifetime timeout (seconds): ").strip())
                    self.settings.setdefault('flow_export', {})['active_timeout'] = timeout
                except ValueError:
                    print("Invalid timeout value")

            elif choice == '8':
                level = input("Enter debug level (debug, info, warning, error): ").strip().lower()
                self.settings.setdefault('logging', {})['log_level'] = level

            elif choice == '9':
                agg = input("Enter aggregation string: ").strip()
                self.settings.setdefault('flow_processing', {})['flow_export_policy'] = agg

            elif choice == '10':
                break

            else:
                print("Invalid choice")

    def run(self):
        while True:
            self.print_header()
            self.print_menu()
            choice = input("\nEnter choice (1-4): ").strip()
            if choice == '1':
                self.show_settings()
            elif choice == '2':
                self.configure_settings()
            elif choice == '3':
                self.save_settings()
                print("Settings saved to config file.")
            elif choice == '4':
                print("Exiting...")
                break
            else:
                print("Invalid choice")

if __name__ == "__main__":
    try:
        manager = ProbeCliManager()
        manager.run()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)
