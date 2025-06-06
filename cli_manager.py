#!/usr/bin/env python3

import sys
import os
from datetime import datetime
from cprobe_control import cProbeControl 
from helper_functions import MyLogger

class ProbeCliManager:
    def __init__(self):
        self.logger = MyLogger("cprobe_cli", console=True)
        self.controller = cProbeControl(None, self.logger)

    def print_header(self):
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        user = os.getenv('USER', 'unknown')
        print(f"\nCurrent Date and Time (UTC): {current_time}")
        print(f"Current User's Login: {user}")
        print("-" * 50)

    def print_menu(self):
        print("\ncProbe Controller Menu")
        print("1. Start nProbe")
        print("2. Stop nProbe")
        print("3. Restart nProbe")
        print("4. Toggle Flow Lock")
        print("0. Configure Settings")
        print("5. Exit")
        print(f"\nCurrent Status: {self.controller.get_status()}")
        print(f"Flow Lock: {'Enabled' if self.controller.lock else 'Disabled'}")

    def configure_settings(self):
        while True:
            print("\nConfiguration Options:")
            print("1.  Set Interface")
            print("2.  Set Target")
            print("3.  Set Flow Template")
            print("4.  Set Flow Version")
            print("5.  Set Sample Rate")
            print("6.  Set Idle Timeout")
            print("7.  Set Lifetime Timeout")
            print("8.  Set Debug Level")
            print("9.  Set Aggregation")
            print("10. Set Bi-directional Mode")
            print("11. Return to Main Menu")

            choice = input("\nEnter choice (1-11): ")

            if choice == '1':
                interface = input("Enter interface name: ")
                self.controller.set_interface(interface)
            
            elif choice == '2':
                target = input("Enter target (IP:port): ")
                self.controller.set_target(target)
            
            elif choice == '3':
                template = input("Enter flow template: ")
                self.controller.set_template(template)
            
            elif choice == '4':
                version = input("Enter flow version (5, 9, or 10): ")
                try:
                    self.controller.set_flow_version(int(version))
                except ValueError:
                    print("Invalid version number")
            
            elif choice == '5':
                try:
                    pkt = int(input("Enter packet rate: "))
                    flow_col = int(input("Enter flow collection rate: "))
                    flow_exp = int(input("Enter flow export rate: "))
                    self.controller.set_sample_rate(pkt, flow_col, flow_exp)
                except ValueError:
                    print("Invalid sample rate values")
            
            elif choice == '6':
                try:
                    timeout = int(input("Enter idle timeout (seconds): "))
                    self.controller.set_timeouts(idle_timeout=timeout)
                except ValueError:
                    print("Invalid timeout value")
            
            elif choice == '7':
                try:
                    timeout = int(input("Enter lifetime timeout (seconds): "))
                    self.controller.set_timeouts(lifetime_timeout=timeout)
                except ValueError:
                    print("Invalid timeout value")
            
            elif choice == '8':
                try:
                    level = int(input("Enter debug level (1-3): "))
                    self.controller.debug_level = level
                except ValueError:
                    print("Invalid debug level")
            
            elif choice == '9':
                agg = input("Enter aggregation string (format: VLAN/proto/IP/port/TOS/SCTP/exporter): ")
                self.controller.aggregation = agg
            
            elif choice == '10':
                try:
                    mode = int(input("Enter bi-directional mode (0-2): "))
                    self.controller.bi_directional = mode
                except ValueError:
                    print("Invalid mode value")
            
            elif choice == '11':
                break
            
            else:
                print("Invalid choice")

    def toggle_lock(self):
        current = self.controller.lock
        self.controller.lock = not current
        print(f"Flow lock {'enabled' if not current else 'disabled'}")

    def run(self):
        while True:
            self.print_header()
            self.print_menu()
            
            choice = input("\nEnter choice (0-5): ")

            if choice == '0':
                self.configure_settings()
            
            elif choice == '1':
                print("Starting nProbe...")
                self.controller.start()
            
            elif choice == '2':
                print("Stopping nProbe...")
                self.controller.stop()
            
            elif choice == '3':
                print("Restarting nProbe...")
                self.controller.restart()
            
            elif choice == '4':
                self.toggle_lock()
            
            elif choice == '5':
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
