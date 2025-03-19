import setup

def main():
    interface = None
    monitor_interface = None
    handshake_file = None
    target_bssid = None  # Store the BSSID for cracking
    capture_proc = None  # Store the capture process to manage it

    while True:
        print("\nWiFi Pentesting Tool")
        print("1. Enable Monitor Mode")
        print("2. Scan Networks")
        print("3. Capture Handshake")
        print("4. Deauth Attack")
        print("5. Crack Handshake")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            if not interface:
                interface = input("Enter wireless interface (e.g., wlan0): ")
            monitor_interface = setup.start_monitor_mode(interface)
            if not monitor_interface:
                interface = None  # Reset if failed

        elif choice == "2":
            if monitor_interface:
                setup.scan_networks(monitor_interface)
            else:
                print("[-] Enable monitor mode first")

        elif choice == "3":
            if monitor_interface:
                bssid = input("Enter target BSSID: ")
                channel = input("Enter target channel: ")
                output_file = input("Enter output file name (e.g., capture): ")
                # Terminate any existing capture process
                if capture_proc:
                    capture_proc.terminate()
                    print("[+] Stopped previous capture")
                capture_proc = setup.capture_handshake(monitor_interface, bssid, channel, output_file)
                target_bssid = bssid  # Store BSSID for cracking
                handshake_file = f"{output_file}-01.cap"  # Assume first capture file
                print(f"[+] Capturing to {handshake_file}. Press Ctrl+C to stop when handshake is captured.")
            else:
                print("[-] Enable monitor mode first")

        elif choice == "4":
            if monitor_interface:
                bssid = input("Enter target BSSID: ")
                client = input("Enter client MAC (or press Enter to skip): ")
                setup.deauth_attack(monitor_interface, bssid, client if client else None)
            else:
                print("[-] Enable monitor mode first")

        elif choice == "5":
            if not handshake_file or not target_bssid:
                print("[-] Capture a handshake first")
            else:
                wordlist = input("Enter path to wordlist: ")
                setup.crack_handshake(handshake_file, wordlist, target_bssid)

        elif choice == "6":
            if capture_proc:
                capture_proc.terminate()
                print("[+] Stopped capture process")
            if monitor_interface:
                setup.stop_monitor_mode(monitor_interface)
            print("[+] Exiting")
            break

        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()
