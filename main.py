import pyfiglet
import setup
import os
import sys

def print_banner():
    print(pyfiglet.figlet_format("WiFi Pentest Tool"))

def show_menu():
    print("\n1. Enable Monitor Mode")
    print("2. Scan Networks")
    print("3. Capture Handshake")
    print("4. Perform Deauth Attack")
    print("5. Crack Handshake")
    print("6. Exit")

def main():
    if os.geteuid() != 0:
        print("[-] Requires root privileges. Run with sudo.")
        sys.exit(1)
        
    print_banner()
    iface = input("[+] Enter wireless interface (e.g. wlan0): ")
    mon_iface = None
    handshake_file = None
    
    while True:
        show_menu()
        choice = input("[+] Select option: ")
        
        if choice == '1':
            mon_iface = setup.enable_monitor_mode(iface)
            if mon_iface:
                iface = mon_iface
                
        elif choice == '2':
            if not mon_iface:
                print("[-] Enable monitor mode first!")
                continue
            setup.scan_networks(iface)
            
        elif choice == '3':
            if not mon_iface:
                print("[-] Enable monitor mode first!")
                continue
            bssid = input("[+] Enter BSSID: ").strip()
            channel = input("[+] Enter channel: ").strip()
            handshake_file = input("[+] Enter output filename: ").strip()
            setup.capture_handshake(iface, bssid, channel, handshake_file)
            print("[+] Capturing handshake...")
            
        elif choice == '4':
            if not mon_iface:
                print("[-] Enable monitor mode first!")
                continue
            bssid = input("[+] Enter BSSID: ").strip()
            client = input("[+] Enter client MAC (or Enter for broadcast): ").strip()
            setup.deauth_attack(iface, bssid, client if client else 'FF:FF:FF:FF:FF:FF')
            
        elif choice == '5':
            if not handshake_file:
                print("[-] Capture handshake first!")
                continue
            wordlist = input("[+] Enter wordlist path: ").strip()
            if not os.path.exists(wordlist):
                print("[-] Wordlist file not found!")
                continue
            setup.crack_handshake(handshake_file, wordlist)
            
        elif choice == '6':
            print("[+] Exiting...")
            subprocess.run(['sudo', 'airmon-ng', 'stop', iface], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sys.exit(0)
            
        else:
            print("[-] Invalid option!")

if __name__ == "__main__":
    main()
