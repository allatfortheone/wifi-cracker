import pyfiglet
import setup

def print_banner():
    ascii_banner = pyfiglet.figlet_format("Tejas")
    print(ascii_banner)

def show_menu():
    print("1. Enable monitor mode")
    print("2. Scan for WiFi networks")
    print("3. WiFi Bruteforce Attack")
    print("4. Fake Authentication Attack")
    print("5. Deauthentication Attack")
    print("6. Crack Password from Capture File")
    print("7. Exit")

def main():
    print_banner()
    iface = input("Enter the WiFi interface (e.g., wlan0): ")
    while True:
        show_menu()
        choice = input("Enter your choice: ")
        
        if choice == '1':
            setup.monitor_mode(iface)
        elif choice == '2':
            setup.scan_networks(iface)
        elif choice == '3':
            essid = input("Enter the ESSID of the target network: ")
            password = input("Enter the password to try: ")
            setup.wifi_bruteforce(iface, essid, password)
        elif choice == '4':
            bssid = input("Enter the BSSID of the target network: ")
            client = input("Enter the MAC address of the client: ")
            setup.start_fake_auth(iface, bssid, client)
        elif choice == '5':
            bssid = input("Enter the BSSID of the target network: ")
            setup.start_deauth(iface, bssid)
        elif choice == '6':
            cap_file = input("Enter the path to the capture file: ")
            wordlist = input("Enter the path to the wordlist file: ")
            setup.crack_password(cap_file, wordlist)
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
