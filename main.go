package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type IPScanResult struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

const (
	green  = "\033[32m"
	blue   = "\033[34m"
	yellow = "\033[33m"
	red    = "\033[31m"
	cyan   = "\033[36m"
	white  = "\033[97m"
	reset  = "\033[0m"
)

var themeColor = red

func main() {
	printBanner()
	scanner := bufio.NewScanner(os.Stdin)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for range signalChan {
			if !showMode {
				os.Exit(0)
			}
		}
	}()

	for {
		fmt.Print(getPrompt())
		if !scanner.Scan() {
			continue
		}
		raw := scanner.Text()

		if raw == "\x1b[A" && len(commandHistory) > 0 {
			historyIndex--
			if historyIndex < 0 {
				historyIndex = 0
			}
			fmt.Println(commandHistory[historyIndex])
			continue
		}

		input := strings.TrimSpace(raw)

		if input != "" {
			commandHistory = append(commandHistory, input)
			historyIndex = len(commandHistory)
		}

		if input == "exit" {
			fmt.Println("Bytar is shutting down...")
			return
		}

		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "mon ") {
			showMode = true
			ctx, cancel := context.WithCancel(context.Background())

			go func() {
				<-signalChan
				if showMode {
					fmt.Println("\nStopping traffic monitoring...")
					cancel()
					showMode = false
				}
			}()

			targetIP := strings.TrimSpace(strings.TrimPrefix(input, "mon "))

			fmt.Println("Press CTRL+C twice to stop monitoring.")
			fmt.Printf("%sMonitoring traffic to/from IP: %s%s\n", cyan, targetIP, reset)
			fmt.Printf("%s%s%s\n", cyan, strings.Repeat("-", 80), reset)
			fmt.Printf("%s%-15s %-10s %-20s %-8s %-20s %-8s %-10s%s\n", white, "Time", "Direction", "Source", "S-Port", "Destination", "D-Port", "Protocol", reset)
			fmt.Printf("%s%s%s\n", cyan, strings.Repeat("-", 80), reset)

			devices, err := pcap.FindAllDevs()
			if err != nil {
				fmt.Println("Error finding devices:", err)
				continue
			}

			for _, device := range devices {
				handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
				if err != nil {
					fmt.Println("Error opening device:", err)
					continue
				}
				go monitorTraffic(ctx, handle, device.Name, targetIP)
			}

			<-ctx.Done()
			showMode = false
			continue
		}

		if strings.HasPrefix(input, "scan ") {
			ip := strings.TrimSpace(strings.TrimPrefix(input, "scan "))
			scanIP(ip)
			continue
		}

		if strings.HasPrefix(input, "theme ") {
			color := strings.TrimSpace(strings.TrimPrefix(input, "theme "))
			switch color {
			case "red":
				themeColor = red
			case "green":
				themeColor = green
			case "blue":
				themeColor = blue
			default:
				fmt.Println("Invalid theme color. Use: red, green, or blue.")
			}
			continue
		}

		switch input {
		case "clear":
			clearScreen()
		case "banner":
			printBanner()
		case "help":
			showHelp()
		case "connections":
			showEstablishedConnections()
		case "history":
			for i, cmd := range commandHistory {
				fmt.Printf("[%d] %s\n", i+1, cmd)
			}
		case "firewall":
			firewallStatus()
		case "wifipass":
			PrintWifiPasswords()
		case "services":
			runningProcesses()
		case "lports":
			listeningPorts()
		default:
			fmt.Println("command is missing or incorrect")
		}
	}
}

func getPrompt() string {
	return themeColor + "Bytar # " + reset
}

func printBanner() {
	clearScreen()
	fmt.Println(themeColor + `

  ____  ____        _              ____  
 / / / | __ ) _   _| |_ __ _ _ __  \ \ \ 
/ / /  |  _ \| | | | __/ _' | '__|  \ \ \
\ \ \  | |_) | |_| | || (_| | |     / / /
 \_\_\ |____/ \__, |\__\__,_|_|    /_/_/ 
              |___/                                                           

` + reset)
	fmt.Println("Welcome to Bytar! Type 'help' to help menu and type 'exit' to quit.")
}

type IPInfo struct {
	Org      string `json:"org"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
}

func runningProcesses() {
	var cmd *exec.Cmd

	cmd = exec.Command("powershell", "/c", "Get-Service | Where-Object { $_.Status -eq \"Running\" }")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running Get-Service:", err)
		return
	}

	fmt.Println(green + string(output) + reset)
}

func listeningPorts() {
	var cmd *exec.Cmd

	cmd = exec.Command("powershell", "/c", "netstat -an | findstr LISTENING")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running netstat:", err)
		return
	}

	fmt.Println(green + string(output) + reset)
}

func getIPInfo(ip string) (*IPInfo, error) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func scanIP(ip string) {
	url := "https://ipinfo.io/" + ip + "/json"
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Request error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Status Code:", resp.StatusCode)
	fmt.Println("Status Description:", resp.Status)

	var result IPScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Error decoding response:", err)
		return
	}

	fmt.Println("IP:        ", result.IP)
	fmt.Println("City:      ", result.City)
	fmt.Println("Country:   ", result.Country)
	fmt.Println("Location:  ", result.Loc)
	fmt.Println("Org:       ", result.Org)
	fmt.Println("Postal:    ", result.Postal)
	fmt.Println("Timezone:  ", result.Timezone)
}

func clearScreen() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func extractIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return strings.Split(address, ":")[0]
	}
	return host
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func showEstablishedConnections() {
	var cmd *exec.Cmd

	cmd = exec.Command("cmd", "/c", "netstat -ano | findstr ESTABLISHED")

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running netstat:", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		fmt.Println("No ESTABLISHED connections found.")
		return
	}

	fmt.Println()
	fmt.Printf("%s%-8s%s %s%-22s%s %s%-22s%s %s%-10s%s %s%-45s%s %s%-20s%s\n",
		cyan, "Type", reset,
		green, "Local IP:Port", reset,
		yellow, "Remote IP:Port", reset,
		red, "Country", reset,
		blue, "Org", reset,
		white, "Hostname", reset,
	)
	fmt.Println(green, strings.Repeat("-", 155), reset)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr := fields[1]  // IP:Port
		remoteAddr := fields[2] // IP:Port

		remoteIP := extractIP(remoteAddr)
		if remoteIP == "" {
			continue
		}

		info, err := getIPInfo(remoteIP)
		if err != nil {
			info = &IPInfo{Org: "-", Hostname: "-", Country: "-"}
		}

		fmt.Printf("%s%-8s%s %s%-22s%s %s%-22s%s %s%-10s%s %s%-45s%s %s%-20s%s\n",
			cyan, fields[0], reset,
			green, localAddr, reset,
			yellow, remoteAddr, reset,
			red, info.Country, reset,
			blue, info.Org, reset,
			white, info.Hostname, reset,
		)
	}
	fmt.Println(green, strings.Repeat("-", 155), reset)
}

func showHelp() {
	fmt.Println(themeColor + "\nAvailable Commands:\n" + reset)

	fmt.Printf("%shelp%s         : %sShow this help menu\n", themeColor, reset, white)
	fmt.Printf("%sconnections%s  : %sList established TCP connections with IP info\n", themeColor, reset, white)
	fmt.Printf("%sscan <ip>%s    : %sScan an IP and show geo and network info\n", themeColor, reset, white)
	fmt.Printf("%smon <ip>%s     : %sMonitor the packets of between your device and <ip> \n", themeColor, reset, white)
	fmt.Printf("%shistory%s      : %sShow command history\n", themeColor, reset, white)
	fmt.Printf("%sfirewall%s     : %sShow Windows Firewall status\n", themeColor, reset, white)
	fmt.Printf("%swifipass%s     : %sShow saved Wi-Fi passwords\n", themeColor, reset, white)
	fmt.Printf("%sservices%s     : %sShow running Windows services\n", themeColor, reset, white)
	fmt.Printf("%slports%s       : %sShow listening ports\n", themeColor, reset, white)
	fmt.Printf("%sbanner%s       : %sShow the Bytar banner\n", themeColor, reset, white)
	fmt.Printf("%sclear%s        : %sClear the terminal screen\n", themeColor, reset, white)
	fmt.Printf("%stheme <color>%s: %sChange output theme (red, green, blue)\n", themeColor, reset, white)
	fmt.Printf("%sexit%s         : %sExit the program\n\n", themeColor, reset, white)
}

func firewallStatus() {
	var cmd *exec.Cmd
	cmd = exec.Command("cmd", "/c", "netsh advfirewall show allprofiles")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running netsh:", err)
		return
	}
	fmt.Println(green, string(output), reset)
}

func PrintWifiPasswords() {

	cmdProfiles := exec.Command("powershell", "-Command", "netsh wlan show profiles")
	var outProfiles bytes.Buffer
	cmdProfiles.Stdout = &outProfiles
	err := cmdProfiles.Run()
	if err != nil {
		fmt.Println("Failed to retrieve profiles:", err)
		return
	}

	lines := strings.Split(outProfiles.String(), "\n")
	var ssids []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "All User Profile") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				ssid := strings.TrimSpace(parts[1])
				ssids = append(ssids, ssid)
			}
		}
	}

	fmt.Printf("\n%-30s | %-30s\n", "SSID", "Password")
	fmt.Println(green, strings.Repeat("-", 65), reset)

	for _, ssid := range ssids {
		cmdPassword := exec.Command("powershell", "-Command", fmt.Sprintf("netsh wlan show profile name=\"%s\" key=clear", ssid))
		var outPass bytes.Buffer
		cmdPassword.Stdout = &outPass
		err := cmdPassword.Run()
		if err != nil {
			fmt.Printf("%-30s | %-30s\n", ssid, "Error retrieving password")
			continue
		}

		output := outPass.String()
		lines := strings.Split(output, "\n")
		password := "N/A"

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Key Content") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					password = strings.TrimSpace(parts[1])
					break
				}
			}
		}

		fmt.Printf("%-30s | %-30s\n", ssid, password)
	}
}

func getLocalIPs() ([]string, error) {
	var localIPs []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					localIPs = append(localIPs, ipnet.IP.String())
				}
			}
		}
	}
	return localIPs, nil
}

func monitorTraffic(ctx context.Context, handle *pcap.Handle, localIP, targetIP string) {
	if net.ParseIP(targetIP) == nil {
		fmt.Printf("%sError: Invalid target IP address: %s%s\n", red, targetIP, reset)
		return
	}

	localIPs, err := getLocalIPs()
	if err != nil || len(localIPs) == 0 {
		fmt.Printf("%sError: Could not determine local IP addresses%s\n", red, reset)
		return
	}

	filter := fmt.Sprintf("host %s", targetIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("%sError setting BPF filter: %v%s\n", red, err, reset)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}

			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}

			srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
			protocol := "UNKNOWN"
			srcPort, dstPort := "?", "?"
			color := white

			if ipLayer, ok := networkLayer.(*layers.IPv4); ok {
				switch ipLayer.Protocol {
				case layers.IPProtocolTCP:
					if tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
						protocol = "TCP"
						srcPort = tcpLayer.SrcPort.String()
						dstPort = tcpLayer.DstPort.String()
						color = blue
					}
				case layers.IPProtocolUDP:
					if udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
						protocol = "UDP"
						srcPort = udpLayer.SrcPort.String()
						dstPort = udpLayer.DstPort.String()
						color = yellow
					}
				case layers.IPProtocolICMPv4:
					protocol = "ICMP"
					srcPort, dstPort = "-", "-"
					color = green
					if icmpLayer, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
						srcPort = fmt.Sprintf("Type:%d", icmpLayer.TypeCode.Type())
						dstPort = fmt.Sprintf("Code:%d", icmpLayer.TypeCode.Code())
					}
				default:
					protocol = fmt.Sprintf("IP:%d", ipLayer.Protocol)
					color = white
				}
			}

			var direction string
			isLocalSrc := false
			for _, ip := range localIPs {
				if srcIP.String() == ip {
					isLocalSrc = true
					break
				}
			}
			if isLocalSrc {
				direction = "OUTGOING"
			} else {
				direction = "INCOMING"
			}

			timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")

			fmt.Printf("%s%-15s %s%-10s%s %-20s %-8s %s%-20s %-8s %s%-10s%s\n",
				white, timestamp,
				yellow, direction, reset,
				srcIP.String(), srcPort,
				cyan, dstIP.String(), dstPort,
				color, protocol, reset)
		}
	}
}

var commandHistory []string
var historyIndex int = -1
var showMode = false
