# Bytar
Bytar is a tool that performs basic security analysis 

### Run
```
go run main.go
```

### Build an .exe
```
go build -o bytar.exe main.go
```

### >_ Features
-Network Connections Viewer:
	Display all established TCP connections with detailed remote IP, port, organization, country, and hostname information.

-IP Scanner:
	Scan any IP address to retrieve geolocation, organization, and network details.

-Traffic Monitor:
	Live monitoring of network packets between your device and a target IP, with protocol, direction, and port info.

-Firewall Status:
	Instantly check the status of Windows Firewall profiles.

-Wi-Fi Password Recovery:
	List all saved Wi-Fi SSIDs and their passwords on your system.

-Running Services:
	Show all currently running Windows services.

-Listening Ports:
	Display all ports your system is currently listening on.

-Command History:
	View and reuse previous commands easily.

-Customizable Theme:
	Change the color theme of the CLI output (red, green, blue).

-Clear & Banner Commands:
	Quickly clear the terminal or display the Bytar banner.

-Help Menu:
	Built-in help menu listing all available commands.



### >_ Usage
- Help Menu
<img width="636" height="560" alt="bytar2" src="https://github.com/user-attachments/assets/5f52d759-949f-47a7-bea3-c904c9a31360" />


- Show established connections (Note: If someone has obtained a reverse shell from you, it will appear in active connections. So, if you notice an IP address that does not belong to your organization/company, you should be suspicious and monitor the traffic between them using the 'mon <ip>' command. You can even check your security by scanning it with VirusTotal.)
<img width="1427" height="942" alt="bytar1" src="https://github.com/user-attachments/assets/b63ae1a5-fd6b-4517-a7d6-597b2c5b7224" />

- Monitoring connections
![Screenshot_4](https://github.com/user-attachments/assets/080cfb2d-8e6a-408e-bfb9-5d828ca918f2)

- BONUS!! THEMES (Command: "theme blue/red/green")
![Screenshot_5](https://github.com/user-attachments/assets/8ebb6370-e24d-4dca-9aa0-2c58d638f9ca)

  


 
