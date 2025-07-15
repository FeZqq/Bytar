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
- Scans all ip addresses that has active connection between your pc and the ip address. ("connections" command)
- Gets more information about established ip addresses. ("scan <ip>" command)
- Shows packets on the connection between your network interfaces and specified ip address. ("mon <ip>" command)


### >_ Usage
- Help Menu
![Screenshot_1](https://github.com/user-attachments/assets/ccfa6958-8a0f-4ba5-9d86-5ab7232ee56c)

- Show established connections (Note: If someone has obtained a reverse shell from you, it will appear in active connections. So, if you notice an IP address that does not belong to your organization/company, you should be suspicious and monitor the traffic between them using the 'mon <ip>' command. You can even check your security by scanning it with VirusTotal.)
![Screenshot_3](https://github.com/user-attachments/assets/80638500-cdde-40e6-8230-967ddc6a4146)

- Monitoring connections
![Screenshot_4](https://github.com/user-attachments/assets/080cfb2d-8e6a-408e-bfb9-5d828ca918f2)

- BONUS!! THEMES (Command: "theme blue/red/green")
![Screenshot_5](https://github.com/user-attachments/assets/8ebb6370-e24d-4dca-9aa0-2c58d638f9ca)

  


 
