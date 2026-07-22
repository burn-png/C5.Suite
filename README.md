# C5.Suite

A lightweight firmware for the Seeed Studio Xiao ESP32-C5 focused on passive Wi-Fi analysis and local network diagnostics through a serial command-line interface.

Unlike touchscreen-based firmware, C5 Firmware is designed around a fast serial workflow, making it suitable for scripting, automation, and terminal-based operation.

> [!IMPORTANT]
> This firmware is intended for educational purposes, security research, and testing on networks you own or are explicitly authorized to assess.

---

# Features

## Passive Wi-Fi Monitoring

- Beacon frame monitoring
- Probe request monitoring
- Deauthentication frame detection
- EAPOL frame detection
- Multi-channel passive scanning
- Configurable scan duration
- Continuous scan mode
- Automatic channel hopping

---

## Access Point Information

Retrieve detailed information about a specific SSID.

Available categories:

### Identity

- SSID
- Hidden SSID detection
- BSSID
- Vendor / OUI lookup

### Security

- Open
- WPA
- WPA2
- WPA3 detection
- Authentication type
- WPS status
- WPS information

### Radio

- RSSI
- Channel
- Channel width
- Frequency band
- 802.11 mode

### Capabilities

- Wi-Fi 6 detection
- Wi-Fi 7 detection
- Mesh support
- Vendor Information Elements

---

## Local Network Diagnostics

Requires joining a Wi-Fi network.

Available tools:

- ICMP Ping
- TCP Port Check
- SSH detection
- HTTP detection
- HTTPS detection
- SMTP detection
- DNS detection
- Telnet detection
- RDP detection
- Local ARP sweep

---

## Serial Command Interface

Simple CLI designed for low overhead.

Commands include:

```
help

scan ap

scan beacon
scan probe
scan deauth
scan eapol
scan all

apinfo <ssid> <tag>

wifi <ssid> <password>
wifi disconnect

scan ping <ip>
scan port <ip> <port>

stop
cancel
```

---

# Current Commands

## Passive Monitoring

```
scan beacon [seconds|inf]
scan probe [seconds|inf]
scan deauth [seconds|inf]
scan eapol [seconds|inf]
scan all [seconds|inf]
```

---

## AP Discovery

```
scan ap
```

Performs three passive scans and lists discovered access points.

---

## AP Information

```
apinfo <ssid> <tag>
```

Available tags:

```
identity
security
radio
capability
all
```

---

## Wi-Fi Connection

```
wifi <ssid> <password>
```

Disconnect:

```
wifi disconnect
```

---

## Network Diagnostics

```
scan ping <ip>

scan arp

scan port <ip> <port>

scan ssh <ip>
scan telnet <ip>
scan smtp <ip>
scan dns <ip>
scan http <ip>
scan https <ip>
scan rdp <ip>
```

---

## Control

```
stop
cancel
```

Stops:

- Passive monitor
- AP information scan
- Wi-Fi connection attempt

---

# Hardware

Current target:

- Seeed Studio Xiao ESP32C5

---

# Requirements

- Arduino IDE
- ESP32 Arduino Core
- USB Serial connection

---

# Example Session

```
help

scan beacon 20

apinfo MyWiFi security

wifi HomeWiFi password123

scan ping 192.168.1.1

scan https 192.168.1.1

wifi disconnect
```

---

# Roadmap

Planned additions include:

- PMKID detection
- SAE commit monitoring
- Expanded AP capability parsing
- Additional diagnostic commands

---

# License

This project is provided for educational purposes and authorized security testing only.

Users are responsible for complying with all applicable laws and regulations when using this software.
