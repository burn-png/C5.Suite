#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
extern "C" {
  #include "esp_wifi.h"
  #include "ping/ping_sock.h"
}
typedef void (*cmd_handler_t)(const char *args);
static void cmd_help(const char *args), cmd_scan(const char *args);
static void cmd_stop(const char *args), cmd_cancel(const char *args), cmd_wifi(const char *args);
static void cmd_apinfo(const char *args);
typedef enum { MODE_NONE, MODE_BEACON, MODE_PROBE, MODE_DEAUTH, MODE_EAPOL, MODE_ALL, MODE_APINFO } scan_mode_t;
typedef struct { const char *name; scan_mode_t mode; } mode_entry_t;
static const mode_entry_t monitor_modes[] = {
  { "beacon", MODE_BEACON },
  { "probe", MODE_PROBE },
  { "deauth", MODE_DEAUTH },
  { "eapol", MODE_EAPOL },
  { "all", MODE_ALL },
};
#define MONITOR_MODE_COUNT (sizeof(monitor_modes) / sizeof(monitor_modes[0]))
typedef struct {
  char ssid[33];
  uint8_t bssid[6];
  int8_t rssi;
  uint8_t channel;
  uint8_t channel_width;
  char security[64];
  char auth[64];
  char cipher[64];
  char akm_suites[128];
  char rsn_info[64];
  bool wps_enabled;
  char wps_manufacturer[33];
  char wps_model[33];
  char wps_device_name[33];
  uint32_t wps_capabilities;
  bool hidden_ssid;
  char band[16];
  char mode[32];
  bool wifi6_supported;
  bool wifi7_supported;
  bool mesh_enabled;
  char vendor_ie[256];
  uint8_t client_load;
  uint8_t channel_utilization;
  char vendor_oui[32];
  bool is_open;
  bool is_wpa;
  bool is_wpa2;
  bool is_wpa3;
  bool is_enterprise;
} ap_info_t;
static scan_mode_t current_mode = MODE_NONE;
static uint32_t packet_count = 0, scan_duration_ms = 0, scan_start_time = 0;
static bool scan_infinite = false;
static const uint8_t hop_channels[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
#define HOP_CHANNEL_COUNT (sizeof(hop_channels) / sizeof(hop_channels[0]))
static uint8_t hop_index = 0;
static uint32_t last_hop_time = 0, hop_count = 0;
#define HOP_INTERVAL_MS 150
static ap_info_t found_ap = {0};
static char target_ssid[33] = {0};
static char apinfo_tag[32] = {0};
static bool apinfo_found = false;
static uint32_t apinfo_scan_timeout = 0;
static bool wifi_connecting = false;
static uint32_t wifi_connect_start_time = 0;
static uint32_t wifi_connect_timeout_ms = 20000;
static char wifi_connecting_ssid[33] = {0};
typedef struct __attribute__((packed)) {
  uint16_t frame_ctrl, duration;
  uint8_t addr1[6], addr2[6], addr3[6];
  uint16_t seq_ctrl;
} wifi_hdr_t;
static void mac_to_str(const uint8_t *mac, char *out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
static const char* lookup_oui(const uint8_t *mac) {
  if (mac[0] == 0x00 && mac[1] == 0x1A && mac[2] == 0x2B) return "Cisco";
  if (mac[0] == 0x00 && mac[1] == 0x0B && mac[2] == 0x85) return "3Com";
  if (mac[0] == 0xA4 && mac[1] == 0xD4 && mac[2] == 0x12) return "Apple";
  if (mac[0] == 0x44 && mac[1] == 0x2A && mac[2] == 0x60) return "Apple";
  if (mac[0] == 0x6C && mac[1] == 0xF3 && mac[2] == 0x7F) return "Intel";
  if (mac[0] == 0xE0 && mac[1] == 0x55 && mac[2] == 0x3D) return "Asus";
  if (mac[0] == 0x00 && mac[1] == 0x11 && mac[2] == 0x95) return "TP-Link";
  if (mac[0] == 0x2C && mac[1] == 0x30 && mac[2] == 0xAD) return "Netgear";
  if (mac[0] == 0xF4 && mac[1] == 0xEC && mac[2] == 0x38) return "Samsung";
  return "Unknown";
}
static const char *mgmt_subtype_name(uint8_t subtype) {
  switch (subtype) {
    case 0x4: return "probe-req"; case 0x5: return "probe-resp";
    case 0x8: return "beacon"; case 0xA: return "disassoc";
    case 0xB: return "auth"; case 0xC: return "deauth";
    case 0xD: return "action"; default: return "mgmt-other";
  }
}
static bool find_ie(uint8_t ie_type, const uint8_t *payload, uint16_t len, uint8_t *out_data, uint16_t *out_len) {
  uint16_t ie_start = 36;
  while (ie_start + 2 <= len) {
    uint8_t type = payload[ie_start];
    uint8_t ie_len = payload[ie_start + 1];
    if (ie_start + 2 + ie_len > len) break;
    if (type == ie_type) {
      if (out_data && out_len) {
        *out_len = ie_len;
        memcpy(out_data, &payload[ie_start + 2], ie_len);
      }
      return true;
    }
    ie_start += 2 + ie_len;
  }
  return false;
}
static void extract_ssid_from_beacon(const uint8_t *payload, uint16_t len, char *out, size_t out_len) {
  uint8_t ssid_data[33] = {0};
  uint16_t ssid_len = 0;
  if (find_ie(0, payload, len, ssid_data, &ssid_len)) { // IE type 0 = SSID
    if (ssid_len == 0) {
      strncpy(out, "(hidden)", out_len);
    } else {
      memcpy(out, ssid_data, ssid_len < out_len ? ssid_len : out_len - 1);
      out[ssid_len] = 0;
    }
  } else {
    strncpy(out, "(no ssid found)", out_len);
  }
  out[out_len - 1] = 0;
}
#define CAP_BUF_SIZE 128
#define CAP_PAYLOAD_COPY 256
typedef struct {
  uint32_t index;
  uint8_t  channel;
  int8_t   rssi;
  uint8_t  frame_type;
  uint8_t  subtype;
  bool eapol;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint16_t payload_len;
  uint8_t  payload[CAP_PAYLOAD_COPY];
} capture_entry_t;
static capture_entry_t cap_buf[CAP_BUF_SIZE];
static volatile uint16_t cap_head = 0, cap_tail = 0;
static volatile uint32_t cap_dropped = 0;
static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (current_mode == MODE_NONE) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  if (pkt->rx_ctrl.sig_len < sizeof(wifi_hdr_t)) return;
  wifi_hdr_t *hdr = (wifi_hdr_t *)pkt->payload;
  uint8_t frame_type = (hdr->frame_ctrl >> 2) & 3, subtype = (hdr->frame_ctrl >> 4) & 15;
  bool mgmt = frame_type == 0;
  bool is_eapol = false;
  if (frame_type == 2) {
    if (pkt->rx_ctrl.sig_len > 32) {
      uint8_t *p = pkt->payload + 24;
      if (p[0] == 0xAA && p[1] == 0xAA && p[2] == 0x03 && p[6] == 0x88 && p[7] == 0x8E) {
        is_eapol = true;
      }
    }
  }
  if (current_mode == MODE_APINFO) {
    if (mgmt && subtype == 0x8) { // beacon
      char ssid[33];
      extract_ssid_from_beacon(pkt->payload, pkt->rx_ctrl.sig_len, ssid, sizeof(ssid));
      if (strcmp(ssid, "(no ssid found)") != 0) {
        Serial.printf("[DEBUG] Found SSID: '%s' ch%d %ddBm\n", ssid, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);
      }
      if (!strcasecmp(ssid, target_ssid)) {
        Serial.printf("[MATCH] Found target SSID: '%s'\n", target_ssid);
        apinfo_found = true;
        memcpy(found_ap.bssid, hdr->addr2, 6);
        found_ap.rssi = pkt->rx_ctrl.rssi;
        found_ap.channel = pkt->rx_ctrl.channel;
        strncpy(found_ap.ssid, ssid, sizeof(found_ap.ssid) - 1);
        found_ap.hidden_ssid = (strlen(ssid) == 0 || !strcasecmp(ssid, "(hidden)"));
        parse_wpa_ie(pkt->payload, pkt->rx_ctrl.sig_len, &found_ap);
        parse_rsn_ie(pkt->payload, pkt->rx_ctrl.sig_len, &found_ap);
        parse_wps_ie(pkt->payload, pkt->rx_ctrl.sig_len, &found_ap);
        strncpy(found_ap.vendor_oui, lookup_oui(hdr->addr2), sizeof(found_ap.vendor_oui) - 1);
        if (!found_ap.is_wpa && !found_ap.is_wpa2 && !found_ap.is_wpa3) {
          found_ap.is_open = true;
          strncpy(found_ap.security, "Open", sizeof(found_ap.security) - 1);
        }
      }
    }
    return;
  }
  if (current_mode == MODE_BEACON && (!mgmt || subtype != 0x8)) return;
  if (current_mode == MODE_PROBE && (!mgmt || subtype != 0x4)) return;
  if (current_mode == MODE_DEAUTH && (!mgmt || (subtype != 0xA && subtype != 0xC))) return;
  if (current_mode == MODE_EAPOL && !is_eapol) return;
  uint16_t next_head = (cap_head + 1) % CAP_BUF_SIZE;
  if (next_head == cap_tail) { ++cap_dropped; return; }
  capture_entry_t *e = &cap_buf[cap_head];
  e->index = ++packet_count;
  e->channel = pkt->rx_ctrl.channel;
  e->rssi = pkt->rx_ctrl.rssi;
  e->frame_type = frame_type;
  e->subtype = subtype;
  e->eapol = is_eapol;
  memcpy(e->addr1, hdr->addr1, 6);
  memcpy(e->addr2, hdr->addr2, 6);
  uint16_t copy_len = pkt->rx_ctrl.sig_len;
  if (copy_len > CAP_PAYLOAD_COPY) copy_len = CAP_PAYLOAD_COPY;
  memcpy(e->payload, pkt->payload, copy_len);
  e->payload_len = copy_len;
  cap_head = next_head;
}
static void drain_capture_buffer() {
  while (cap_tail != cap_head) {
    capture_entry_t *e = &cap_buf[cap_tail];
    bool mgmt = e->frame_type == 0;
    char src[18], dst[18];
    mac_to_str(e->addr2, src);
    mac_to_str(e->addr1, dst);
    if (e->eapol) {
      const char *type = "EAPOL";
      if (e->payload_len > 40) {
        uint8_t eapol_type = e->payload[39];
        if (eapol_type == 3) type = "EAPOL-Key";
      }
      Serial.printf("#%lu %s ch%d %ddBm src=%s dst=%s\n",
        (unsigned long)e->index, type, e->channel, e->rssi, src, dst);
    } else if (current_mode == MODE_BEACON || current_mode == MODE_PROBE) {
      char ssid[33];
      extract_ssid_from_beacon(e->payload, e->payload_len, ssid, sizeof(ssid));
      Serial.printf("#%lu %s ch%d %ddBm from=%s ssid=%s\n", (unsigned long)e->index,
        current_mode == MODE_BEACON ? "BEACON" : "PROBE-REQ", e->channel, e->rssi, src, ssid);
    } else if (current_mode == MODE_DEAUTH) {
      Serial.printf("#%lu %s ch%d %ddBm from=%s to=%s  <-- possible attack in progress\n", (unsigned long)e->index,
        e->subtype == 0xC ? "DEAUTH" : "DISASSOC", e->channel, e->rssi, src, dst);
    } else {
      const char *kind = mgmt ? mgmt_subtype_name(e->subtype) : (e->frame_type == 1 ? "control" : "data");
      Serial.printf("#%lu ch%d %ddBm [%s] src=%s dst=%s\n", (unsigned long)e->index, e->channel, e->rssi, kind, src, dst);
    }
    cap_tail = (cap_tail + 1) % CAP_BUF_SIZE;
  }
  static uint32_t last_dropped_report = 0;
  if (cap_dropped != last_dropped_report) {
    Serial.printf("[buffer overrun: %lu frames dropped total - traffic exceeded print rate]\n", (unsigned long)cap_dropped);
    last_dropped_report = cap_dropped;
  }
}
static void parse_rsn_ie(const uint8_t *payload, uint16_t len, ap_info_t *ap) {
  uint8_t rsn_data[256] = {0};
  uint16_t rsn_len = 0;
  if (find_ie(48, payload, len, rsn_data, &rsn_len)) {
    if (rsn_len >= 2) {
      ap->is_wpa2 = true;
      strncpy(ap->security, "WPA2", sizeof(ap->security) - 1);
      
      if (rsn_len >= 18 && (rsn_data[18] & 0x01)) {
        ap->is_wpa3 = true;
        strncpy(ap->security, "WPA3/WPA2", sizeof(ap->security) - 1);
      }
    }
  }
}
static void parse_wpa_ie(const uint8_t *payload, uint16_t len, ap_info_t *ap) {
  for (uint16_t i = 36; i + 6 < len; ++i) {
    if (payload[i] == 0xDD &&
        payload[i + 2] == 0x00 && payload[i + 3] == 0x50 && 
        payload[i + 4] == 0xF2 && payload[i + 5] == 0x01) {
      ap->is_wpa = true;
      if (!ap->is_wpa2) strncpy(ap->security, "WPA", sizeof(ap->security) - 1);
      break;
    }
  }
}
static void parse_wps_ie(const uint8_t *payload, uint16_t len, ap_info_t *ap) {
  for (uint16_t i = 36; i + 6 < len; ++i) {
    if (payload[i] == 0xDD && 
        payload[i + 2] == 0x00 && payload[i + 3] == 0x50 && 
        payload[i + 4] == 0xF2 && payload[i + 5] == 0x04) {
      ap->wps_enabled = true;
      if (i + 11 < len) {
        ap->wps_capabilities = (payload[i + 10] << 8) | payload[i + 11];
      }
      break;
    }
  }
}
static void do_stop_scan() {
  bool did_something = false;
  if (current_mode != MODE_NONE) {
    esp_wifi_set_promiscuous(false);
    if (current_mode == MODE_APINFO) {
      Serial.printf("apinfo scan stopped\n");
    } else {
      Serial.printf("scan stopped, %lu results seen\n", (unsigned long)packet_count);
    }
    current_mode = MODE_NONE;
    scan_duration_ms = 0;
    scan_infinite = false;
    did_something = true;
  }
  if (wifi_connecting) {
    WiFi.disconnect(false, false);
    Serial.printf("Wi-Fi connection attempt to '%s' cancelled\n", wifi_connecting_ssid);
    wifi_connecting = false;
    did_something = true;
  }
  if (!did_something) Serial.println("nothing running");
}
static bool connected() { return WiFi.status() == WL_CONNECTED; }
static bool parse_ip(const char *text, IPAddress &out) {
  if (!out.fromString(text)) { Serial.println("target must be an IPv4 address"); return false; }
  return true;
}
static bool is_local_target(const IPAddress &target) {
  IPAddress local = WiFi.localIP(), mask = WiFi.subnetMask();
  for (uint8_t i = 0; i < 4; ++i) if ((target[i] & mask[i]) != (local[i] & mask[i])) return false;
  return true;
}
static bool require_local_target(const char *text, IPAddress &target) {
  if (!connected()) { Serial.println("connect first: wifi <ssid> <password>"); return false; }
  if (!parse_ip(text, target)) return false;
  if (!is_local_target(target)) { Serial.println("for safety, connected-network checks are limited to this local subnet"); return false; }
  return true;
}
static void scan_ap_mode() {
  if (current_mode != MODE_NONE) { Serial.println("already scanning, use 'stop' first"); return; }
  if (connected()) { Serial.println("disconnect from Wi-Fi before scan ap; client mode must stay on its AP channel"); return; }
  Serial.println("AP discovery started: three passive scans across all available channels");
  for (uint8_t pass = 1; pass <= 3; ++pass) {
    int found = WiFi.scanNetworks(false, true, true);
    Serial.printf("AP pass %u/3: %d access point(s)\n", pass, found);
    for (int i = 0; i < found; ++i)
      Serial.printf("  ch%d %ddBm bssid=%s ssid=%s\n", WiFi.channel(i), WiFi.RSSI(i), WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str());
    WiFi.scanDelete();
  }
  Serial.println("AP discovery complete: all channels scanned three times");
}
static void run_tcp_probe(const char *label, const char *host_text, uint16_t port) {
  IPAddress host;
  if (!require_local_target(host_text, host)) return;
  WiFiClient client;
  bool open = client.connect(host, port, 650);
  Serial.printf("%s %s:%u %s\n", label, host.toString().c_str(), port, open ? "OPEN" : "closed or filtered");
  if (open) client.stop();
}
static volatile bool ping_done = false, ping_reply = false;
static void ping_success(esp_ping_handle_t hdl, void *args) { ping_reply = true; }
static void ping_end(esp_ping_handle_t hdl, void *args) { ping_done = true; }
static void run_ping(const char *host_text) {
  IPAddress host;
  if (!require_local_target(host_text, host)) return;
  ip4_addr_t addr;
  IP4_ADDR(&addr, host[0], host[1], host[2], host[3]);
  esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
  cfg.target_addr.type = ESP_IPADDR_TYPE_V4;
  cfg.target_addr.u_addr.ip4 = addr;
  cfg.count = 1;
  cfg.timeout_ms = 800;
  cfg.interval_ms = 1;
  esp_ping_callbacks_t callbacks = {};
  callbacks.on_ping_success = ping_success;
  callbacks.on_ping_end = ping_end;
  esp_ping_handle_t handle = NULL;
  ping_done = false;
  ping_reply = false;
  if (esp_ping_new_session(&cfg, &callbacks, &handle) != ESP_OK) {
    Serial.println("could not start ICMP ping");
    return;
  }
  esp_ping_start(handle);
  uint32_t deadline = millis() + 1500;
  while (!ping_done && millis() < deadline) delay(10);
  esp_ping_stop(handle);
  esp_ping_delete_session(handle);
  Serial.printf("PING %s %s\n", host.toString().c_str(), ping_reply ? "reachable" : "no reply");
}
static void run_arp_sweep(const char *start_text, const char *end_text) {
  if (!connected()) { Serial.println("connect first: wifi <ssid> <password>"); return; }
  int start = start_text && *start_text ? atoi(start_text) : 1;
  int end = end_text && *end_text ? atoi(end_text) : 32;
  if (start < 1 || end > 254 || end < start || end - start + 1 > 32) { Serial.println("usage: scan arp [start 1-254] [end; maximum 32 hosts]"); return; }
  IPAddress local = WiFi.localIP();
  WiFiUDP udp;
  Serial.printf("ARP discovery traffic sent to local hosts %d-%d (responses are not guaranteed)\n", start, end);
  for (int octet = start; octet <= end; ++octet) {
    IPAddress target(local[0], local[1], local[2], octet);
    udp.beginPacket(target, 9);
    udp.write((uint8_t)0);
    udp.endPacket();
    delay(15);
  }
  Serial.println("ARP probe complete. ESP32 Arduino does not expose its ARP cache portably, so only confirmed TCP/ICMP results are printed by the other scans.");
}
static void print_apinfo_section(ap_info_t *ap, const char *tag) {
  if (!strcasecmp(tag, "identity") || !strcasecmp(tag, "all")) {
    Serial.println("\n--- IDENTITY ---");
    Serial.printf("SSID: %s\n", ap->ssid);
    Serial.printf("Hidden SSID: %s\n", ap->hidden_ssid ? "Yes" : "No");
    char bssid_str[18];
    mac_to_str(ap->bssid, bssid_str);
    Serial.printf("BSSID: %s\n", bssid_str);
    Serial.printf("Vendor/OUI: %s\n", ap->vendor_oui);
  }
  if (!strcasecmp(tag, "security") || !strcasecmp(tag, "all")) {
    Serial.println("\n--- SECURITY ---");
    Serial.printf("Security Type: %s\n", ap->security);
    Serial.printf("Authentication: %s\n", ap->is_enterprise ? "Enterprise (802.1X)" : ap->is_open ? "Open" : "Personal");
    Serial.printf("WPA: %s\n", ap->is_wpa ? "Yes" : "No");
    Serial.printf("WPA2: %s\n", ap->is_wpa2 ? "Yes" : "No");
    Serial.printf("WPA3: %s\n", ap->is_wpa3 ? "Yes" : "No");
    Serial.printf("WPS Status: %s\n", ap->wps_enabled ? "Enabled" : "Disabled");
    if (ap->wps_enabled) {
      Serial.printf("WPS Manufacturer: %s\n", ap->wps_manufacturer);
      Serial.printf("WPS Model: %s\n", ap->wps_model);
      Serial.printf("WPS Device Name: %s\n", ap->wps_device_name);
    }
  }
  if (!strcasecmp(tag, "radio") || !strcasecmp(tag, "all")) {
    Serial.println("\n--- RADIO ---");
    Serial.printf("Band: %s\n", ap->channel <= 14 ? "2.4 GHz" : "5 GHz");
    Serial.printf("Channel: %d\n", ap->channel);
    Serial.printf("Channel Width: %s\n", ap->channel_width == 20 ? "20 MHz" : "40+ MHz");
    Serial.printf("802.11 Mode: %s\n", ap->mode);
    Serial.printf("RSSI: %d dBm\n", ap->rssi);
  }
  if (!strcasecmp(tag, "capability") || !strcasecmp(tag, "all")) {
    Serial.println("\n--- CAPABILITY ---");
    Serial.printf("Wi-Fi 6 (802.11ax): %s\n", ap->wifi6_supported ? "Yes" : "No");
    Serial.printf("Wi-Fi 7 (802.11be): %s\n", ap->wifi7_supported ? "Yes" : "No");
    Serial.printf("Mesh Enabled: %s\n", ap->mesh_enabled ? "Yes" : "No");
    Serial.printf("Vendor IEs: %s\n", ap->vendor_ie);
  }
}
static void cmd_apinfo(const char *args) {
  if (current_mode != MODE_NONE) { Serial.println("already scanning, use 'stop' first"); return; }
  if (connected()) { Serial.println("disconnect from Wi-Fi before apinfo scan; channel hopping interrupts the connection"); return; }
  char buf[96];
  strncpy(buf, args, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  char *ssid = strtok(buf, " ");
  char *tag = strtok(NULL, " ");
  if (!ssid) {
    Serial.println("usage: apinfo <ssid> <tag>");
    Serial.println("tags: identity, security, radio, capability, all");
    return;
  }
  if (!tag) tag = "all";
  strncpy(target_ssid, ssid, sizeof(target_ssid) - 1);
  target_ssid[sizeof(target_ssid) - 1] = 0;
  strncpy(apinfo_tag, tag, sizeof(apinfo_tag) - 1);
  apinfo_tag[sizeof(apinfo_tag) - 1] = 0;
  memset(&found_ap, 0, sizeof(found_ap));
  apinfo_found = false;
  current_mode = MODE_APINFO;
  packet_count = hop_count = 0;
  scan_start_time = last_hop_time = millis();
  hop_index = 0;
  apinfo_scan_timeout = millis() + 15000;

  esp_wifi_set_channel(hop_channels[hop_index], WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);

  Serial.printf("apinfo scan started for SSID '%s' (15s timeout, or 'stop' to abort)\n", ssid);
}
static void cmd_scan(const char *args) {
  char buf[96];
  strncpy(buf, args, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  char *mode = strtok(buf, " "), *arg1 = strtok(NULL, " "), *arg2 = strtok(NULL, " ");
  if (!mode) { Serial.println("try 'help'"); return; }
  if (!strcasecmp(mode, "ap")) { if (arg1) Serial.println("scan ap takes no duration or arguments"); else scan_ap_mode(); return; }
  if (!strcasecmp(mode, "ping")) { if (arg1) run_ping(arg1); else Serial.println("usage: scan ping <local-ip>"); return; }
  if (!strcasecmp(mode, "arp")) { run_arp_sweep(arg1, arg2); return; }
  struct service_t { const char *name; uint16_t port; };
  static const service_t services[] = { {"ssh",22}, {"telnet",23}, {"smtp",25}, {"dns",53}, {"http",80}, {"https",443}, {"rdp",3389} };
  if (!strcasecmp(mode, "port")) {
    if (!arg1 || !arg2) { Serial.println("usage: scan port <local-ip> <1-65535>"); return; }
    long port = atol(arg2);
    if (port < 1 || port > 65535) { Serial.println("port must be 1-65535"); return; }
    run_tcp_probe("PORT", arg1, (uint16_t)port);
    return;
  }
  for (size_t i = 0; i < sizeof(services)/sizeof(services[0]); ++i)
    if (!strcasecmp(mode, services[i].name)) { if (arg1) run_tcp_probe(services[i].name, arg1, services[i].port); else Serial.printf("usage: scan %s <local-ip>\n", services[i].name); return; }
  if (current_mode != MODE_NONE) { Serial.println("already scanning, use 'stop' first"); return; }
  if (connected()) { Serial.println("disconnect from Wi-Fi before monitor scans; channel hopping interrupts the connection"); return; }
  scan_mode_t selected = MODE_NONE;
  for (size_t i = 0; i < MONITOR_MODE_COUNT; ++i) if (!strcasecmp(mode, monitor_modes[i].name)) { selected = monitor_modes[i].mode; break; }
  if (selected == MODE_NONE) { Serial.println("unknown scan mode; try 'help'"); return; }
  scan_duration_ms = 0;
  scan_infinite = false;
  if (arg1) {
    if (!strcasecmp(arg1, "inf")) scan_infinite = true;
    else { long seconds = atol(arg1); if (seconds <= 0) { Serial.println("duration must be positive seconds or inf"); return; } scan_duration_ms = (uint32_t)seconds * 1000UL; }
  }
  current_mode = selected;
  packet_count = hop_count = 0;
  scan_start_time = last_hop_time = millis();
  hop_index = 0;
  esp_wifi_set_channel(hop_channels[hop_index], WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  Serial.printf("monitor scan '%s' started%s\n", mode, scan_duration_ms ? " (timed)" : scan_infinite ? " (until stop)" : " (one channel cycle)");
}
static void cmd_wifi(const char *args) {
  if (current_mode != MODE_NONE) do_stop_scan();
  char buf[130];
  strncpy(buf, args, sizeof(buf)-1);
  buf[sizeof(buf)-1]=0;
  char *ssid = strtok(buf, " "), *password = strtok(NULL, " "), *timeout_arg = strtok(NULL, " ");
  if (ssid && !strcasecmp(ssid, "disconnect") && !password) {
    if (wifi_connecting) { wifi_connecting = false; }
    WiFi.disconnect(false, false);
    Serial.println("Wi-Fi disconnected");
    return;
  }
  if (!ssid || !password) {
    Serial.println("usage: wifi <ssid> <password> [timeout_seconds]  (SSID/password cannot contain spaces)");
    return;
  }
  if (wifi_connecting) {
    Serial.println("already attempting a connection, use 'cancel' or 'stop' first");
    return;
  }
  uint32_t timeout_ms = 20000;
  if (timeout_arg) {
    long secs = atol(timeout_arg);
    if (secs <= 0) { Serial.println("timeout_seconds must be a positive number"); return; }
    timeout_ms = (uint32_t)secs * 1000UL;
  }
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, false);
  WiFi.begin(ssid, password);
  strncpy(wifi_connecting_ssid, ssid, sizeof(wifi_connecting_ssid) - 1);
  wifi_connecting_ssid[sizeof(wifi_connecting_ssid) - 1] = '\0';
  wifi_connecting = true;
  wifi_connect_start_time = millis();
  wifi_connect_timeout_ms = timeout_ms;
  Serial.printf("connecting to %s (timeout %lus, 'cancel'/'stop' to abort)\n", ssid, (unsigned long)(timeout_ms / 1000));
}
static void cmd_stop(const char *args) { do_stop_scan(); }
static void cmd_cancel(const char *args) { do_stop_scan(); }
static void cmd_help(const char *args) {
  Serial.println("available commands:");
  Serial.println("  scan ap                         - passive AP discovery; exactly three full scans, no duration");
  Serial.println("  scan beacon|probe|deauth|eapol|all [seconds|inf] - passive receive-only monitor");
  Serial.println("  apinfo <ssid> <tag>             - detailed AP information (tags: identity, security, radio, capability, all)");
  Serial.println("  wifi <ssid> <password> [timeout_seconds] - join Wi-Fi (no spaces in SSID/password; default timeout 20s)");
  Serial.println("  wifi disconnect                 - leave Wi-Fi before passive monitor/AP scans");
  Serial.println("  stop / cancel                   - stop a passive monitor scan OR abort an in-progress Wi-Fi connect");
  Serial.println("\nrequires a Wi-Fi connection (local subnet targets only; authorized networks only):");
  Serial.println("  scan ping <ip>                  - one ICMP reachability check");
  Serial.println("  scan arp [start] [end]          - send local ARP-triggering probes (maximum 32 hosts)");
  Serial.println("  scan port <ip> <port>           - one TCP port check");
  Serial.println("  scan ssh|telnet|smtp|dns|http|https|rdp <ip> - TCP service-port check");
}
typedef struct { const char *name; cmd_handler_t handler; } cmd_entry_t;
static const cmd_entry_t commands[] = { {"scan",cmd_scan}, {"apinfo",cmd_apinfo}, {"wifi",cmd_wifi}, {"stop",cmd_stop}, {"cancel",cmd_cancel}, {"help",cmd_help} };
static void dispatch_line(char *line) {
  while (*line == ' ') ++line;
  if (!*line) return;
  char *args = strchr(line, ' ');
  if (args) { *args++ = 0; while (*args == ' ') ++args; } else args = line + strlen(line);
  for (size_t i = 0; i < sizeof(commands)/sizeof(commands[0]); ++i)
    if (!strcasecmp(line, commands[i].name)) { commands[i].handler(args); return; }
  Serial.printf("unknown command: '%s' (try help)\n", line);
}
#define RX_BUF_SIZE 256
static char line_buf[RX_BUF_SIZE];
static size_t line_idx = 0;
void setup() {
  Serial.begin(921600);
  delay(500);
  Serial.println(" ,-----.,-----.     ,---.          ,--.  ,--.          ");
  Serial.println("'  .--./|  .--'    '   .-' ,--.,--.`--',-'  '-. ,---.  ");
  Serial.println("|  |    '--. `\\    `.  `-. |  ||  |,--.'-.  .-'| .-. : ");
  Serial.println("'  '--'\.--'  /.--..-'    |'  ''  '|  |  |  |  \\   --. ");
  Serial.println(" `-----'`----' '--'`-----'  `----' `--'  `--'   `----' ");
  Serial.println("version 0.11.2                        MADE BY Burn-png");
  Serial.println();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, false);
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
  Serial.println("ESP32 passive monitor / local diagnostics ready; type help");
}
void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (line_idx) {
        line_buf[line_idx] = 0;
        dispatch_line(line_buf);
        line_idx = 0;
      }
    }
    else if (line_idx < RX_BUF_SIZE - 1) line_buf[line_idx++] = c;
    else { line_idx = 0; Serial.println("line too long, dropped"); }
  }
  drain_capture_buffer();
  if (wifi_connecting) {
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf("connected: ip=%s gateway=%s mask=%s\n",
        WiFi.localIP().toString().c_str(), WiFi.gatewayIP().toString().c_str(), WiFi.subnetMask().toString().c_str());
      wifi_connecting = false;
    } else if (millis() - wifi_connect_start_time >= wifi_connect_timeout_ms) {
      Serial.printf("Wi-Fi connection to '%s' timed out, giving up\n", wifi_connecting_ssid);
      WiFi.disconnect(false, false);
      wifi_connecting = false;
    }
  }
  if (current_mode == MODE_APINFO) {
    uint32_t now = millis();
    if (now >= apinfo_scan_timeout) {
      if (apinfo_found) {
        Serial.printf("\nAP Information found for '%s':\n", target_ssid);
        print_apinfo_section(&found_ap, apinfo_tag);
      } else {
        Serial.printf("SSID '%s' not found after 15 seconds\n", target_ssid);
      }
      do_stop_scan();
      return;
    }
    if (now - last_hop_time < HOP_INTERVAL_MS) return;
    hop_index = (hop_index + 1) % HOP_CHANNEL_COUNT;
    ++hop_count;
    esp_wifi_set_channel(hop_channels[hop_index], WIFI_SECOND_CHAN_NONE);
    last_hop_time = now;
    return;
  }
  if (current_mode == MODE_NONE) return;
  uint32_t now = millis();
  if (scan_duration_ms && now - scan_start_time >= scan_duration_ms) { Serial.println("scan duration elapsed"); do_stop_scan(); return; }
  if (now - last_hop_time < HOP_INTERVAL_MS) return;
  hop_index = (hop_index + 1) % HOP_CHANNEL_COUNT;
  ++hop_count;
  esp_wifi_set_channel(hop_channels[hop_index], WIFI_SECOND_CHAN_NONE);
  last_hop_time = now;
  if (!scan_duration_ms && !scan_infinite && hop_count >= HOP_CHANNEL_COUNT) { Serial.println("full channel cycle complete"); do_stop_scan(); }
}
