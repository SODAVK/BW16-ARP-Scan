#include <Arduino.h>
#include <WiFi.h>

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"

extern "C" {
  extern struct netif xnetif[];
  struct raw_pcb *raw_new(u8_t proto);
  void raw_recv(struct raw_pcb *pcb, u8_t (*recv)(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr), void *recv_arg);
  err_t raw_bind(struct raw_pcb *pcb, const ip_addr_t *ipaddr);
}
struct DeviceInfo {
  int ttl;
};

DeviceInfo scan_db[256];
extern "C" u8_t raw_recv_cb(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr) {
  (void)arg;
  (void)pcb;
  if (p != NULL) {
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    uint32_t src_ip = ip4_addr_get_u32(ip_2_ip4(addr));
    // index
    uint8_t last_octet = (src_ip >> 24) & 0xFF;
    scan_db[last_octet].ttl = IPH_TTL(iphdr);
    pbuf_free(p);
  }
  return 0;
}

const char *guessOS(int ttl) {
  if (ttl == 0) return "no response";
  if (ttl <= 64) return "Linux/android/ios";
  if (ttl <= 128) return "windows";
  if (ttl <= 255) return "network gear";
  return "unknown";
}

void setup() {
  Serial.begin(115200);
  for (int i = 0; i < 256; i++) scan_db[i].ttl = 0;
  // s
  WiFi.begin("u_ssid", "u_pass");
  while (WiFi.status() != WL_CONNECTED) { delay(500); }

  // cr socket
  struct raw_pcb *icmppcb = raw_new(IP_PROTO_ICMP);
  if (icmppcb) {
    raw_bind(icmppcb, IP_ADDR_ANY);
    raw_recv(icmppcb, raw_recv_cb, NULL);
  }
  Serial.println("\n[ type 'scan' ]");
}

void runScan() {
  IPAddress localIP = WiFi.localIP();
  IPAddress gatewayIP = WiFi.gatewayIP();
  uint32_t startIP = (uint32_t)localIP & 0x00FFFFFF;
  // clear
  for (int i = 0; i < 256; i++) scan_db[i].ttl = 0;
  Serial.println("\narp now");
  for (int i = 1; i < 255; i++) {
    ip4_addr_t target;
    target.addr = startIP | (i << 24);
    etharp_request(&xnetif[0], &target);
    delay(15);
  }

  Serial.println("os search");
  struct udp_pcb *probe_pcb = udp_new();
  for (int i = 1; i < 255; i++) {
    ip4_addr_t target;
    target.addr = startIP | (i << 24);
    struct eth_addr *ret_eth;
    const ip4_addr_t *ret_ip;
    // if dev
    if (etharp_find_addr(&xnetif[0], &target, &ret_eth, &ret_ip) >= 0) {
      if (target.addr == (uint32_t)localIP) continue;
      if (probe_pcb) {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_RAM);
        ip_addr_t target_generic;
        ip_addr_copy_from_ip4(target_generic, target);
        udp_sendto(probe_pcb, p, &target_generic, 55555);
        pbuf_free(p);
        Serial.print("probing ");
        Serial.println(ip4addr_ntoa(&target));
        delay(100);
      }
    }
  }
  if (probe_pcb) udp_remove(probe_pcb);
  Serial.println("waiting resp.");
  delay(1500);
  Serial.println("\nIP\t\tMAC\t\t\tINFO / OS Guess");

  for (int i = 1; i < 255; i++) {
    ip4_addr_t target;
    target.addr = startIP | (i << 24);
    struct eth_addr *ret_eth;
    const ip4_addr_t *ret_ip;
    if (etharp_find_addr(&xnetif[0], &target, &ret_eth, &ret_ip) >= 0) {
      Serial.print(ip4addr_ntoa(&target));
      Serial.print("\t");
      //mac now
      for (int b = 0; b < 6; b++) {
        if (ret_eth->addr[b] < 0x10) Serial.print("0");
        Serial.print(ret_eth->addr[b], HEX);
        if (b < 5) Serial.print(":");
      }
      Serial.print("\t");

      if (target.addr == (uint32_t)gatewayIP) {
        Serial.print("GATEWAY ");
      } else if (target.addr == (uint32_t)localIP) {
        Serial.print("BW16 (THIS) ");
      }

      int t = scan_db[i].ttl;
      if (target.addr != (uint32_t)localIP) {
        Serial.print(guessOS(t));
        if (t > 0) {
          Serial.print(" (");
          Serial.print(t);
          Serial.print(")");
        }
      }
      Serial.println();
    }
  }
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "scan") runScan();
  }
}
