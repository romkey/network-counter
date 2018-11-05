#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 

#include "counter.h"

#define PCAP_DEVICE "eth0"
//#define PCAP_DEVICE "en0"

struct snaphdr {
  u_char pcp:3;
  u_char dei:1;
  unsigned short vid:12;
  u_char ethertype[2];
};

#define SNAPLEN 4

#if 0
#define IS_LOCAL(net1, net2) (net1 == 10 && net2 == 10)
#define IS_BROADCAST(host) (host == 255)
#define IS_MULTICAST(net) (net >= 224 && net <= 239)
#define IS_RX(net) (net != 10)
#endif

#define IS_LOCAL(src_bytes, dst_bytes) (src_bytes[0] == 10 && dst_bytes[0] == 10)
#define IS_BROADCAST(dst_bytes) (dst_bytes[3] == 255)
#define IS_MULTICAST(dst_bytes) (dst_bytes[0] >= 224 && dst_bytes[0] <= 239)
#define IS_RX(src_bytes) (src_bytes[0] != 10)
#define IS_TX(src_bytes) (src_bytes[0] == 10)

void check_host(int host) {
  if(host < 0 || host > 255) {
    printf("invalid host number! %d\n", host);
    exit(1);
  }
}

void add_rx_counter(int host, unsigned length) {
  check_host(host);

  volatile counter_t *host_counts = shared_info->hosts[shared_info->current_page];

  host_counts[host].rx_byte_count += length;
  host_counts[host].rx_pkt_count++;

  host_counts[host].last_seen = time(NULL);
}

void add_tx_counter(int host, unsigned length) {
  check_host(host);

  volatile counter_t *host_counts = shared_info->hosts[shared_info->current_page];

  host_counts[host].tx_byte_count += length;
  host_counts[host].tx_pkt_count++;

  host_counts[host].last_seen = time(NULL);
}

void add_broadcast_counter(int host, unsigned length) {
  check_host(host);

  volatile counter_t *host_counts = shared_info->hosts[shared_info->current_page];

  host_counts[host].broadcast_byte_count += length;
  host_counts[host].broadcast_pkt_count++;

  host_counts[host].last_seen = time(NULL);
}

void add_multicast_counter(int host, unsigned length) {
  check_host(host);

  volatile counter_t *host_counts = shared_info->hosts[shared_info->current_page];

  host_counts[host].multicast_byte_count += length;
  host_counts[host].multicast_pkt_count++;

  host_counts[host].last_seen = time(NULL);
}

struct ip *get_ip_hdr(struct ether_header *ether) {
  if(ntohs(ether->ether_type) == 0x0800)
    return (struct ip *)((u_char *)ether + sizeof(struct ether_header));

  // 802.1q - VLAN encapsulation
  if(ntohs(ether->ether_type) == 0x8100)
    return (struct ip *)((u_char *)ether + sizeof(struct ether_header) + sizeof(struct snaphdr));

  return NULL;    
}


void show_counts() {
  static time_t last_time = 0;
  int i;

  volatile counter_t *host_counts = shared_info->hosts[shared_info->current_page];

  for(i = 0; i < 256; i++) {
    if((host_counts[i].last_seen < last_time) || (host_counts[i].last_seen == 0 && host_counts[i].rx_byte_count == 0 && host_counts[i].tx_byte_count == 0))
      continue;

    printf("host %d: bytes - rx %lu, tx %lu; pkts rx %lu, tx %lu\n",
	   i,
	   host_counts[i].rx_byte_count, host_counts[i].tx_byte_count,
	   host_counts[i].rx_pkt_count, host_counts[i].rx_pkt_count);
  }

  last_time = time(NULL);
}

void ether_addr_to_s(u_char *addr, char *buffer) {
  int i = 0;

  for(i = 0; i < 6; i++) {
    sprintf(buffer + i*3, "%02x", addr[i]);
    if(i != 5)
      strcat(buffer, ":");
  }
}

void show_pkt(const u_char *pkt, int len) {
  int i;
  struct ether_header *eth = (struct ether_header *)pkt;
  struct ip *ip;
  char ether_dst[18];
  char ether_src[18];
  char ip_src[INET_ADDRSTRLEN];
  char ip_dst[INET_ADDRSTRLEN];

  ip = get_ip_hdr(eth);

  printf("\n");
  ether_addr_to_s(eth->ether_dhost, ether_dst);
  ether_addr_to_s(eth->ether_shost, ether_src);
  printf("%s -> %s  %04x\n", ether_dst, ether_src, ntohs(eth->ether_type));

  if(ip == NULL) {
    printf("No IP header!\n");
    return;
  }


  printf("ip prot %d, tos %d, ttl %d, len %d\n", ip->ip_p, ip->ip_tos, ip->ip_ttl, ip->ip_len);

  inet_ntop(AF_INET, &ip->ip_src, ip_src, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &ip->ip_dst, ip_dst, INET_ADDRSTRLEN);

  printf("ip %s -> %s\n", ip_src, ip_dst);
	u_char *src_bytes = (u_char *)&ip->ip_src;

	//	printf("...bytes %d, %d, %d, %d\n", src_bytes[0],  src_bytes[1],  src_bytes[2],  src_bytes[3]);

  printf("\n");

  len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);

  for(i = 0; i < len; i++) {
    printf("%02x ", pkt[i]);
    if(i && (i % 10 == 0))
      printf("\n");
  }
}

int main(int argc, char **argv) {
  char pcap_error[PCAP_ERRBUF_SIZE];
  int ret;
  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  pcap_t* descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *ether_hdr;
  u_char *ptr;
  int i;
  char *device;
  pcap_t *pcap;

  init_shared_memory(1);

  volatile counter_t *host_counts = shared_info->hosts[0];

  memset((void *)&host_counts, 0, sizeof(host_counts));

#ifdef PCAP_FILE
  pcap = pcap_open_offline(PCAP_FILE, pcap_error);
#else
  pcap = pcap_create(PCAP_DEVICE, pcap_error);
  pcap_set_buffer_size(pcap, 65536*1024);
  pcap_set_snaplen(pcap, sizeof(struct pcap_pkthdr) + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + 8);
  pcap_set_promisc(pcap, 1);
  pcap_activate(pcap);
#endif

  if(pcap == NULL)     {
    printf("pcap_open_live(): %s\n", pcap_error);
    exit(1);
  }

  while(1) {
    packet = pcap_next(pcap, &hdr);

    if(packet == NULL) {
      show_counts();

      printf("pcap failure");
      exit(1);
    }

    //        printf("packet length %d\n", hdr.caplen);
    ether_hdr = (struct ether_header *)packet;
    struct ip *ip_hdr = get_ip_hdr(ether_hdr);

    if(ip_hdr == NULL) {
#ifdef VERBOSE
      printf("No IP header; ether type %04x\n", ntohs(ether_hdr->ether_type));
#endif
      continue;
    }

    //	printf("IP protocol %d\n", ip_hdr->ip_p);

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, str, INET_ADDRSTRLEN);
    //printf("IP source %s\n", str);

#ifdef VERBOSE
    show_pkt(packet, hdr.len);
#endif

    u_char *src_bytes = (u_char *)&ip_hdr->ip_src;
    u_char *dst_bytes = (u_char *)&ip_hdr->ip_dst;

    //	printf("...bytes %d, %d, %d, %d\n", src_bytes[0],  src_bytes[1],  src_bytes[2],  src_bytes[3]);

    if(IS_LOCAL(src_bytes, dst_bytes)) {
#ifdef VERBOSE
      printf("LOCAL\n\n\n");
#endif
      continue;
    }

    if(IS_BROADCAST(dst_bytes)) {
#ifdef VERBOSE
      printf("BROADCAST\n\n\n");
#endif
      add_broadcast_counter(src_bytes[3], ip_hdr->ip_len);
      continue;
    }

    if(IS_MULTICAST(dst_bytes)) {
#ifdef VERBOSE
      printf("MULTICAST\n\n\n");
#endif
      add_multicast_counter(src_bytes[3], ip_hdr->ip_len);
      continue;
    }

    if(IS_RX(src_bytes)) {
#ifdef VERBOSE
      printf("RX %d\n\n\n", dst_bytes[3]);
#endif
      add_rx_counter(dst_bytes[3], ip_hdr->ip_len);
    } else {
#ifdef VERBOSE
      printf("TX %d\n\n\n", src_bytes[3]);
#endif
      add_tx_counter(src_bytes[3], ip_hdr->ip_len);
    }

#ifdef VERBOSE
    show_counts();
#endif
  }
}
