#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "counter.h"

void show_counts() {
  static time_t last_time = 0;
  int i;

  volatile counter_t *host_counts = shared_info->hosts[0];

  for(i = 0; i < 256; i++) {
    if(host_counts[i].last_seen < last_time)
      continue;

    printf("host %d: bytes - rx %lu, tx %lu; pkts rx %lu, tx %lu\n",
	   i,
	   host_counts[i].rx_byte_count, host_counts[i].tx_byte_count,
	   host_counts[i].rx_pkt_count, host_counts[i].rx_pkt_count);
  }

  last_time = time(NULL);

  printf("\n\n");
}

#define MAX_COUNTER_JSON_LENGTH 2 + (8 + 2 + 9 + 2) * 2 + (10 + 2 + 9 + 2) * 2 + (24 + 2 + 9 + 2)*4+ + 2    + 500

char *count_to_json(int host, volatile counter_t *counter) {
  static char buffer[MAX_COUNTER_JSON_LENGTH];

  snprintf(buffer, MAX_COUNTER_JSON_LENGTH,
	   "{ \"host\": %d, \"rx_bytes\": %lu, \"tx_bytes\": %lu, \"rx_packets\": %lu, \"tx_packets\": %lu, \"broadcast_bytes\": %lu, \"broadcast_packets\": %lu, \"multicast_bytes\": %lu, \"multicast_packets\": %lu }",
	   host,
	   counter->rx_byte_count, counter->tx_byte_count,
	   counter->rx_pkt_count, counter->tx_pkt_count,
	   counter->broadcast_byte_count, counter->broadcast_pkt_count,
	   counter->multicast_byte_count, counter->multicast_pkt_count);
  
  return buffer;
}


char *counts_to_json(int page) {
  static char buffer[(MAX_COUNTER_JSON_LENGTH + 6)*256 + 8 + 1024] = "";
  int i;
  int first = 1;

  volatile counter_t *host_counts = shared_info->hosts[page];

  strcpy(buffer, "{ \"counts\": [ ");

  for(i = 0; i < 256; i++) {
    if(host_counts[i].rx_byte_count == 0 && host_counts[i].tx_byte_count == 0)
      continue;

    if(first) {
      first = 0;
    } else {
      strcat(buffer, ",\n");
    }

    strcat(buffer, count_to_json(i, &host_counts[i]));
  }

  strcat(buffer, " ] }\n");

  return buffer;
}

void upload_counts(char *json) {
  FILE *file = fopen("counts.json", "w");
  fputs(json, file);
  fclose(file);

  system("curl --header \"Content-Type: application/json\"   --request POST   --data @counts.json https://net-use.herokuapp.com/counters/create_many");
  //  system("curl --header \"Content-Type: application/json\"   --request POST   --data @counts.json http://localhost:3000/counters/create_many");
}

int main(int argc, char **argv) {
  init_shared_memory(0);

  while(1) {
    sleep(60);

    /* lock index
     * alternate index
     * unlock index
     *
     * generate json
     * clear counters
     * upload json
     *
     * sleep
     */
    int old_page = shared_info->current_page;

    if(shared_info->current_page == 0)
      shared_info->current_page = 1;
    else
      shared_info->current_page = 0;

    char *str = counts_to_json(old_page);

    memset((void *)shared_info->hosts[old_page], 0, sizeof(counter_t)*256);

    upload_counts(str);

    puts(str);

    puts("");
    puts("");
    puts("");
  }
}
