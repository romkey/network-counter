#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>

typedef struct count {
  unsigned long rx_byte_count;
  unsigned long tx_byte_count;

  unsigned long rx_pkt_count;
  unsigned long tx_pkt_count;

  unsigned long broadcast_byte_count;
  unsigned long broadcast_pkt_count;

  unsigned long multicast_byte_count;
  unsigned long multicast_pkt_count;

  time_t last_seen;
} counter_t;

typedef struct {
  volatile int current_page;
  volatile counter_t hosts[2][256];
} shared_info_t;

extern counter_t host_counts[256];

extern volatile shared_info_t *shared_info;

extern void init_shared_memory(int clear);

extern sem_t *counters_mutex;
