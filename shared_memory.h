#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "counter.h"

void init_shared_memory() {
  int fd;

  if(fd = shm_open("/host_packet_counter", O_CREAT|O_RW, 0666) == -1) {
    printf("shm_open fails %d\n", errno);
    exit(1);
  }

  ftruncate(fd, sizeof(shared_info_t));

  shared_info = mmap(NULL, sizeof(shared_info_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(shared_info == (void *)-1) {
    printf("mmap fails %d\n", errno);
    exit(1);
  }
}
