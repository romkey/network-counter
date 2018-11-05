#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include "counter.h"

volatile shared_info_t *shared_info = NULL;

sem_t *counters_mutex;

void init_shared_memory(int clear) {
  int fd;

  fd = shm_open("/host_packet_counter", O_CREAT|O_RDWR, 0666);
  if(fd == -1) {
    printf("shm_open fails %d\n", errno);
    exit(1);
  }

  ftruncate(fd, sizeof(shared_info_t));

  printf("shared memory length %lu\n", sizeof(shared_info_t));
  //  printf("page size %d\n", _POSIX_PAGESIZE);

  //  shared_info = mmap(NULL, sizeof(shared_info_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  shared_info = mmap(NULL, 4096*10, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(shared_info == (void *)-1) {
    printf("mmap fails %d\n", errno);
    exit(1);
  }

  if(clear)
    memset((void *)shared_info, 0, sizeof(shared_info_t));

#if 0
  counters_mutex = sem_open("shared_info_mutex", O_CREAT|O_RDWR, 0);
#endif 
}
#if 0
void wait_till_mutex() {
  sem_wait(counters_mutex);
}

void mark_mutex() {
  sem_post(counters_mutex);
}
#endif
