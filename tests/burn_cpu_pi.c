#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
void burn_cpu_pi_loop() {
  volatile double pi = 0.0;
  int64_t i = 0;
  while (1) {
    double term = (i % 2 == 0 ? 1.0 : -1.0) / (2.0 * i + 1);
    pi += term;
    i++;
  }
}

// uint64_t test_thread() {
//   // create a test thread

//   pthread_t thread;
//   uint64_t tid = 0;
//   int err =
//       pthread_create(&thread, NULL, (void *(*)(void *))burn_cpu_pi_loop, NULL);
//   if (err != 0) {
//     fprintf(stderr, "Failed to create thread: %s\n", strerror(err));
//     return 0;
//   }

//   err = pthread_threadid_np(thread, &tid);
//   if (err != 0) {
//     fprintf(stderr, "Failed to get thread id: %s\n", strerror(err));
//     return 0;
//   }
//   return tid;
// }
int main(int argc, const char *argv[]) {
  // create a thread to burn CPU
  


  uint64_t tid=0;
  pthread_threadid_np(pthread_self(), &tid);

  printf("process id: %d\n", getpid());
  printf("Main thread with TID: %llu\n", (unsigned long long)tid);
  burn_cpu_pi_loop();
  return 0;
}