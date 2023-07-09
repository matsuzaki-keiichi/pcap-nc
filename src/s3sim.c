#include "s3sim.h"

#include <time.h>
// nanosleep
#include <sys/time.h>
// gettimeofday
#include <math.h>
// floor

double s3sim_sleep(double tdiff){

  if ( tdiff <= 0.0 ) {
    return 0.0;
  }

  const double coarse_dtime = floor(tdiff);
  const long fine_dtime = (long)((tdiff - coarse_dtime) * 1e9);
  struct timespec ts_req = {(time_t)coarse_dtime, fine_dtime};
  struct timespec ts_rem;
  
  int iret = 1;
  while (iret) {
    iret = nanosleep(&ts_req, &ts_rem);
    ts_req.tv_sec  = ts_rem.tv_sec;
    ts_req.tv_nsec = ts_rem.tv_nsec;
  }
  
  return 0.0;
}

uint32_t s3sim_coarse_time = 0x00000000;
uint32_t s3sim_nanosec     = 0x00000000;
