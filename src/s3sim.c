#include "s3sim.h"

#include <time.h>
// nanosleep
#include <sys/time.h>
// gettimeofday
#include <math.h>
// floor

/**
 Convert the presentation of a time from a combination of sec and nsec to s3sim_time_t.
 @param time [out]
 @param sec [in]
 @param nsec [in]
 */
void s3sim_secnsec_to_timet(s3sim_time_t *time, uint32_t sec, uint32_t nsec){
  *time = ((s3sim_time_t) sec) + ((s3sim_time_t) nsec) * 1e-9L;
}

/**
 Convert the presentation of a time from s3sim_time_t to a combination of sec and nsec.
 @param sec [out]
 @param nsec [out]
 @param time [in]
*/
void s3sim_timet_to_secnsec(uint32_t *sec, uint32_t *nsec, s3sim_time_t time){
  *sec = floorl(time);
  *nsec = (time - *sec) * 1e9L;
}


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
