#include <inttypes.h>

/**
 Scalar type to present a time;
 */
typedef long double s3sim_time_t;

extern void s3sim_secnsec_to_timet(s3sim_time_t *time, uint32_t sec, uint32_t nsec);
extern void s3sim_timet_to_secnsec(uint32_t *sec, uint32_t *nsec, s3sim_time_t time);
extern double   s3sim_sleep(double tdiff);
extern uint32_t s3sim_coarse_time;
extern uint32_t s3sim_nanosec;
