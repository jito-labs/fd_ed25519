#include "../fd_util.h"
#if FD_HAS_HOSTED
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define TEST_DEQUE_MAX (8UL)

static int   buf[ TEST_DEQUE_MAX ];
static ulong buf_start = 0UL;
static ulong buf_end   = 0UL;
static ulong buf_cnt   = 0UL;

static void
buf_push_head( int i ) {
  FD_TEST( buf_cnt<TEST_DEQUE_MAX );
  buf_cnt++; buf_start--; if( buf_start>=TEST_DEQUE_MAX ) buf_start = TEST_DEQUE_MAX-1UL;
  buf[ buf_start ] = i;
}

static void
buf_push_tail( int i ) {
  FD_TEST( buf_cnt<TEST_DEQUE_MAX );
  buf[ buf_end ] = i;
  buf_cnt++; buf_end++; if( buf_end>=TEST_DEQUE_MAX ) buf_end = 0UL;
}

static int
buf_pop_head( void ) {
  FD_TEST( buf_cnt );
  int i = buf[ buf_start ];
  buf_cnt--; buf_start++; if( buf_start>=TEST_DEQUE_MAX ) buf_start = 0UL;
  return i;
}

static int
buf_pop_tail( void ) {
  FD_TEST( buf_cnt );
  buf_cnt--; buf_end--; if( buf_end>=TEST_DEQUE_MAX ) buf_end = TEST_DEQUE_MAX-1UL;
  return buf[ buf_end ];
}

static int
buf_pop_idx( ulong idx ) {
  FD_TEST( buf_cnt );
  buf_cnt--; buf_end--; if( buf_end>=TEST_DEQUE_MAX ) buf_end = TEST_DEQUE_MAX-1UL;
  int val = buf[ (buf_start+idx) % TEST_DEQUE_MAX ];
  ulong gap = idx;
  while( gap<=buf_cnt ) {
    ulong i = (buf_start+gap  )%TEST_DEQUE_MAX;
    ulong j = (buf_start+gap+1)%TEST_DEQUE_MAX;
    buf[i] = buf[j];
    gap++;
  }
  return val;
}

#define DEQUE_NAME test_deque
#define DEQUE_T    int
#include "fd_deque_dynamic.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, TEST_DEQUE_MAX );
  if( FD_UNLIKELY( max>TEST_DEQUE_MAX ) )  {
    FD_LOG_WARNING(( "skip: increase TEST_DEQUE_MAX to support this level of --max" ));
    return 0;
  }
  if( FD_UNLIKELY( (test_deque_align()>SCRATCH_ALIGN) | (test_deque_footprint( max )>SCRATCH_FOOTPRINT) ) ) {
    FD_LOG_WARNING(( "skip: adjust scratch region and footprint to support this level of --max" ));
    return 0;
  }
  FD_LOG_NOTICE(( "--max %lu", max ));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = test_deque_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = test_deque_footprint( max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shdeque = test_deque_new ( scratch, max ); FD_TEST( shdeque );
  int *  deque   = test_deque_join( shdeque      ); FD_TEST( deque   );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( test_deque_max( deque )==max );
  FD_TEST( test_deque_cnt( deque )==0UL );

  FD_LOG_NOTICE(( "Testing operations" ));

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {

    /* Randomly pick an operation to do */

    int   op    = fd_rng_int_roll( rng, 17 ); /* in [0,17) */
    ulong r     = fd_rng_ulong( rng );
    int   val   = (int)(uint)r;      r >>= 32;
    int   reset = !(r & 65535UL);    r >>= 16;

    if( FD_UNLIKELY( reset ) ) {
      buf_start = 0UL;
      buf_end   = 0UL;
      buf_cnt   = 0UL;
      FD_TEST( test_deque_remove_all( deque )==deque );
    }

    switch( op ) {

    case 0: /* push head */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_head( val ); FD_TEST( test_deque_push_head( deque, val )==deque );
      break;

    case 1: /* push tail */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_tail( val ); FD_TEST( test_deque_push_tail( deque, val )==deque );
      break;

    case 2: /* pop head */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head(); FD_TEST( test_deque_pop_head( deque )==val );
      break;

    case 3: /* pop tail */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail(); FD_TEST( test_deque_pop_tail( deque )==val );
      break;

    case 4: /* zero-copy push head */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_head( val );
      FD_TEST( test_deque_insert_head( deque )==deque );
      *test_deque_peek_head( deque ) = val;
      break;

    case 5: /* zero-copy push tail */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_tail( val );
      FD_TEST( test_deque_insert_tail( deque )==deque );
      *test_deque_peek_tail( deque ) = val;
      break;

    case 6: /* zero-copy pop head */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head();
      FD_TEST( (*test_deque_peek_head_const( deque ))==val );
      FD_TEST( test_deque_remove_head( deque )==deque      );
      break;

    case 7: /* zero-copy pop tail */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail();
      FD_TEST( (*test_deque_peek_tail_const( deque ))==val );
      FD_TEST( test_deque_remove_tail( deque )==deque      );
      break;

    case 8: /* push head nocopy */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_head( val ); *test_deque_push_head_nocopy( deque ) = val;
      break;

    case 9: /* push tail nocopy */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push_tail( val ); *test_deque_push_tail_nocopy( deque ) = val;
      break;

    case 10: /* pop head nocopy */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head(); FD_TEST( *test_deque_pop_head_nocopy( deque )==val );
      break;

    case 11: /* pop tail nocopy */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail(); FD_TEST( *test_deque_pop_tail_nocopy( deque )==val );
      break;

    case 12: { /* iter */
      ulong i = buf_start;
      ulong j = 0UL;
      for( test_deque_iter_t iter = test_deque_iter_init( deque ); !test_deque_iter_done( deque, iter ); iter = test_deque_iter_next( deque, iter ) ) {
        int * ele = test_deque_iter_ele( deque, iter );
        FD_TEST( buf[i] == *ele );
        FD_TEST( test_deque_peek_index( deque, j ) == test_deque_peek_index_const( deque, j ) );
        FD_TEST( *test_deque_peek_index_const( deque, j ) == *ele );
        if ( ++i >= TEST_DEQUE_MAX )
          i = 0;
        j++;
      }
      FD_TEST( i == buf_end );
      FD_TEST( j == buf_cnt );
      break;
    }

    case 13: { /* iter reverse */
      long i = (long)buf_end - 1L;
      long j = (long)buf_cnt - 1L;
      for( test_deque_iter_t iter = test_deque_iter_init_rev( deque ); !test_deque_iter_done_rev( deque, iter ); iter = test_deque_iter_prev( deque, iter ) ) {
        if( i < 0L )
          i = (long)TEST_DEQUE_MAX - 1L;
        int * ele = test_deque_iter_ele( deque, iter );
        FD_TEST( j>=0L );
        FD_TEST( buf[i] == *ele );
        FD_TEST( test_deque_peek_index( deque, (ulong)j ) == test_deque_peek_index_const( deque, (ulong)j ) );
        FD_TEST( *test_deque_peek_index_const( deque, (ulong)j ) == *ele );
        i--;
        j--;
      }
      FD_TEST( i == (long)buf_start-1L );
      FD_TEST( j == -1L );
      break;
    }

    case 14: { /* pop index (shift tail to head) */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      ulong idx = fd_rng_uint_roll( rng, (uint)buf_cnt );
      val = buf_pop_idx( idx );
      FD_TEST( test_deque_pop_idx_tail( deque, idx )==val );
      break;
    }

    case 15: { /* push_head_wrap */
      if( FD_UNLIKELY( !max ) ) break; /* not valid on max 0 */
      if( FD_UNLIKELY( buf_cnt>=max ) ) (void)buf_pop_tail(); /* pop when full */
      buf_push_head( val );
      FD_TEST( test_deque_push_head_wrap( deque, val )==deque );
      break;
    }

    case 16: { /* push_tail_wrap */
      if( FD_UNLIKELY( !max ) ) break; /* not valid on max 0 */
      if( FD_UNLIKELY( buf_cnt>=max ) ) (void)buf_pop_head(); /* pop when full */
      buf_push_tail( val );
      FD_TEST( test_deque_push_tail_wrap( deque, val )==deque );
      break;
    }

    default: /* never get here */
      break;
    }

    FD_TEST( test_deque_max  ( deque )==max            );
    FD_TEST( test_deque_cnt  ( deque )==buf_cnt        );
    FD_TEST( test_deque_avail( deque )==(max-buf_cnt)  );
    FD_TEST( test_deque_empty( deque )==(!buf_cnt)     );
    FD_TEST( test_deque_full ( deque )==(buf_cnt==max) );
  }

  FD_TEST( test_deque_leave ( deque   )==shdeque         );
  FD_TEST( test_deque_delete( shdeque )==(void *)scratch );

  FD_LOG_NOTICE(( "Testing max==0 deque" ));

  shdeque = test_deque_new ( scratch, 0UL ); FD_TEST( shdeque );
  deque   = test_deque_join( shdeque      ); FD_TEST( deque   );

  FD_TEST( test_deque_max  ( deque )==0UL );
  FD_TEST( test_deque_cnt  ( deque )==0UL );
  FD_TEST( test_deque_avail( deque )==0UL );
  FD_TEST( test_deque_empty( deque )==1   );
  FD_TEST( test_deque_full ( deque )==1   );

  for( test_deque_iter_t iter=test_deque_iter_init( deque );
       !test_deque_iter_done( deque, iter );
       iter = test_deque_iter_next( deque, iter ) ) {
    int never_get_here = 1;
    FD_TEST( never_get_here );
  }

  for( test_deque_iter_t iter=test_deque_iter_init_rev( deque );
       !test_deque_iter_done_rev( deque, iter );
       iter = test_deque_iter_prev( deque, iter ) ) {
    int never_get_here = 1;
    FD_TEST( never_get_here );
  }

  FD_TEST( test_deque_leave ( deque   )==shdeque         );
  FD_TEST( test_deque_delete( shdeque )==(void *)scratch );

#if FD_HAS_HOSTED && FD_TMPL_USE_HANDHOLDING
  #define FD_EXPECT_LOG_CRIT( CALL ) do {                          \
    FD_LOG_DEBUG(( "Testing that "#CALL" triggers FD_LOG_CRIT" )); \
    pid_t pid = fork();                                            \
    FD_TEST( pid >= 0 );                                           \
    if( pid == 0 ) {                                               \
      /* we don't want to confuse the user with an ERR log */      \
      fd_log_level_logfile_set( 6 );                               \
      __typeof__(CALL) res = (CALL);                               \
      __asm__("" : "+r"(res));                                     \
      _exit( 0 );                                                  \
    }                                                              \
    int status = 0;                                                \
    wait( &status );                                               \
                                                                   \
    FD_TEST( WIFSIGNALED(status) && WTERMSIG(status)==6 );         \
  } while( 0 )                                                     \

  shdeque = test_deque_new ( scratch, max ); FD_TEST( shdeque );
  deque   = test_deque_join( shdeque      ); FD_TEST( deque   );

  FD_LOG_NOTICE(( "Testing invalid arguments to DEQUE_({new,join})" ));
  FD_EXPECT_LOG_CRIT( test_deque_new   ( NULL                     , TEST_DEQUE_MAX ) );
  FD_EXPECT_LOG_CRIT( test_deque_new   ( (void*)((char*)scratch+1), TEST_DEQUE_MAX ) );
  FD_EXPECT_LOG_CRIT( test_deque_delete( NULL ) );
  FD_EXPECT_LOG_CRIT( test_deque_delete( (void*)((char*)scratch+1) ) );

  FD_LOG_NOTICE(( "Testing boundary conditions of operations on a full/empty deque" ));
  for( ulong i=test_deque_cnt( deque ); i<TEST_DEQUE_MAX; i++ ) {
    FD_TEST( test_deque_push_tail( deque, (int)i )==deque );
  }
  FD_TEST( test_deque_full( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_push_tail       ( deque, 42 ) );
  FD_EXPECT_LOG_CRIT( test_deque_push_head       ( deque, 42 ) );
  FD_EXPECT_LOG_CRIT( test_deque_push_head_nocopy( deque     ) );
  FD_EXPECT_LOG_CRIT( test_deque_push_head_nocopy( deque     ) );
  FD_EXPECT_LOG_CRIT( test_deque_insert_head     ( deque     ) );
  FD_EXPECT_LOG_CRIT( test_deque_insert_tail     ( deque     ) );
  FD_TEST( test_deque_push_tail_wrap( deque, 23 )==deque );
  FD_TEST( test_deque_push_head_wrap( deque, 23 )==deque );
  FD_EXPECT_LOG_CRIT( test_deque_push_tail       ( deque, 42 ) );
  FD_EXPECT_LOG_CRIT( test_deque_push_head       ( deque, 42 ) );

  FD_TEST( test_deque_remove_all( deque )==deque );
  FD_EXPECT_LOG_CRIT( test_deque_pop_head       ( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_pop_tail       ( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_pop_head_nocopy( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_pop_tail_nocopy( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_peek_tail      ( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_peek_head      ( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_peek_tail_const( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_peek_head_const( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_remove_head    ( deque ) );
  FD_EXPECT_LOG_CRIT( test_deque_remove_tail    ( deque ) );

  FD_TEST( test_deque_push_tail( deque, 23 )==deque );
  test_deque_iter_t iter = test_deque_iter_init( deque );
  for( ; !test_deque_iter_done( deque, iter ); iter = test_deque_iter_next( deque, iter ) ) ;
  iter = test_deque_iter_next( deque, iter );
  FD_EXPECT_LOG_CRIT( test_deque_iter_ele_const( deque, iter ) );
  FD_EXPECT_LOG_CRIT( test_deque_iter_ele( deque, iter ) );
  FD_TEST( test_deque_leave ( deque   )==shdeque         );
  FD_TEST( test_deque_delete( shdeque )==(void *)scratch );

  FD_LOG_NOTICE(( "Testing handholding on max=0 deque" ));
  shdeque = test_deque_new ( scratch, 0UL ); FD_TEST( shdeque );
  deque   = test_deque_join( shdeque      ); FD_TEST( deque   );
  FD_EXPECT_LOG_CRIT( test_deque_push_tail_wrap( deque, 23 )==deque );
  FD_EXPECT_LOG_CRIT( test_deque_push_head_wrap( deque, 23 )==deque );
  FD_TEST( test_deque_leave ( deque   )==shdeque         );
  FD_TEST( test_deque_delete( shdeque )==(void *)scratch );

#else
  FD_LOG_WARNING(( "skip: testing handholding, requires hosted" ));
#endif

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
