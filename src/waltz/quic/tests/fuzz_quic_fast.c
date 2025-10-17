#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


#include "../../../util/sanitize/fd_fuzz.h"

#pragma GCC diagnostic ignored "-Wunused-function"
#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "../fd_quic_proto.h"

#include "fd_quic_test_helpers.h"

struct container {
  fd_quic_t *server_quic;
  fd_quic_t *cli_quic;
  fd_rng_t * rng;
  fd_aio_t * aio;
};
typedef struct container container_t;
static FD_TL long g_clock = 1L;

static container_t fuzz_ctx;

uchar scratch[0x4000];
size_t scratch_sz = 0x4000;

fd_aio_t _aio[1];

int test_aio_send_func(void *ctx, fd_aio_pkt_info_t const *batch,
                       ulong batch_cnt, ulong *opt_batch_idx, int flush) {
  (void)flush;
  (void)batch;
  (void)batch_cnt;
  (void)opt_batch_idx;
  (void)ctx;
  return 0;
}


int LLVMFuzzerInitialize(int *argc, char ***argv) {
  /* Set up shell without signal handlers */
  putenv("FD_LOG_BACKTRACE=0");
  fd_boot(argc, argv);
  fd_log_level_core_set(3); /* crash on warning log */
  atexit(fd_halt);
  fd_log_level_stderr_set(0);
  fd_log_level_logfile_set(0);
  fd_log_level_flush_set( 3);

  fd_rng_t _rng[1]; fuzz_ctx.rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Memory region to hold the QUIC instance */
  static uchar quic_mem[ 1<<23 ] __attribute__((aligned(FD_QUIC_ALIGN)));

  /* Create ultra low limits for QUIC instance for maximum performance */
  fd_quic_limits_t const quic_limits = {
    .conn_cnt           = 2,
    .handshake_cnt      = 2,
    .conn_id_cnt        = 4,
    .inflight_frame_cnt = 16UL,
    .stream_pool_cnt    = 8UL,
    .tx_buf_sz          = 1UL<<8UL
  };

  assert( fd_quic_footprint( &quic_limits ) <= sizeof(quic_mem) );
  void *      shquic = fd_quic_new( quic_mem, &quic_limits );
  fuzz_ctx.server_quic    = fd_quic_join( shquic );

  fd_quic_config_anonymous( fuzz_ctx.server_quic , FD_QUIC_ROLE_SERVER );
  FD_TEST( fuzz_ctx.server_quic );
  
  // static uchar cquic_mem[ 1<<23 ] __attribute__((aligned(FD_QUIC_ALIGN)));
  // fuzz_ctx.cli_quic  = fd_quic_join( fd_quic_new( cquic_mem, &quic_limits) );
  // fd_quic_config_anonymous( fuzz_ctx.cli_quic , FD_QUIC_ROLE_CLIENT );
  // FD_TEST( fuzz_ctx.cli_quic );
  
  fd_memcpy( fuzz_ctx.server_quic ->config.identity_public_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32 );
  fuzz_ctx.server_quic->config.retry = 0;
	fuzz_ctx.server_quic->config.keep_alive = 1;
  fuzz_ctx.server_quic->config.ack_delay    = 1e6;
  fuzz_ctx.server_quic->config.idle_timeout = 1e7;


  fd_aio_t aio_[1];
  fuzz_ctx.aio = fd_aio_join( fd_aio_new( aio_, NULL, test_aio_send_func ) );
  assert( fuzz_ctx.aio  );

  fd_quic_set_aio_net_tx( fuzz_ctx.server_quic , fuzz_ctx.aio );
  assert( fd_quic_init( fuzz_ctx.server_quic  ) );
  assert( fuzz_ctx.server_quic ->config.idle_timeout > 0 );  
  g_clock    = 1000L;
  return 0;
}

void
schedule_conn(fd_quic_conn_t* conn, fd_quic_state_t * state) {
  assert( conn );
  fd_quic_svc_timers_schedule( state->svc_timers, conn, g_clock );
  {
    fd_quic_svc_event_t event = fd_quic_svc_timers_get_event( state->svc_timers, conn, g_clock );
    assert( event.conn );
    assert( event.timeout > g_clock );
  }
}

fd_quic_conn_t*
create_dummy_conn(fd_quic_state_t * state)
{
   /* Create dummy connection */
  ulong             our_conn_id  = ULONG_MAX;
  fd_quic_conn_id_t peer_conn_id = { .sz=8 };
  uint              dst_ip_addr  = 0U;
  ushort            dst_udp_port = (ushort)0;

  fd_quic_conn_t * conn =
    fd_quic_conn_create( fuzz_ctx.server_quic,
                         our_conn_id, &peer_conn_id,
                         dst_ip_addr,  (ushort)dst_udp_port,
                         0U, 0U,
                         1  /* we are the server */ );
  if(!conn) return NULL;

  conn->tx_max_data                            =       512UL;
  conn->tx_initial_max_stream_data_uni         =        64UL;
  conn->srx->rx_max_data                       =       512UL;
  conn->srx->rx_sup_stream_id                  =        32UL;
  conn->tx_max_datagram_sz                     = FD_QUIC_MTU;
  conn->tx_sup_stream_id                       =        32UL;
	schedule_conn(conn ,state);
  return conn;
}

void
invoke_service(void)
{  
  /* service all 'instant' events */
  fd_quic_service( fuzz_ctx.server_quic, g_clock );


  // while( g_clock == fd_quic_svc_timers_next( state->svc_timers, g_clock, pop ).timeout ) {
  //   fd_quic_service( fuzz_ctx.cli_quic, g_clock );
  //   assert( --svc_quota > 0 );
  // }  
}

static void
send_udp_packet( fd_quic_t *   quic,
                 uchar const * data,
                 ulong         size , uchar dcid) {

  uchar buf[16384] = {0};

  ulong headers_sz = sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

  uchar * cur = buf;
  uchar * end = buf + sizeof(buf);

  fd_ip4_hdr_t ip4 = {
    .verihl      = FD_IP4_VERIHL(4,5),
    .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
    .net_tot_len = (ushort)( sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)+size ),
  };
  fd_udp_hdr_t udp = {
    .net_sport = 8000,
    .net_dport = 8001,
    .net_len   = (ushort)( sizeof(fd_udp_hdr_t)+size ),
    .check     = 0
  };

  /* Guaranteed to not overflow */
  fd_quic_encode_ip4( cur, (ulong)( end-cur ), &ip4 ); cur += sizeof(fd_ip4_hdr_t);
  fd_quic_encode_udp( cur, (ulong)( end-cur ), &udp ); cur += sizeof(fd_udp_hdr_t);

  if( cur + size > end ) return;
  
	fd_memcpy( cur, data, size );
	// long pkt type
 	// *cur++ = (uchar)( 0xC0 | (dcid<<4) | 1 );
  cur++;
	//version
  *cur++ = 0x00; *cur++ = 0x00; *cur++ = 0x00; *cur++ = 0x01; 
  *cur++ = sizeof(dcid);
  fd_memcpy( cur, &dcid, sizeof(dcid));

	(void)dcid;
		
  /* Main fuzz entrypoint */

  fd_quic_process_packet( quic, buf, headers_sz + size, g_clock );
}

static fd_quic_conn_t *
find_active_conn( fd_quic_t * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );
  for( ulong i = 0; i < quic->limits.conn_cnt; i++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, i );
    if( conn && conn->state != FD_QUIC_CONN_STATE_INVALID ) return conn;
  }
  return NULL;
}


bool ConsumeBytes(const uint8_t **data, size_t *size, void *out, size_t n) {
    if (*size < n) {
        return false;  // Not enough data
    }
    
    memcpy(out, *data, n);
    *data += n;
    *size -= n;
    return true;
}

// Convenience wrappers
bool ConsumeUint8(const uint8_t **data, size_t *size, uint8_t *out) {
    return ConsumeBytes(data, size, out, 1);
}

bool ConsumeUint16(const uint8_t **data, size_t *size, uint16_t *out) {
    return ConsumeBytes(data, size, out, 2);
}

bool ConsumeUint32(const uint8_t **data, size_t *size, uint32_t *out) {
    return ConsumeBytes(data, size, out, 4);
}

bool ConsumeUint64(const uint8_t **data, size_t *size, uint64_t *out) {
    return ConsumeBytes(data, size, out, 8);
}

uchar max_map_id = 6;
uchar nops = 5;


int LLVMFuzzerTestOneInput(uchar const *data, ulong size) {
  // uchar const *ptr = data;

  fd_quic_state_t * state = fd_quic_get_state( fuzz_ctx.server_quic );
  g_clock++;
  state->now = g_clock;
	uchar burst;
	uchar dice_roll;
	fd_quic_conn_t* conn;
	uint val;
	size_t send_size;

	while(size) {
		FD_FUZZ_MUST_BE_COVERED;
		if(!ConsumeUint8(&data, &size, &burst)){
			return 0;
		}
		burst = burst % max_map_id;
		if(!ConsumeUint8(&data, &size, &dice_roll)){
			return 0;
		}
		dice_roll = dice_roll % nops;
		if(!ConsumeUint32(&data, &size, &val)){
			return 0;
		}				
		switch(dice_roll){
			case 0: //conn create
				FD_FUZZ_MUST_BE_COVERED;
				conn = create_dummy_conn(state);
				break;
			case 1: //send packet
				FD_FUZZ_MUST_BE_COVERED;
				if (burst && (size % burst)==0){
					for(uint k = 1; k <= (size/burst); k++) {
						FD_FUZZ_MUST_BE_COVERED;
						send_size = (size/burst) * k;
						send_udp_packet( fuzz_ctx.server_quic, data, send_size, dice_roll );
						size -= send_size;
						data += send_size;						
					}
				} else {
					FD_FUZZ_MUST_BE_COVERED;
					send_size = (size < 1500) ? size : 1500; 
					send_udp_packet( fuzz_ctx.server_quic, data, send_size, dice_roll );
					size -= send_size;
					data += send_size;
				}
				break;
			case 2: //service
				FD_FUZZ_MUST_BE_COVERED;
        for( ulong j=0; j<20; ++j ) {
				  invoke_service();
        }
				break;
			case 3: //close
				FD_FUZZ_MUST_BE_COVERED;
				conn = find_active_conn( fuzz_ctx.server_quic );
				if (conn) {
					fd_quic_conn_close( conn, val );
				}
				break;
      case 4:
        // fd_quic_connect( fuzz_ctx.cli_quic, 0U, 0, 0U, 0, g_clock );
        break;
			default:
				break;
		}
	}


  FD_FUZZ_MUST_BE_COVERED;
  // fd_quic_delete( fd_quic_leave( fd_quic_fini( fuzz_ctx.server_quic ) ) );
  // fd_aio_delete( fd_aio_leave( fuzz_ctx.aio ) );
  // fd_rng_delete( fd_rng_leave( fuzz_ctx.rng ) );  
  return 0;
}
