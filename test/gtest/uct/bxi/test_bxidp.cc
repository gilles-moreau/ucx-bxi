#include <uct/bxi/test_bxidp.h>

extern "C" {
#include <uct/bxi/bxi_ep.h>
#include <uct/bxi/bxi_iface.h>
}

#define NSAMPLES 1000
#define WARMUP   100

#define NOP_MIN           0
#define NOP_MAX           1000
#define NOP_STEP          100
#define NOP_CALIB_ITERS   10000
#define TSC_CYCLES_PER_US 2594.890

static UCS_F_ALWAYS_INLINE void run_nops(size_t nop_count)
{
  for (size_t i = 0; i < nop_count; ++i)
    asm volatile("nop");
}

/*
 * Measure the average execution time of one run_nops(nop_count) call.
 * The caller may subtract the value obtained with nop_count == 0 to remove
 * the outer calibration-loop overhead.
 */
static double measure_nop_loop_us(size_t nop_count)
{
  ucs_time_t start, stop;

  for (size_t i = 0; i < WARMUP; ++i)
    run_nops(nop_count);

  ucs_compiler_fence();
  start = ucs_get_time();

  for (size_t i = 0; i < NOP_CALIB_ITERS; ++i)
    run_nops(nop_count);

  stop = ucs_get_time();
  ucs_compiler_fence();

  return ((double)(stop - start) / NOP_CALIB_ITERS) / TSC_CYCLES_PER_US;
}

void test_uct_bxidp::connect()
{
  m_e1->connect(0, *m_e2, 0);
  m_e2->connect(0, *m_e1, 0);

  uct_iface_set_am_handler(m_e1->iface(), 0, am_dummy_handler, NULL, 0);
  uct_iface_set_am_handler(m_e2->iface(), 0, am_dummy_handler, NULL, 0);
}

test_uct_bxidp::test_uct_bxidp() : m_e1(NULL), m_e2(NULL)
{
}

ucs_status_t test_uct_bxidp::send_am_message(entity *e, uint8_t am_id,
                                             ucs_status_t expected, int ep_idx)
{
  ssize_t res;
  uint8_t buffer = 1;

  res = uct_ep_am_short(e->ep(ep_idx), am_id, 0, &buffer, sizeof(buffer));
  return (ucs_status_t)(res >= 0 ? UCS_OK : res);
}

static int cmp_u64(const void *a, const void *b)
{
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;

  return (va > vb) - (va < vb);
}

static void print_stats(const char *name, uint64_t *samples, size_t n)
{
  uint64_t sum = 0;

  qsort(samples, n, sizeof(*samples), cmp_u64);

  for (size_t i = 0; i < n; ++i)
    sum += samples[i];

  printf("\n%s\n", name);
  printf("  min    : %" PRIu64 " cycles\n", samples[0]);
  printf("  median : %" PRIu64 " cycles\n", samples[n / 2]);
  printf("  p90    : %" PRIu64 " cycles\n", samples[(n * 90) / 100]);
  printf("  p99    : %" PRIu64 " cycles\n", samples[(n * 99) / 100]);
  printf("  max    : %" PRIu64 " cycles\n", samples[n - 1]);
  printf("  mean   : %.2f cycles\n", (double)sum / n);
  printf("  mean   : %.2f us\n", ((double)(sum) / n) / 2594.890);
}

static void measure_baseline(uint64_t *samples, size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    ucs_time_t start = ucs_get_time();

    ucs_compiler_fence();

    uint64_t stop = ucs_get_time();

    samples[i] = stop - start;
  }

  print_stats("TSC measurement overhead", samples, n);
}

template<typename T>
void measure_wc_write_sfence(const char *name, uct_bxi_iface_t *iface,
                             uint64_t *samples, size_t n)
{
  ucs_time_t         t0, t1;
  volatile uint64_t *slot, *addr;

  /* Warm-up */
  for (size_t i = 0; i < WARMUP; ++i) {
    uct_bxi_get_txslot(iface, &slot);

    addr  = (volatile uint64_t *)UCS_PTR_BYTE_OFFSET(slot, 56);
    *addr = 42;

    uct_bxi_txslot_commit(iface);
  }

  for (size_t i = 0; i < n; i++) {

    uct_bxi_get_txslot(iface, &slot);
    addr = (volatile uint64_t *)UCS_PTR_BYTE_OFFSET(slot, 56);

    ucs_compiler_fence();

    t0 = ucs_get_time();

    *addr = 42;

    ucs_memory_bus_store_fence();

    t1 = ucs_get_time();

    ucs_compiler_fence();

    uct_bxi_txslot_commit(iface);

    samples[i] = t1 - t0;
  }

  print_stats(name, samples, n);
}

template<typename T, typename U>
void measure_write_flush(const char *name, volatile T *addr,
                         volatile U *readback, T value, uint64_t *samples,
                         size_t n)
{
  ucs_time_t t0, t1;
  U          tmp;

  for (size_t i = 0; i < WARMUP; ++i) {
    *addr = value;
    ucs_memory_bus_store_fence();
    tmp ^= *readback;
  }

  for (size_t i = 0; i < n; i++) {

    ucs_compiler_fence();

    t0 = ucs_get_time();

    *addr = value;

    ucs_memory_bus_store_fence();

    tmp = *readback;

    t1 = ucs_get_time();

    ucs_compiler_fence();

    samples[i] = t1 - t0;
  }

  asm volatile("" ::"r"(tmp));
  print_stats(name, samples, n);
}

template<typename T>
static void measure_reads(const char *name, volatile T *addr, uint64_t *samples,
                          size_t n)
{
  T value = 0;

  for (int i = 0; i < 100; ++i)
    value ^= *addr;

  for (size_t i = 0; i < n; ++i) {
    uint64_t start, stop;

    ucs_compiler_fence();

    start = ucs_get_time();

    value ^= *addr;

    stop = ucs_get_time();

    ucs_compiler_fence();

    samples[i] = stop - start;
  }

  /*
     * Make sure the compiler cannot conclude that the loads
     * were irrelevant.
     */
  if (value == 0xff)
    printf("Impossible value: %x\n", value);

  print_stats(name, samples, n);
}

static UCS_F_MAYBE_UNUSED int
dump_samples(const char *filename, const uint64_t *samples, size_t n,
             const char *header, size_t start_sample, size_t n_samples)
{
  FILE *f = fopen(filename, "w");

  if (f == NULL) {
    perror(filename);
    return -1;
  }

  fprintf(f, "%s\n", header);

  for (size_t i = 0; i < n; ++i) {
    fprintf(f, "%zu", i);
    for (size_t j = start_sample; j < start_sample + n_samples; j++) {
      fprintf(f, ",%" PRIu64, samples[i + j * NSAMPLES]);
    }
    fprintf(f, "\n");
  }

  fclose(f);

  printf("Samples written to %s\n", filename);
  return 0;
}

void test_uct_bxidp::init()
{
  uct_test::init();
  modify_config("BXI_DP_ENABLE", "y");

  m_e1 = uct_test::create_entity(0);
  m_entities.push_back(m_e1);

  check_skip_test();

  m_e2 = uct_test::create_entity(0);
  m_entities.push_back(m_e2);

  connect();
}

UCS_TEST_P(test_uct_bxidp, read_mmios)
{
  ucs_time_t        *samples;
  uct_bxi_iface_t   *iface = (uct_bxi_iface_t *)m_e1->iface();
  volatile uint64_t *slot, *addr;

  volatile uint8_t *mmio_hw_head = uct_bxi_iface_hw_head(iface);

  volatile uint8_t normal = 42;

  uct_bxi_get_txslot(iface, &slot);
  addr = (volatile uint64_t *)UCS_PTR_BYTE_OFFSET(slot, 56);

  samples = (ucs_time_t *)ucs_malloc(NSAMPLES * sizeof(*samples), "samples");
  EXPECT_TRUE(samples != NULL);

  measure_baseline(samples, NSAMPLES);

  measure_reads<uint8_t>("Cached RAM", &normal, samples, NSAMPLES);

  measure_reads<uint8_t>("PCI MMIO read", mmio_hw_head, samples, NSAMPLES);

  measure_wc_write_sfence<uint64_t>("PCI MMIO wc write sfence", iface, samples,
                                    NSAMPLES);

  measure_write_flush<uint64_t, uint8_t>("PCI MMIO wc flush", addr,
                                         mmio_hw_head, 42, samples, NSAMPLES);

  //dump_samples("ucx_bxi_dp_hw_head.csv", samples, NSAMPLES);

  ucs_free(samples);
}

UCS_TEST_P(test_uct_bxidp, send_inline_short_dp)
{
  ucs_time_t      *samples;
  uct_bxi_iface_t *iface = (uct_bxi_iface_t *)m_e1->iface();
  uct_bxi_ep_t    *ep    = ucs_derived_of(m_e1->ep(0), uct_bxi_ep_t);
  //uint64_t           buffer[1] __attribute__((aligned(8)));
  volatile uint64_t *slot;
  FILE              *csv, *csv2;
  double             nop_baseline_us;

  //buffer[0] = 1;

  samples =
          (ucs_time_t *)ucs_malloc(4 * NSAMPLES * sizeof(*samples), "samples");
  EXPECT_TRUE(samples != NULL);
  if (samples == NULL)
    return;

  csv = fopen("ucx_bxi_send_inline_short_dp_throttle.csv", "w");
  EXPECT_TRUE(csv != NULL);
  if (csv == NULL) {
    ucs_free(samples);
    return;
  }

  csv2 = fopen("ucx_bxi_send_inline_short_dp_throttle_median.csv", "w");
  EXPECT_TRUE(csv != NULL);
  if (csv == NULL) {
    ucs_free(samples);
    return;
  }

  fprintf(csv, "nop_count,nop_time_us,sample,get_slot_cycles,set_slot_cycles,"
               "commit_slot_cycles,whole_cycles\n");
  fprintf(csv2, "nop_count,nop_time_us,median_whole_cycles\n");

  /*
   * Calibrate the fixed loop/timestamp overhead once. nop_time_us below is
   * therefore the additional delay introduced by the requested NOP count.
   */
  nop_baseline_us = measure_nop_loop_us(0);

  for (size_t nop_count  = NOP_MIN; nop_count <= NOP_MAX;
       nop_count        += NOP_STEP) {
    double nop_time_us = measure_nop_loop_us(nop_count) - nop_baseline_us;

    if (nop_time_us < 0.0)
      nop_time_us = 0.0;

    /* Start every throttle point from a reasonably drained/progressed state. */
    short_progress_loop(10);

    /* Warm-up using the same throttling level as the measured run. */
    for (size_t i = 0; i < WARMUP; ++i) {
      while (uct_bxi_get_txslot(iface, &slot) == UCS_ERR_NO_RESOURCE) {
        uct_bxi_iface_progress_hw_head(iface);
      }

      uct_bxi_ep_dp_write(iface, ep, slot, 0, 0, NULL, 0);
      uct_bxi_txslot_commit(iface);
      ep->flags       |= UCT_BXI_EP_FLUSH_REMOTE;
      ep->conn->flags &= ~UCT_BXI_CONN_RESET_REMOTE_SN;

      run_nops(nop_count);
    }

    memset(samples, 0, 4 * NSAMPLES * sizeof(*samples));

    for (size_t i = 0; i < NSAMPLES; ++i) {
      ucs_time_t start_send_dp, get_dp, set_dp, stop_send_dp;

      start_send_dp = ucs_get_time();

      while (uct_bxi_get_txslot(iface, &slot) == UCS_ERR_NO_RESOURCE) {
        uct_bxi_iface_progress_hw_head(iface);
      }

      get_dp = ucs_get_time();

      uct_bxi_ep_dp_write(iface, ep, slot, 0, 0, NULL, 0);

      set_dp = ucs_get_time();

      uct_bxi_txslot_commit(iface);
      ep->flags       |= UCT_BXI_EP_FLUSH_REMOTE;
      ep->conn->flags &= ~UCT_BXI_CONN_RESET_REMOTE_SN;

      stop_send_dp = ucs_get_time();

      samples[i]                = get_dp - start_send_dp;
      samples[i + 1 * NSAMPLES] = set_dp - get_dp;
      samples[i + 2 * NSAMPLES] = stop_send_dp - set_dp;
      samples[i + 3 * NSAMPLES] = stop_send_dp - start_send_dp;

      /* Throttle only after the measured send path. */
      run_nops(nop_count);
    }

    /*
     * Dump only after the complete batch, so file I/O does not perturb the
     * timing of individual sends.
     */
    for (size_t i = 0; i < NSAMPLES; ++i) {
      fprintf(csv,
              "%zu,%.9f,%zu,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
              nop_count, nop_time_us, i, (uint64_t)samples[i],
              (uint64_t)samples[i + 1 * NSAMPLES],
              (uint64_t)samples[i + 2 * NSAMPLES],
              (uint64_t)samples[i + 3 * NSAMPLES]);
    }

    fflush(csv);

    printf("\nNOP count: %zu, calibrated throttle: %.6f us\n", nop_count,
           nop_time_us);
    print_stats("get slot", samples, NSAMPLES);
    print_stats("set slot", samples + 1 * NSAMPLES, NSAMPLES);
    print_stats("commit slot", samples + 2 * NSAMPLES, NSAMPLES);
    print_stats("whole slot", samples + 3 * NSAMPLES, NSAMPLES);

    fprintf(csv2, "%zu,%.9f,%" PRIu64 "\n", nop_count, nop_time_us,
            (uint64_t)samples[3 * NSAMPLES + NSAMPLES / 2]);
  }

  fclose(csv);
  fclose(csv2);
  short_progress_loop(10);
  ucs_free(samples);
}

UCS_TEST_P(test_uct_bxidp, send_short_dp)
{
  int              i;
  ucs_time_t      *samples;
  uct_bxi_iface_t *iface = (uct_bxi_iface_t *)m_e1->iface();
  uint64_t         buffer[1] __attribute__((aligned(8)));
  //ptl_event_t      ev;
  uint8_t value UCS_F_MAYBE_UNUSED;

  buffer[0] = 1;

  samples =
          (ucs_time_t *)ucs_malloc(5 * NSAMPLES * sizeof(*samples), "samples");
  EXPECT_TRUE(samples != NULL);
  memset(samples, 0, 4 * NSAMPLES * sizeof(ucs_time_t));

  for (i = 0; i < NSAMPLES; i++) {
    ucs_time_t start_send_dp, stop_send_dp;

    start_send_dp = ucs_get_time();
    uct_bxi_ep_dp_am_short(m_e1->ep(0), 0, 0, buffer, sizeof(buffer));
    stop_send_dp = ucs_get_time();

    samples[i]                = iface->samples[0];
    samples[NSAMPLES + i]     = iface->samples[1];
    samples[2 * NSAMPLES + i] = iface->samples[2];
    samples[3 * NSAMPLES + i] = iface->samples[3];
    samples[4 * NSAMPLES + i] = stop_send_dp - start_send_dp;
    for (size_t j = 0; j < 100; j++)
      asm volatile("nop");
  }

  short_progress_loop(10);
  print_stats("Whole DP time", samples + 4 * NSAMPLES, NSAMPLES);

  for (i = 0; i < NSAMPLES; i++) {
    ucs_time_t start_send_dp, stop_send_dp;
    start_send_dp = ucs_get_time();
    uct_bxi_ep_am_short(m_e1->ep(0), 0, 0, buffer, sizeof(buffer));
    stop_send_dp              = ucs_get_time();
    samples[3 * NSAMPLES + i] = stop_send_dp - start_send_dp;
    short_progress_loop(1);
  }

  print_stats("Whole PTL time", samples + 3 * NSAMPLES, NSAMPLES);
  short_progress_loop(10);

  ucs_free(samples);
}

UCT_INSTANTIATE_BXI_TEST_CASE(test_uct_bxidp);
