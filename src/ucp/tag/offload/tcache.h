#ifndef UCP_TCACHE_H_
#define UCP_TCACHE_H_

#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/datastruct/pgtable.h>
#include <ucs/datastruct/queue.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/stats/stats.h>
#include <ucs/type/spinlock.h>

#include <uct/api/uct_def.h>

typedef struct ucp_tcache_region ucp_tcache_region_t;
typedef struct ucp_tcache_params ucp_tcache_params_t;
typedef struct ucp_tcache_ops    ucp_tcache_ops_t;
typedef struct ucp_tcache        ucp_tcache_t;
typedef struct ucp_tcache_config ucp_tcache_config_t;

/*
 * Memory region flags.
 */
enum {
  UCP_TCACHE_REGION_FLAG_PGTABLE   = UCS_BIT(0), /**< In the page table */
  UCP_TCACHE_REGION_FLAG_OFFLOADED = UCS_BIT(1), /**< Offloaded */
};

struct ucp_tcache_region {
  ucs_pgt_region_t  super;
  uct_oop_ctx_h     oop;
  ucs_list_link_t   tmp_list; /**< Temp list element */
  unsigned          flags;
  ucs_status_t      status;
  volatile uint32_t refcount; /**< Reference count, including +1 if it's
                                           in the page table */
};

struct ucp_tcache_ops {
  /**
     * Create an offloading context for this region.
     *
     * @param [in]  context    User context, as passed to @ref ucp_tcache_create().
     * @param [in]  tcache     Pointer to the offload cache.
     * @param [in]  arg        Custom argument passed to @ref ucp_tcache_get().
     * @param [in]  region     Memory region to offload. This may point to a larger
     *                          user-defined structure, as specified by the field
     *                          `region_struct_size' in @ref ucp_tcache_params.
     *                         This function may store relevant information (such
     *                          as memory keys) inside the larger structure.
     * @param [in]  flags      Memory offload flags.
     *
     * @return UCS_OK if offloading is successful, error otherwise.
     *
     * @note This function should be able to handle inaccessible memory addresses
     *       and return error status in this case, without any destructive consequences
     *       such as error messages or fatal failure.
     */
  ucs_status_t (*mem_off)(void *context, ucp_tcache_t *tcache, void *arg,
                          ucp_tcache_region_t *region, uint16_t flags);
  /**
     * Unoffload a memory region.
     *
     * @param [in]  context  User context, as passed to @ref ucp_tcache_create().
     * @param [in]  tcache   Pointer to the offload cache.
     * @param [in]  region   Memory region to unoffload.
     */
  void (*mem_unoff)(void *context, ucp_tcache_t *tcache,
                    ucp_tcache_region_t *region);
};

struct ucp_tcache_params {
  size_t           region_struct_size; /**< Size of memory region structure,
                                  must be at least the size
                                  of @ref ucs_tcache_region_t */
  int              ucm_events;         /**< UCM events to register. */
  void            *context;            /**< User-defined context that will
                                  be passed to mem_reg/mem_dereg */
  int              ucm_event_priority; /**< Priority of memory events */
  size_t           max_regions;
  size_t           max_size;
  ucp_tcache_ops_t ops; /**< Memory operations functions */
};

/*
 * Registration cache configuration parameters.
 */
struct ucp_tcache_config {
  unsigned      event_prio;  /**< Memory events priority */
  unsigned long max_regions; /**< Maximal number of tcache regions */
  size_t        max_size;    /**< Maximal size of mapped memory */
};

struct ucp_tcache {
  ucp_tcache_params_t params; /**< tcache parameters (immutable) */

  pthread_rwlock_t pgt_lock; /**< Protects the page table and all
                                  regions whose refcount is 0 */
  ucs_pgtable_t    pgtable;  /**< page table to hold the regions */

  ucp_tcache_ops_t ops;
  ucs_spinlock_t   lock;        /**< Protects 'mp', 'inv_q' and 'gc_list'.
                                   This is a separate lock because we
                                   may want to invalidate regions
                                   while the page table lock is held by
                                   the calling context.
                                   @note: This lock should always be
                                   taken **after** 'pgt_lock'. */
  ucs_mpool_t      mp;          /**< Memory pool to allocate entries for
                                   inv_q and page table entries, since
                                   we cannot use regular malloc().
                                   The backing storage is original mmap()
                                   which does not generate memory events */
  unsigned long    num_regions; /**< Total number of managed regions */
  size_t           total_size;  /**< Total size of registered memory */
  size_t unreleased_size; /**< Total size of the regions in gc_list and in inv_q */

  UCS_STATS_NODE_DECLARE(stats)
  char *name; /**< Name of the cache, for debug purpose */
};

/**
 * Create a memory offloading cache.
 *
 * @param [in]  params        Offloading cache parameters.
 * @param [in]  name          Offloading cache name, for debugging.
 * @param [in]  stats_parent  Pointer to statistics parent node.
 * @param [out] tcache_p      Filled with a pointer to the offloading cache.
 */
ucs_status_t ucp_tcache_create(const ucp_tcache_params_t *params,
                               const char *name, ucs_stats_node_t *stats_parent,
                               ucp_tcache_t **tcache_p);

/**
 * Destroy a memory offloading cache.
 *
 * @param [in]  tcache      Offloading cache to destroy.
 */
void ucp_tcache_destroy(ucp_tcache_t *tcache);

/**
 * Resolve buffer in the offloading cache, or register it if not found.
 * TODO register after N usages.
 *
 * @param [in]  tcache      Memory offloading cache.
 * @param [in]  address     Address to register or resolve.
 * @param [in]  length      Length of buffer to register or resolve.
 * @param [in]  alignment   Alignment for offloading buffer.
 * @param [in]  prot        Requested access flags, PROT_xx (same as passed to mmap).
 * @param [in]  arg         Custom argument passed down to memory offloading
 *                          callback, if a memory offloading happens during
 *                          this call.
 * @param [out] region_p    On success, filled with a pointer to the memory
 *                          region. The user could put more data in the region
 *                          structure in mem_reg() function.
 *
 * On success succeeds, the memory region reference count is incremented by 1.
 *
 * @return Error code.
 */
ucs_status_t ucp_tcache_get(ucp_tcache_t *tcache, void *address, size_t length,
                            void *arg, ucp_tcache_region_t **region_p);

/**
 * Increment memory region reference count.
 *
 * @param [in]  tcache      Memory offloading cache.
 * @param [in]  region      Memory region whose reference count to increment.
 */
void ucp_tcache_region_hold(ucp_tcache_t *tcache, ucp_tcache_region_t *region);

/**
 * Decrement memory region reference count and possibly destroy it.
 *
 * @param [in]  tcache      Memory offloading cache.
 * @param [in]  region      Memory region to release.
 */
void ucp_tcache_region_put(ucp_tcache_t *tcache, ucp_tcache_region_t *region);

/**
 * Set tcache parameters based on fields in tcache configuration.
 *
 * @param [out] tcache_params On success, tcache_params fields are populated
 *                            with default values.
 */
void ucp_tcache_set_default_params(ucp_tcache_params_t *tcache_params);

/**
 * Set tcache parameters based on fields in tcache configuration.
 *
 * @param [out] tcache_params On success, tcache_params fields are populated
 *                            with values provided in tcache_config.
 * @param [in]  tcache_config Configuration used to populate tcache parameters.
 */
void ucp_tcache_set_params(ucp_tcache_params_t       *tcache_params,
                           const ucp_tcache_config_t *tcache_config);

#endif
