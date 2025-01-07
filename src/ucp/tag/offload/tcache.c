#include "tcache.h"

#include <ucm/api/ucm.h>
#include <ucs/arch/atomic.h>
#include <ucs/profile/profile.h>
#include <ucs/sys/ptr_arith.h>
#include <ucs/sys/string.h>
#include <ucs/sys/sys.h>

static inline void ucp_tcache_region_put_internal(ucp_tcache_t        *tcache,
                                                  ucp_tcache_region_t *region,
                                                  unsigned             flags)
{
  size_t region_size;

  ucs_assert(region->refcount > 0);
  if (ucs_likely(ucs_atomic_fsub32(&region->refcount, 1) != 1)) {
    return;
  }

  --tcache->num_regions;
  region_size         = region->super.end - region->super.start;
  tcache->total_size -= region_size;

  UCS_PROFILE_NAMED_CALL_VOID_ALWAYS("mem_unoff", tcache->params.ops->mem_unoff,
                                     tcache->params.context, tcache, region);

  ucs_free(region);
}

/* Lock must be held */
static void ucp_tcache_region_collect_callback(const ucs_pgtable_t *pgtable,
                                               ucs_pgt_region_t    *pgt_region,
                                               void                *arg)
{
  ucp_tcache_region_t *region = ucs_derived_of(pgt_region, ucp_tcache_region_t);
  ucs_list_link_t     *list   = arg;

  ucs_list_add_tail(list, &region->tmp_list);
}

static void ucp_tcache_find_regions(ucp_tcache_t *tcache, ucs_pgt_addr_t from,
                                    ucs_pgt_addr_t to, ucs_list_link_t *list)
{
  ucs_trace("%s: find regions in 0x%lx..0x%lx", tcache->name, from, to);
  ucs_pgtable_search_range(&tcache->pgtable, from, to,
                           ucp_tcache_region_collect_callback, list);
}

static ucs_status_t ucp_tcache_check_overlap(ucp_tcache_t *tcache, void *arg,
                                             ucs_pgt_addr_t       *start,
                                             ucs_pgt_addr_t       *end,
                                             ucp_tcache_region_t **region_p)
{
  ucp_tcache_region_t *region;
  ucs_list_link_t      region_list;

  ucs_trace_func("tcache=%s, *start=0x%lx, *end=0x%lx", tcache->name, *start,
                 *end);

  ucp_tcache_find_regions(tcache, *start, *end - 1, &region_list);

  if (!ucs_list_is_empty(&region_list)) {
    region = ucs_list_next(&region_list, ucp_tcache_region_t, tmp_list);
    if (ucs_list_is_only(&region_list, &region->tmp_list) &&
        (*start >= region->super.start) && (*end <= region->super.end)) {
      /* Found a region which contains the given address range */
      ucp_tcache_region_hold(tcache, region);
      *region_p = region;
      return UCS_ERR_ALREADY_EXISTS;
    }
  }

  return UCS_OK;
}

ucs_status_t ucp_tcache_create_region(ucp_tcache_t *tcache, void *address,
                                      size_t length, void *arg,
                                      ucp_tcache_region_t **region_p)
{
  ucp_tcache_region_t *region;
  ucs_pgt_addr_t       start, end;
  ucs_status_t         status;
  int                  error;
  size_t               region_size;

  ucs_trace_func("tcache=%s, address=%p, length=%zu", tcache->name, address,
                 length);

  pthread_rwlock_wrlock(&tcache->pgt_lock);
  region = NULL;

  /* Check overlap with existing regions */
  status = UCS_PROFILE_CALL(ucp_tcache_check_overlap, tcache, arg, &start, &end,
                            &region);
  if (status == UCS_ERR_ALREADY_EXISTS) {
    /* Found a matching region (it could have been added after we released
         * the lock)
         */
    UCS_STATS_UPDATE_COUNTER(tcache->stats, UCS_RCACHE_HITS_SLOW, 1);
    goto out_set_region;
  } else if (status != UCS_OK) {
    goto out_unlock;
  }

  /* Allocate structure for new region */
  error = ucs_posix_memalign(
          (void **)&region, ucs_max(sizeof(void *), UCS_PGT_ENTRY_MIN_ALIGN),
          tcache->params.region_struct_size, "tcache_region");
  if (error != 0) {
    ucs_error("failed to allocate tcache region descriptor: %m");
    status = UCS_ERR_NO_MEMORY;
    goto out_unlock;
  }

  memset(region, 0, tcache->params.region_struct_size);

  region->super.start = start;
  region->super.end   = end;
  status              = UCS_PROFILE_CALL(ucs_pgtable_insert, &tcache->pgtable,
                                         &region->super);
  if (status != UCS_OK) {
    ucs_error("failed to insert region " UCS_PGT_REGION_FMT ": %s",
              UCS_PGT_REGION_ARG(&region->super), ucs_status_string(status));
    ucs_free(region);
    goto out_unlock;
  }

  ++tcache->num_regions;
  region->flags    = UCP_TCACHE_REGION_FLAG_PGTABLE;
  region->refcount = 1;

  region_size         = region->super.end - region->super.start;
  tcache->total_size += region_size;

  region->status = status = UCS_PROFILE_NAMED_CALL_ALWAYS(
          "mem_off", tcache->params.ops->mem_off, tcache->params.context,
          tcache, arg, region, 0);
  if (status != UCS_OK) {
    ucs_debug("failed to offload region " UCS_PGT_REGION_FMT ": %s",
              UCS_PGT_REGION_ARG(&region->super), ucs_status_string(status));
    goto out_unlock;
  }

  region->flags    |= UCP_TCACHE_REGION_FLAG_OFFLOADED;
  region->refcount  = 2; /* Page-table + user */

out_set_region:
  *region_p = region;
out_unlock:
  pthread_rwlock_unlock(&tcache->pgt_lock);
  return status;
}

void ucs_tcache_region_hold(ucp_tcache_t *tcache, ucp_tcache_region_t *region)
{
  ucs_atomic_add32(&region->refcount, +1);
}

ucs_status_t ucp_tcache_get(ucp_tcache_t *tcache, void *address, size_t length,
                            void *arg, ucp_tcache_region_t **region_p)
{
  ucs_pgt_addr_t       start = (uintptr_t)address;
  ucs_pgt_region_t    *pgt_region;
  ucp_tcache_region_t *region;

  ucs_trace_func("tcache=%s, address=%p, length=%zu", tcache->name, address,
                 length);

  pthread_rwlock_rdlock(&tcache->pgt_lock);
  pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup, &tcache->pgtable, start);
  if (ucs_likely(pgt_region != NULL)) {
    region = ucs_derived_of(pgt_region, ucp_tcache_region_t);
    if ((start + length) <= region->super.end) {
      *region_p = region;
      pthread_rwlock_unlock(&tcache->pgt_lock);
      return UCS_OK;
    }
  }

  pthread_rwlock_unlock(&tcache->pgt_lock);

  return UCS_PROFILE_CALL(ucp_tcache_create_region, tcache, address, length,
                          arg, region_p);
}

static void ucp_tcache_alloc_callback(ucm_event_type_t event_type,
                                      ucm_event_t *event, void *arg)
{
  ucp_tcache_t        *tcache = arg;
  void                *start;
  size_t               size;
  ucp_tcache_region_t *region;

  ucs_assert(event_type == UCM_EVENT_MEM_TYPE_ALLOC);

  if (event_type == UCM_EVENT_MEM_TYPE_ALLOC) {
    start = event->mem_type.address;
    size  = event->mem_type.size;
  } else {
    ucs_warn("%s: unknown event type: %x", tcache->name, event_type);
    return;
  }

  UCS_PROFILE_CALL(ucp_tcache_create_region, tcache, start, size, arg, &region);
}

static void ucp_tcache_free_callback(ucm_event_type_t event_type,
                                     ucm_event_t *event, void *arg)
{
  ucp_tcache_t        *tcache = arg;
  ucs_pgt_region_t    *pgt_region;
  ucp_tcache_region_t *region;
  ucs_pgt_addr_t       start, end;

  ucs_assert(event_type == UCM_EVENT_MEM_TYPE_FREE);

  if (event_type == UCM_EVENT_MEM_TYPE_FREE) {
    start = (uintptr_t)event->mem_type.address;
    end   = (uintptr_t)event->mem_type.address + event->mem_type.size;
  } else {
    ucs_warn("%s: unknown event type: %x", tcache->name, event_type);
    return;
  }

  pthread_rwlock_rdlock(&tcache->pgt_lock);
  pgt_region = UCS_PROFILE_CALL(ucs_pgtable_lookup, &tcache->pgtable, start);
  if (ucs_likely(pgt_region != NULL)) {
    region = ucs_derived_of(pgt_region, ucp_tcache_region_t);

    ucs_assert(region->super.start == start && region->super.end == end);
  } else {
    ucs_error("failed to find region " UCS_PGT_REGION_FMT, NULL, start, end);
    return;
  }
  pthread_rwlock_unlock(&tcache->pgt_lock);

  ucs_trace_func("%s: event vm_unmapped 0x%lx..0x%lx", tcache->name, start,
                 end);

  ucp_tcache_region_put_internal(tcache, region, 0);
}

void ucp_tcache_set_default_params(ucp_tcache_params_t *tcache_params)
{
  tcache_params->region_struct_size = sizeof(ucp_tcache_region_t);
  tcache_params->ucm_events         = 0;
  tcache_params->ucm_event_priority = 1000;
  tcache_params->max_regions        = UCS_MEMUNITS_INF;
  tcache_params->max_size           = UCS_MEMUNITS_INF;
}

void ucp_tcache_set_params(ucp_tcache_params_t       *tcache_params,
                           const ucp_tcache_config_t *tcache_config)
{
  ucp_tcache_set_default_params(tcache_params);

  tcache_params->ucm_event_priority = tcache_config->event_prio;
  tcache_params->max_regions        = tcache_config->max_regions;
  tcache_params->max_size           = tcache_config->max_size;
}

static ucs_pgt_dir_t *ucp_tcache_pgt_dir_alloc(const ucs_pgtable_t *pgtable)
{
  ucp_tcache_t  *tcache = ucs_container_of(pgtable, ucp_tcache_t, pgtable);
  ucs_pgt_dir_t *dir;

  ucs_spin_lock(&tcache->lock);
  dir = ucs_mpool_get(&tcache->mp);
  ucs_spin_unlock(&tcache->lock);

  return dir;
}

static void ucp_tcache_pgt_dir_release(const ucs_pgtable_t *pgtable,
                                       ucs_pgt_dir_t       *dir)
{
  ucp_tcache_t *tcache = ucs_container_of(pgtable, ucp_tcache_t, pgtable);

  ucs_spin_lock(&tcache->lock);
  ucs_mpool_put(dir);
  ucs_spin_unlock(&tcache->lock);
}

static ucs_status_t ucp_tcache_mp_chunk_alloc(ucs_mpool_t *mp, size_t *size_p,
                                              void **chunk_p)
{
  size_t size;
  void  *ptr;

  size = ucs_align_up_pow2(sizeof(size_t) + *size_p, ucs_get_page_size());
  ptr  = ucm_orig_mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ptr == MAP_FAILED) {
    ucs_error("mmap(size=%zu) failed: %m", size);
    return UCS_ERR_NO_MEMORY;
  }

  /* Store the size in the first bytes of the chunk */
  *(size_t *)ptr = size;
  *chunk_p       = UCS_PTR_BYTE_OFFSET(ptr, sizeof(size_t));
  *size_p        = size - sizeof(size_t);
  return UCS_OK;
}

static void ucp_tcache_mp_chunk_release(ucs_mpool_t *mp, void *chunk)
{
  size_t size;
  void  *ptr;
  int    ret;

  ptr  = UCS_PTR_BYTE_OFFSET(chunk, -sizeof(size_t));
  size = *(size_t *)ptr;
  ret  = ucm_orig_munmap(ptr, size);
  if (ret) {
    ucs_warn("munmap(%p, %zu) failed: %m", ptr, size);
  }
}

static ucs_mpool_ops_t ucp_tcache_mp_ops = {
        .chunk_alloc   = ucp_tcache_mp_chunk_alloc,
        .chunk_release = ucp_tcache_mp_chunk_release,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

ucs_status_t ucp_tcache_create(const ucp_tcache_params_t *params,
                               const char *name, ucs_stats_node_t *stats_parent,
                               ucp_tcache_t **tcache_p)
{
  ucs_status_t       status;
  size_t             mp_obj_size, mp_align;
  int                ret;
  ucs_mpool_params_t mp_params;
  ucp_tcache_t      *tcache;

  tcache = (ucp_tcache_t *)ucs_malloc(sizeof(ucp_tcache_t), "ucp tcache alloc");
  if (tcache == NULL) {
    ucs_error("OP: could not allocate tag offloading cache.");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  tcache->name = ucs_strdup(name, "ucs tcache name");
  if (tcache->name == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  status = UCS_STATS_NODE_ALLOC(&tcache->stats, &ucp_tcache_stats_class,
                                stats_parent, "-%s", self->name);
  if (status != UCS_OK) {
    goto err_free_name;
  }

  tcache->params = *params;

  ret = pthread_rwlock_init(&tcache->pgt_lock, NULL);
  if (ret) {
    ucs_error("pthread_rwlock_init() failed: %m");
    status = UCS_ERR_INVALID_PARAM;
    goto err_destroy_stats;
  }

  status = ucs_spinlock_init(&tcache->lock, 0);
  if (status != UCS_OK) {
    goto err_destroy_rwlock;
  }

  status = ucs_pgtable_init(&tcache->pgtable, ucp_tcache_pgt_dir_alloc,
                            ucp_tcache_pgt_dir_release);
  if (status != UCS_OK) {
    goto err_destroy_inv_q_lock;
  }

  mp_obj_size = sizeof(ucs_pgt_dir_t);
  mp_align    = ucs_max(sizeof(void *), UCS_PGT_ENTRY_MIN_ALIGN);

  ucs_mpool_params_reset(&mp_params);
  mp_params.elem_size       = mp_obj_size;
  mp_params.alignment       = mp_align;
  mp_params.malloc_safe     = 1;
  mp_params.elems_per_chunk = 1024;
  mp_params.ops             = &ucp_tcache_mp_ops;
  mp_params.name            = "tcache_mp";
  status                    = ucs_mpool_init(&mp_params, &tcache->mp);
  if (status != UCS_OK) {
    goto err_cleanup_pgtable;
  }

  status = ucm_set_event_handler(UCM_EVENT_MEM_TYPE_ALLOC,
                                 params->ucm_event_priority,
                                 ucp_tcache_alloc_callback, tcache);
  if (status != UCS_OK) {
    ucs_diag("tcache failed to install UCM alloc event handler: %s",
             ucs_status_string(status));
    goto err_destroy_mp;
  }

  status = ucm_set_event_handler(UCM_EVENT_MEM_TYPE_FREE,
                                 params->ucm_event_priority,
                                 ucp_tcache_free_callback, tcache);
  if (status != UCS_OK) {
    ucs_diag("tcache failed to install UCM free event handler: %s",
             ucs_status_string(status));
    goto err_destroy_mp;
  }

  return status;
err_destroy_mp:
  ucs_mpool_cleanup(&tcache->mp, 1);
err_cleanup_pgtable:
  ucs_pgtable_cleanup(&tcache->pgtable);
err_destroy_inv_q_lock:
  ucs_spinlock_destroy(&tcache->lock);
err_destroy_rwlock:
  pthread_rwlock_destroy(&tcache->pgt_lock);
err_destroy_stats:
  UCS_STATS_NODE_FREE(tcache->stats);
err_free_name:
  ucs_free(tcache->name);
err:
  return status;
}

void ucp_tcache_destroy(ucp_tcache_t *tcache)
{
  ucs_mpool_cleanup(&tcache->mp, 1);
  ucs_pgtable_cleanup(&tcache->pgtable);
  ucs_spinlock_destroy(&tcache->lock);
  pthread_rwlock_destroy(&tcache->pgt_lock);
  UCS_STATS_NODE_FREE(tcache->stats);
  ucs_free(tcache->name);
}
