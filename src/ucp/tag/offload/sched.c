#include <ucp/core/ucp_worker.h>
#include <ucs/datastruct/khash.h>
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>

typedef struct ucp_offload_region {
  void        *buffer;
  size_t       size;
  uct_op_ctx_h op;
} ucp_offload_region_t;

struct ucp_offload_sched {
  ucp_offload_region_t *regions;
  size_t                count;
  size_t                capacity;
  ucp_worker_h          worker;
  int                   activated;
};

static int ucp_offload_sched_is_activated(ucp_offload_sched_h sched)
{
  return sched->worker->tm.offload.iface != NULL;
}

// Helper: grow the internal region array if needed
static ucs_status_t ucp_offload_sched_ensure_capacity(ucp_offload_sched_h sched)
{
  size_t                new_capacity;
  ucp_offload_region_t *new_regions;

  if (sched->count < sched->capacity) {
    return UCS_OK;
  }

  new_capacity = (sched->capacity == 0) ? 4 : sched->capacity * 2;
  new_regions  = ucs_realloc(sched->regions,
                             new_capacity * sizeof(ucp_offload_region_t),
                             "offload region");
  if (new_regions == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  sched->regions  = new_regions;
  sched->capacity = new_capacity;

  return UCS_OK;
}

// Add a region to the sched
ucs_status_t ucp_offload_sched_region_add(ucp_offload_sched_h sched,
                                          void *buffer, size_t size,
                                          uct_op_ctx_h *op_p)
{
  ucs_status_t        status;
  ucp_worker_iface_t *wiface;

  if (!ucp_offload_sched_is_activated(sched)) {
    return UCS_OK;
  }

  status = ucp_offload_sched_ensure_capacity(sched);
  if (status != UCS_OK) {
    return status;
  }

  wiface = sched->worker->tm.offload.iface;

  sched->regions[sched->count].buffer = buffer;
  sched->regions[sched->count].size   = size;

  status = uct_iface_tag_op_ctx_create(wiface->iface,
                                       &sched->regions[sched->count].op);
  if (status != UCS_OK) {
    return status;
  }

  *op_p = sched->regions[sched->count].op;
  sched->count++;

  return status;
}

// Remove a region from the sched
ucs_status_t ucp_offload_sched_region_rm(ucp_offload_sched_h sched,
                                         void *buffer, size_t size)
{
  for (size_t i = 0; i < sched->count; ++i) {
    if (sched->regions[i].buffer == buffer && sched->regions[i].size == size) {
      // Move the last element into the current slot
      sched->regions[i] = sched->regions[sched->count - 1];
      sched->count--;
      return UCS_OK;
    }
  }
  return UCS_ERR_NO_ELEM;
}

// Check if two memory regions overlap
int ucp_offload_sched_regions_overlap(void *a_buf, size_t a_size, void *b_buf,
                                      size_t b_size)
{
  uintptr_t a_start = (uintptr_t)a_buf;
  uintptr_t a_end   = a_start + a_size;
  uintptr_t b_start = (uintptr_t)b_buf;
  uintptr_t b_end   = b_start + b_size;
  return a_start < b_end && b_start < a_end;
}

// Return overlapping regions (caller allocates the output array)
size_t ucp_offload_sched_region_get_overlaps(ucp_offload_sched_h sched,
                                             void *buffer, size_t size,
                                             ucs_list_link_t *op_head,
                                             size_t           max_overlaps)
{
  size_t found = 0;

  if (!ucp_offload_sched_is_activated(sched)) {
    return found;
  }

  for (size_t i = 0; i < sched->count && found < max_overlaps; ++i) {
    if (ucp_offload_sched_regions_overlap(buffer, size,
                                          sched->regions[i].buffer,
                                          sched->regions[i].size)) {
      ucs_list_add_head(op_head, &sched->regions[i].op->elem);
      found++;
    }
  }

  return found;
}

ucs_status_t ucp_offload_sched_create(ucp_worker_h         worker,
                                      ucp_offload_sched_h *sched_p)
{
  ucs_status_t        status = UCS_OK;
  ucp_offload_sched_h sched;
  int                 ret;

  sched = ucs_malloc(sizeof(struct ucp_offload_sched), "alloc oop ctx");
  if (sched == NULL) {
    ucs_error("OOP: could not allocate offload operation context.");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  //FIXME: add iface attr checks.

  sched->activated = worker->tm.offload.iface == NULL;
  sched->regions   = NULL;
  sched->count     = 0;
  sched->capacity  = 0;
  sched->worker    = worker;

  /* Append the scheduler to the worker's hash table. */
  kh_put(ucp_tag_sched_hash, &worker->tm.offload.sched_hash, sched, &ret);
  ucs_assertv(ret != UCS_KH_PUT_FAILED, "ret %d", ret);

  *sched_p = sched;
err:
  return status;
}

void ucp_offload_sched_fini(ucp_offload_sched_h sched)
{
  for (size_t i = 0; i < sched->count; ++i) {
    uct_iface_tag_op_ctx_delete(sched->worker->tm.offload.iface->iface,
                                sched->regions[i].op);
    sched->count--;
  }
  ucs_free(sched->regions);
}
