#include "sched.h"

#include <ucp/core/ucp_worker.h>
#include <ucs/datastruct/khash.h>
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>

static int ucp_offload_sched_is_activated(ucp_offload_sched_h sched)
{
  return sched->worker->tm.offload.iface != NULL;
}

// Add a region to the sched
ucs_status_t ucp_offload_sched_region_add(ucp_offload_sched_h sched,
                                          void *buffer, size_t size,
                                          uct_gop_h *op_p)
{
  ucs_status_t        status;
  ucp_worker_iface_t *wiface;

  if (!ucp_offload_sched_is_activated(sched)) {
    return UCS_OK;
  }

  wiface = sched->worker->tm.offload.iface;

  sched->regions[sched->count].buffer = buffer;
  sched->regions[sched->count].size   = size;

  status = uct_iface_tag_gop_create(wiface->iface,
                                    &sched->regions[sched->count].op);
  if (status != UCS_OK) {
    return status;
  }
  sched->regions[sched->count].op->size = size;

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
                                             uct_gop_h *gop_p)
{
  ucs_status_t        status;
  size_t              found = 0;
  ucp_worker_iface_t *wiface;
  uct_gop_h           gop = NULL;
  uct_gop_h           gops[UCP_SCHED_MAX_SCHEDULE_SIZE];

  if (!ucp_offload_sched_is_activated(sched)) {
    return found;
  }

  wiface = sched->worker->tm.offload.iface;

  for (size_t i = 0; i < sched->count; ++i) {
    if (ucp_offload_sched_regions_overlap(buffer, size,
                                          sched->regions[i].buffer,
                                          sched->regions[i].size)) {

      gops[found++] = sched->regions[i].op;

      if (found > UCP_SCHED_MAX_SCHEDULE_SIZE) {
        ucs_error("SCHED: max dependencies overflow. max=%d",
                  UCP_SCHED_MAX_SCHEDULE_SIZE);
        return -1;
      }
    }
  }

  /* If overlap regions were found, create the dependencies between 
   * operations. If there is only one dependency, then we may optimize 
   * and use the same generic operation as a dependency. */
  if (found > 1) {
    status = uct_iface_tag_gop_create(wiface->iface, &gop);
    if (status != UCS_OK) {
      return -1;
    }

    status = uct_iface_tag_gop_depends_on(wiface->iface, gop, gops, found);
    if (status != UCS_OK) {
      return -1;
    }
    gop->size = size;

    *gop_p = gop;
  } else if (found == 1) {
    *gop_p = gops[0];
  }

  return found;
}

ucs_status_t ucp_offload_sched_create(ucp_worker_h         worker,
                                      ucp_offload_sched_h *sched_p)
{
  ucs_status_t        status = UCS_OK;
  ucp_offload_sched_h sched;
  int                 ret;

  sched = ucs_mpool_get(&worker->tm.offload.sched_mp);
  if (sched == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  //FIXME: add iface attr checks.

  sched->activated = worker->tm.offload.iface == NULL;
  sched->count     = 0;
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
    uct_iface_tag_gop_delete(sched->worker->tm.offload.iface->iface,
                             sched->regions[i].op);
  }

  ucs_mpool_put(sched);
}
