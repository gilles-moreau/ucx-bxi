/**
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rma.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/core/ucp_worker.h>
#include <ucp/dt/datatype_iter.inl>
#include <ucp/proto/proto_init.h>
#include <ucp/proto/proto_single.inl>

static void ucp_proto_post_offload_completion(uct_completion_t *uct_comp)
{
  ucp_request_t *req =
          ucs_container_of(uct_comp, ucp_request_t, send.state.uct_comp);

  ucp_send_request_id_release(req);
  ucp_proto_request_zcopy_complete(req, uct_comp->status);
}

static ucs_status_t
ucp_proto_post_offload_request_init(ucp_request_t *req, ucp_md_map_t md_map,
                                    uct_completion_callback_t comp_func,
                                    unsigned uct_reg_flags, unsigned dt_mask)
{
  ucs_status_t status;

  ucs_assertv(dt_mask == UCS_BIT(UCP_DATATYPE_CONTIG), "dt_mask=0x%x", dt_mask);

  status = ucp_proto_request_zcopy_init(req, md_map, comp_func, uct_reg_flags,
                                        dt_mask);
  if (status != UCS_OK) {
    return status;
  }

  ucp_send_request_id_alloc(req);

  return UCS_OK;
}

static ucs_status_t
ucp_proto_post_offload_send_func(ucp_request_t                 *req,
                                 const ucp_proto_single_priv_t *spriv,
                                 uct_iov_t                     *iov)
{
  ucs_status_t    status;
  uint64_t        remote_addr = req->send.amo.remote_addr;
  uct_atomic_op_t op          = req->send.amo.uct_op;
  uct_rkey_t      tl_rkey;

  tl_rkey = ucp_rkey_get_tl_rkey(req->send.amo.rkey, spriv->super.rkey_index);

  status = UCS_PROFILE_CALL(
          uct_ep_atomicv_post,
          ucp_ep_get_fast_lane(req->send.ep, spriv->super.lane), op, iov, 1,
          remote_addr, tl_rkey);

  return status;
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_proto_post_offload_proto_progress, (self),
                 uct_pending_req_t *self)
{
  ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);

  return ucp_proto_zcopy_single_progress(
          req, UCT_MD_MEM_ACCESS_RMA | UCT_MD_MEM_FLAG_HIDE_ERRORS,
          ucp_proto_post_offload_send_func, NULL,
          ucp_proto_post_offload_completion,
          ucp_proto_post_offload_request_init);
}

static void
ucp_proto_post_offload_probe(const ucp_proto_init_params_t *init_params)
{
  ucp_proto_single_init_params_t params = {
          .super.super        = *init_params,
          .super.latency      = 0,
          .super.overhead     = 0,
          .super.cfg_thresh   = 0,
          .super.cfg_priority = 20,
          .super.min_length   = sizeof(uint64_t),
          .super.max_length   = SIZE_MAX,
          .super.min_iov      = 0,
          .super.min_frag_offs =
                  ucs_offsetof(uct_iface_attr_t, cap.put.min_zcopy),
          .super.max_frag_offs =
                  ucs_offsetof(uct_iface_attr_t, cap.put.max_zcopy),
          .super.max_iov_offs = ucs_offsetof(uct_iface_attr_t, cap.put.max_iov),
          .super.hdr_size     = 0,
          .super.send_op      = UCT_EP_OP_ATOMIC_POST,
          .super.memtype_op   = UCT_EP_OP_LAST,
          .super.flags        = UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS |
                         UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                         UCP_PROTO_COMMON_INIT_FLAG_SINGLE_FRAG,
          .super.exclude_map  = 0,
          .super.reg_mem_info = ucp_mem_info_unknown,
          .lane_type          = UCP_LANE_TYPE_AMO,
          .tl_cap_flags       = 0};

  if ((init_params->select_param->dt_class != UCP_DATATYPE_CONTIG) ||
      !ucp_proto_init_check_op(init_params, UCS_BIT(UCP_OP_ID_AMO_POST))) {
    return;
  }

  ucp_proto_single_probe(&params);
}

ucp_proto_t ucp_post_offload_proto = {
        .name     = "amo/post/offload",
        .desc     = "Atomic post offload",
        .flags    = 0,
        .probe    = ucp_proto_post_offload_probe,
        .query    = ucp_proto_single_query,
        .progress = {ucp_proto_post_offload_proto_progress},
        .abort    = ucp_proto_request_zcopy_abort,
        .reset    = ucp_proto_request_zcopy_id_reset};
