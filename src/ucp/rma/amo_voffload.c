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

static void ucp_proto_amo_completion(uct_completion_t *self)
{
  ucp_request_t *req =
          ucs_container_of(self, ucp_request_t, send.state.uct_comp);

  ucp_request_complete_send(req, self->status);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_amo_vec_progress(uct_pending_req_t *self)
{
  ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
  const ucp_proto_single_priv_t *spriv       = req->send.proto_config->priv;
  ucp_ep_t                      *ep          = req->send.ep;
  uint64_t                       remote_addr = req->send.amo.remote_addr;
  uct_atomic_op_t                op          = req->send.amo.uct_op;
  uct_ep_h                       uct_ep;
  ucp_datatype_iter_t            next_iter;
  ucp_md_map_t                   md_map;
  ucs_status_t                   status;
  uct_rkey_t                     tl_rkey;
  uct_iov_t                      iov[1];

  req->send.lane = spriv->super.lane;
  uct_ep         = ucp_ep_get_fast_lane(ep, req->send.lane);
  tl_rkey = ucp_rkey_get_tl_rkey(req->send.amo.rkey, spriv->super.rkey_index);

  if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
    md_map = (spriv->reg_md == UCP_NULL_RESOURCE) ? 0 : UCS_BIT(spriv->reg_md);
    status = ucp_proto_request_zcopy_init(req, md_map, ucp_proto_amo_completion,
                                          UCT_MD_MEM_ACCESS_LOCAL_READ,
                                          UCS_BIT(UCP_DATATYPE_CONTIG));

    req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
  }

  ucp_datatype_iter_next_iov(&req->send.state.dt_iter, SIZE_MAX,
                             spriv->super.md_index,
                             UCS_BIT(UCP_DATATYPE_CONTIG), &next_iter, iov, 1);

  status = UCS_PROFILE_CALL(
          uct_ep_atomicv_post, uct_ep, op, req->send.amo.uct_type,
          iov, 1, remote_addr, tl_rkey, 0);

  if (status == UCS_OK) {
    ucp_request_complete_send(req, status);
  } else if (status == UCS_ERR_NO_RESOURCE) {
    /* keep on pending queue */
    return UCS_ERR_NO_RESOURCE;
  } else {
    ucp_proto_request_abort(req, status);
  }

  return UCS_OK;
}

static void ucp_proto_amo_vec_probe(const ucp_proto_init_params_t *init_params)
{
  ucp_proto_single_init_params_t params = {
          .super.super         = *init_params,
          .super.latency       = 0,
          .super.overhead      = 0,
          .super.cfg_thresh    = 0,
          .super.cfg_priority  = 20,
          .super.min_length    = 0,
          .super.max_length    = SIZE_MAX,
          .super.min_iov       = 0,
          .super.min_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
          .super.max_frag_offs =
                  ucs_offsetof(uct_iface_attr_t, cap.atomicv.max_atomic_size),
          .super.max_iov_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
          .super.hdr_size     = 0,
          .super.send_op      = UCT_EP_OP_ATOMIC_POST,
          .super.memtype_op   = UCT_EP_OP_GET_SHORT,
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

static void ucp_proto_amo_vec_query(const ucp_proto_query_params_t *params,
                                    ucp_proto_query_attr_t         *attr)
{
  UCS_STRING_BUFFER_FIXED(config_strb, attr->config, sizeof(attr->config));
  UCS_STRING_BUFFER_FIXED(desc_strb, attr->desc, sizeof(attr->desc));
  const ucp_proto_single_priv_t *spriv = params->priv;

  ucs_string_buffer_appendf(&desc_strb, "atomic vec post");
  ucs_string_buffer_rbrk(&desc_strb, "/");

  attr->max_msg_length = SIZE_MAX;
  attr->is_estimation  = 0;
  attr->lane_map       = UCS_BIT(spriv->super.lane);
  ucp_proto_common_lane_priv_str(params, &spriv->super, 1, 1, &config_strb);
}

ucp_proto_t ucp_amo_vec_proto = {.name     = "amovec",
                                 .desc     = NULL,
                                 .probe    = ucp_proto_amo_vec_probe,
                                 .query    = ucp_proto_amo_vec_query,
                                 .progress = {ucp_proto_amo_vec_progress},
                                 .abort = ucp_proto_abort_fatal_not_implemented,
                                 .reset = ucp_proto_request_bcopy_reset};
