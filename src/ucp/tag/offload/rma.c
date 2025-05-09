
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ucp/proto/proto_single.inl>
#include <ucp/tag/offload.h>
#include <ucp/tag/proto_eager.inl>

#define UCP_PROTO_RMA_OFFLOAD_DESC "rma offloaded"

static void
ucp_rma_tag_offload_get_probe(const ucp_proto_init_params_t *init_params)
{
  ucp_worker_h                   worker  = init_params->worker;
  ucp_context_h                  context = worker->context;
  ucp_proto_single_init_params_t params  = {
           .super.super    = *init_params,
           .super.latency  = 0,
           .super.overhead = context->config.ext.proto_overhead_rndv_offload_get,
           .super.cfg_thresh   = UCS_MEMUNITS_AUTO,
           .super.cfg_priority = 100,
           .super.min_length =
                  ucs_offsetof(uct_iface_attr_t, cap.tag.eager.max_zcopy),
           .super.max_length    = SIZE_MAX,
           .super.min_iov       = 0,
           .super.min_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
           .super.max_frag_offs =
                  ucs_offsetof(uct_iface_attr_t, cap.tag.recv.max_zcopy),
           .super.max_iov_offs =
                  ucs_offsetof(uct_iface_attr_t, cap.tag.rndv.max_iov),
           .super.hdr_size   = 0,
           .super.send_op    = UCT_EP_OP_GET_TAG_ZCOPY,
           .super.memtype_op = UCT_EP_OP_LAST,
           .super.flags      = UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY |
                         UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                         UCP_PROTO_COMMON_INIT_FLAG_OP_OFFLOAD |
                         UCP_PROTO_COMMON_INIT_FLAG_SINGLE_FRAG,
           .super.exclude_map  = 0,
           .super.reg_mem_info = ucp_proto_common_select_param_mem_info(
                  init_params->select_param),
           .lane_type    = UCP_LANE_TYPE_TAG,
           .tl_cap_flags = UCT_IFACE_FLAG_TAG_GET_ZCOPY};

  if (!ucp_tag_eager_check_op_id(init_params, UCP_OP_ID_GET_TAG, 1)) {
    return;
  }

  ucp_proto_single_probe(&params);
}

static ucs_status_t
ucp_rma_tag_offload_get_send_func(ucp_request_t                 *req,
                                  const ucp_proto_single_priv_t *spriv,
                                  uct_iov_t                     *iov)
{
  unsigned flags = 0;

  if (req->flags & UCP_REQUEST_FLAG_OFFLOAD_OPERATION) {
    ucs_assert(req->send.state.dt_iter.dt_class == UCP_DATATYPE_CONTIG);
    ucs_assert(iov->count == 1);
    ucp_offload_sched_region_get_overlaps(
            req->send.tag_offload.sched, iov->buffer, iov->length,
            &req->send.state.uct_comp.op_head, UCP_OFFLOAD_SCHED_MAX_OVERLAPS);
    flags = UCT_TAG_OFFLOAD_OPERATION;
  }

  return uct_ep_tag_get_zcopy(
          ucp_ep_get_fast_lane(req->send.ep, spriv->super.lane),
          req->send.msg_proto.tag, iov, 1, 0, flags, &req->send.state.uct_comp);
}

UCS_PROFILE_FUNC(ucs_status_t, ucp_rma_tag_offload_get_progress, (self),
                 uct_pending_req_t *self)
{
  ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);

  return ucp_proto_zcopy_single_progress(
          req, UCT_MD_MEM_ACCESS_RMA | UCT_MD_MEM_FLAG_HIDE_ERRORS,
          ucp_rma_tag_offload_get_send_func,
          ucp_request_invoke_uct_completion_success,
          ucp_proto_request_zcopy_completion, ucp_proto_request_zcopy_init);
}

ucp_proto_t ucp_rma_tag_offload_get_proto = {
        .name     = "tag/rma/offload_get",
        .desc     = "rma offload get",
        .flags    = 0,
        .probe    = ucp_rma_tag_offload_get_probe,
        .query    = ucp_proto_single_query,
        .progress = {ucp_rma_tag_offload_get_progress},
        .abort    = ucp_proto_request_zcopy_abort,
        .reset    = ucp_proto_request_zcopy_id_reset};
