# API support

## UCT

TODO:
- Atomic (MEDIUM): fetch and cswap
  - ptl_am/uct_amo_fand_for_test
  - ptl_am/uct_amo_swap_test
  - ptl_am/uct_amo_fadd_fxor_test
  - ptl_am/uct_amo_cswap_test
- Flush (HIGH): 
  - ptl_am/uct_flush_test
- Fence (LOW):
  - ptl_am/uct_fence_test
- AM Short (MEDIUM): need support for both am_short and am_short_iov. Second not yet possible without doing bcopy.
  - ptl_am/uct_p2p_am_test
- AM Zcopy (LOW):
  - ptl_am/uct_p2p_am_test
- TX Buf (TOCHECK):
  - ptl_am/uct_p2p_am_tx_bufs
- AM Alignment (LOW): not support yet by implementation since using MANAGE_LOCAL
  - ptl_am/uct_p2p_am_alignment
- Err handling (TOCHECK): feature are UCT_IFACE_FLAG_ERRHANDLE_ZCOPY_BUF, UCT_IFACE_FLAG_ERRHANDLE_REMOTE_MEM, UCT_IFACE_FLAG_ERRHANDLE_BCOPY_LEN
  - ptl_am/uct_p2p_err_test 
  - ptl_am/uct_p2p_err_test.invalid_put_short_length
- Pending: UCT_IFACE_FLAG_PENDING
  - ptl_am/test_uct_pending
