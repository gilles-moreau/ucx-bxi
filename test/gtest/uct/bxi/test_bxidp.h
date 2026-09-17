#include <uct/uct_test.h>

class test_uct_bxidp : public uct_test {
    public:
  test_uct_bxidp();
  void                 init();
  virtual void         connect();
  virtual ucs_status_t send_am_message(entity *e, uint8_t am_id,
                                       ucs_status_t expected, int ep_idx = 0);
  static size_t        bxidp_pack_callback(void *dest, void *arg);

  static ucs_status_t am_dummy_handler(void *arg, void *data, size_t length,
                                       unsigned flags)
  {
    return UCS_OK;
  }

    protected:
  entity *m_e1, *m_e2;
};
