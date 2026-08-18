#include <uct/uct_test.h>

class test_uct_bxihw : public uct_test {
    public:
  test_uct_bxihw();
  void init();

    protected:
  entity *m_e1, *m_e2;
};
