#include <uct/bxi/test_bxihw.h>

extern "C" {
#include <uct/bxi/bxihw/bxihw_md.h>
}

test_uct_bxihw::test_uct_bxihw() : m_e1(NULL), m_e2(NULL)
{
}

void test_uct_bxihw::init()
{
  uct_test::init();
}

UCS_TEST_P(test_uct_bxihw, open_device)
{
  uct_md_h     md;
  ucs_status_t status = uct_bxihw_md_open(NULL, "", NULL, &md);
  EXPECT_TRUE(status == UCS_OK);
}

UCT_INSTANTIATE_BXI_TEST_CASE(test_uct_bxihw);
