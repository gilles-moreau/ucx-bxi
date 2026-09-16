#include <uct/bxi/test_bxidp.h>

void test_uct_bxidp::connect()
{
  m_e1->connect(0, *m_e2, 0);
  m_e2->connect(0, *m_e1, 0);

  uct_iface_set_am_handler(m_e1->iface(), 0, am_dummy_handler, NULL, 0);
  uct_iface_set_am_handler(m_e2->iface(), 0, am_dummy_handler, NULL, 0);
}

test_uct_bxidp::test_uct_bxidp() : m_e1(NULL), m_e2(NULL)
{
}

void test_uct_bxidp::init()
{
  uct_test::init();

  m_e1 = uct_test::create_entity(0);
  m_entities.push_back(m_e1);

  check_skip_test();

  m_e2 = uct_test::create_entity(0);
  m_entities.push_back(m_e2);

  connect();
}

UCS_TEST_P(test_uct_bxidp, send_bcopy)
{
  ucs_status_t status;

  status = send_am_message(m_e1, 0, UCS_OK);
  EXPECT_TRUE(status == UCS_OK);

  uct_test::short_progress_loop();
}

UCT_INSTANTIATE_BXI_TEST_CASE(test_uct_bxidp);
