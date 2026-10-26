#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {}
void tearDown(void) {}

void test_ip_parse_and_format(void)
{
  uint32_t address = UINT32_C(0xdeadbeef);
  char formatted[IP_STR_LEN];
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1",
    "1.2.3.4x", "+1.2.3.4", "1.2.3.4 "
  };

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &address));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), address);
  ip_format(address, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", formatted);
  for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
    address = UINT32_C(0xdeadbeef);
    TEST_ASSERT_FALSE(ip_parse(invalid[index], &address));
    TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xdeadbeef), address);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &address));
}

void test_cidr_parse_and_arithmetic(void)
{
  cidr_t block = {0U, 0U};
  const char *invalid[] = {
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24",
    "1.2.3.4/-1"
  };
  char formatted[CIDR_STR_LEN];

  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e30b), block.addr);
  TEST_ASSERT_EQUAL_UINT8(25U, block.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xffffff80), cidr_mask(25U));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e300), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37f), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e301), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37e), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(126U, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84b2e332)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x84b2e3c8)));
  TEST_ASSERT_FALSE(cidr_is_network(block));
  cidr_format(block, formatted);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", formatted);
  for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[index], &block));
  }
  TEST_ASSERT_EQUAL_HEX32(0U, cidr_mask(0U));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count((cidr_t){0U, 0U}));
  TEST_ASSERT_EQUAL_UINT64(2U, cidr_host_count((cidr_t){UINT32_C(0x0a000000), 31U}));
  TEST_ASSERT_EQUAL_UINT64(1U, cidr_host_count((cidr_t){UINT32_C(0x0a000001), 32U}));
}

void test_cidr_subnet(void)
{
  cidr_t network = {UINT32_C(0xc0a80100), 24U};
  cidr_t subnet = {0U, 0U};

  TEST_ASSERT_TRUE(cidr_subnet(network, 4U, 2U, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a80180), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26U, subnet.prefix);
  TEST_ASSERT_FALSE(cidr_subnet(network, 3U, 0U, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(network, 4U, 4U, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){UINT32_C(0xc0a80101), 24U}, 2U, 0U, &subnet));
}

void test_route_table_and_longest_prefix(void)
{
  fwd_table_t *table = table_create();
  route_t route;
  const route_t *found;

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1\n", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 10.1.0.1 eth1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 direct eth1", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.2.0/24 direct eth2", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_TRUE(route_parse("10.1.2.128/25 10.1.2.1 eth2", &route));
  TEST_ASSERT_TRUE(table_add(table, &route));
  TEST_ASSERT_EQUAL_UINT(5U, table_count(table));
  found = table_lookup(table, UINT32_C(0x0a0102c8));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(25U, found->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a010201), found->gateway);
  found = table_lookup(table, UINT32_C(0x08080808));
  TEST_ASSERT_NOT_NULL(found);
  TEST_ASSERT_EQUAL_UINT8(0U, found->dest.prefix);
  TEST_ASSERT_FALSE(route_parse("10.1.2.1/24 direct eth0", &route));
  TEST_ASSERT_FALSE(route_parse("10.0.0.0/8 direct eth0 extra", &route));
  TEST_ASSERT_FALSE(table_add(table, &route));
  table_destroy(table);
  TEST_ASSERT_EQUAL_UINT(0U, table_count(NULL));
  table_destroy(NULL);
}

void test_table_load(void)
{
  fwd_table_t *table = table_create();
  FILE *input = tmpfile();
  size_t bad_line = 99U;

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_NOT_NULL(input);
  (void)fputs("# comment\n\n default 1.2.3.4 eth0\ninvalid route\n", input);
  rewind(input);
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_UINT(4U, bad_line);
  TEST_ASSERT_EQUAL_UINT(1U, table_count(table));
  (void)fclose(input);
  table_destroy(table);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_and_arithmetic);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_route_table_and_longest_prefix);
  RUN_TEST(test_table_load);
  return UNITY_END();
}
