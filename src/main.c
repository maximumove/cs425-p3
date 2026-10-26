#include "lab.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *stream)
{
  (void)fprintf(stream,
                "Usage: myapp info <address>/<prefix>\n"
                "       myapp split <network>/<prefix> <count>\n"
                "       myapp lookup <table-file> <address>...\n");
}

static bool parse_count(const char *text, uint32_t *count)
{
  uint32_t value = 0U;
  if (text == NULL || *text == '\0' || count == NULL) {
    return false;
  }
  for (const char *cursor = text; *cursor != '\0'; cursor++) {
    uint32_t digit;
    if (*cursor < '0' || *cursor > '9') {
      return false;
    }
    digit = (uint32_t)(*cursor - '0');
    if (value > (UINT32_MAX - digit) / 10U) {
      return false;
    }
    value = value * 10U + digit;
  }
  *count = value;
  return true;
}

static int run_info(const char *text)
{
  cidr_t block;
  char address[IP_STR_LEN];
  char mask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first[IP_STR_LEN];
  char last[IP_STR_LEN];

  if (!cidr_parse(text, &block)) {
    (void)fprintf(stderr, "myapp: not a valid CIDR address: %s\n", text);
    return 1;
  }
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), mask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first);
  ip_format(cidr_last_host(block), last);
  (void)printf("address    %s\n", address);
  (void)printf("prefix     /%u\n", (unsigned int)block.prefix);
  (void)printf("netmask    %s\n", mask);
  (void)printf("network    %s\n", network);
  (void)printf("broadcast  %s\n", broadcast);
  (void)printf("first host %s\n", first);
  (void)printf("last host  %s\n", last);
  (void)printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return 0;
}

static int run_split(const char *text, const char *count_text)
{
  cidr_t block;
  uint32_t count;

  if (!cidr_parse(text, &block) || !cidr_is_network(block) ||
      !parse_count(count_text, &count) || count == 0U ||
      (count & (count - 1U)) != 0U) {
    (void)fprintf(stderr, "myapp: invalid network or subnet count\n");
    return 1;
  }
  for (uint64_t index = 0U; index < count; index++) {
    cidr_t subnet;
    char formatted[CIDR_STR_LEN];
    if (!cidr_subnet(block, count, (uint32_t)index, &subnet)) {
      (void)fprintf(stderr, "myapp: subnet count exceeds the block capacity\n");
      return 1;
    }
    cidr_format(subnet, formatted);
    (void)puts(formatted);
  }
  return 0;
}

static int run_lookup(const char *path, int address_count, char **addresses)
{
  FILE *input = fopen(path, "r");
  fwd_table_t *table;
  size_t bad_line;
  int exit_status = 0;

  if (input == NULL) {
    (void)fprintf(stderr, "myapp: %s: cannot open table file\n", path);
    return 2;
  }
  table = table_create();
  if (table == NULL) {
    (void)fclose(input);
    (void)fprintf(stderr, "myapp: could not allocate forwarding table\n");
    return 2;
  }
  if (!table_load(table, input, &bad_line)) {
    if (bad_line == 0U) {
      (void)fprintf(stderr, "myapp: %s: could not read table file\n", path);
    } else {
      (void)fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    (void)fclose(input);
    table_destroy(table);
    return 2;
  }
  (void)fclose(input);

  for (int index = 0; index < address_count; index++) {
    uint32_t address;
    const route_t *route;
    if (!ip_parse(addresses[index], &address)) {
      (void)fprintf(stderr, "myapp: not a valid address: %s\n", addresses[index]);
      exit_status = 1;
      continue;
    }
    route = table_lookup(table, address);
    if (route == NULL) {
      (void)printf("%s unreachable\n", addresses[index]);
      if (exit_status == 0) {
        exit_status = 3;
      }
    } else if (route->gateway != 0U) {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      (void)printf("%s via %s dev %s\n", addresses[index], gateway, route->dev);
    } else {
      (void)printf("%s dev %s\n", addresses[index], route->dev);
    }
  }
  table_destroy(table);
  return exit_status;
}

int main(int argc, char **argv)
{
  if (argc == 1) {
    print_usage(stdout);
    return 0;
  }
  if (strcmp(argv[1], "info") == 0 && argc == 3) {
    return run_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0 && argc == 4) {
    return run_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0 && argc >= 4) {
    return run_lookup(argv[2], argc - 3, &argv[3]);
  }
  print_usage(stderr);
  return 1;
}
