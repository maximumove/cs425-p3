#include "lab.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t value = 0;
  const char *cursor = text;

  if (text == NULL || addr == NULL) {
    return false;
  }

  for (unsigned int octet_index = 0; octet_index < 4; octet_index++) {
    unsigned int octet = 0;
    unsigned int digits = 0;

    if (!isdigit((unsigned char)*cursor)) {
      return false;
    }
    if (*cursor == '0' && isdigit((unsigned char)cursor[1])) {
      return false;
    }

    while (isdigit((unsigned char)*cursor)) {
      octet = octet * 10U + (unsigned int)(*cursor - '0');
      if (octet > 255U) {
        return false;
      }
      digits++;
      cursor++;
    }
    if (digits == 0U) {
      return false;
    }
    value = (value << 8) | (uint32_t)octet;

    if (octet_index < 3U) {
      if (*cursor != '.') {
        return false;
      }
      cursor++;
    } else if (*cursor != '\0') {
      return false;
    }
  }

  *addr = value;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & UINT32_C(0xff)),
                 (unsigned int)((addr >> 16) & UINT32_C(0xff)),
                 (unsigned int)((addr >> 8) & UINT32_C(0xff)),
                 (unsigned int)(addr & UINT32_C(0xff)));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  char address_text[IP_STR_LEN];
  const char *slash;
  const char *prefix_text;
  size_t address_length;
  unsigned int prefix = 0;
  uint32_t address;
  cidr_t parsed;

  if (text == NULL || block == NULL) {
    return false;
  }
  slash = strchr(text, '/');
  if (slash == NULL || strchr(slash + 1, '/') != NULL) {
    return false;
  }
  address_length = (size_t)(slash - text);
  if (address_length == 0U || address_length >= sizeof(address_text)) {
    return false;
  }
  memcpy(address_text, text, address_length);
  address_text[address_length] = '\0';
  if (!ip_parse(address_text, &address)) {
    return false;
  }

  prefix_text = slash + 1;
  if (*prefix_text == '\0' || (*prefix_text == '0' && prefix_text[1] != '\0')) {
    return false;
  }
  for (const char *cursor = prefix_text; *cursor != '\0'; cursor++) {
    if (!isdigit((unsigned char)*cursor)) {
      return false;
    }
    prefix = prefix * 10U + (unsigned int)(*cursor - '0');
    if (prefix > 32U) {
      return false;
    }
  }

  parsed.addr = address;
  parsed.prefix = (uint8_t)prefix;
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address,
                 (unsigned int)(block.prefix > 32U ? 32U : block.prefix));
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0U) {
    return 0U;
  }
  if (prefix >= 32U) {
    return UINT32_MAX;
  }
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  uint32_t network = cidr_network(block);
  return prefix >= 31U ? network : network + 1U;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  uint32_t broadcast = cidr_broadcast(block);
  return prefix >= 31U ? broadcast : broadcast - 1U;
}

uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  if (prefix == 32U) {
    return UINT64_C(1);
  }
  if (prefix == 31U) {
    return UINT64_C(2);
  }
  return (UINT64_C(1) << (32U - prefix)) - UINT64_C(2);
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  uint32_t remaining;
  unsigned int borrowed = 0;
  uint8_t prefix;
  uint64_t offset;
  cidr_t subnet;

  if (out == NULL || !cidr_is_network(block) || n == 0U || i >= n ||
      (n & (n - 1U)) != 0U) {
    return false;
  }
  remaining = n;
  while (remaining > 1U) {
    borrowed++;
    remaining >>= 1;
  }
  if ((unsigned int)block.prefix + borrowed > 32U) {
    return false;
  }

  prefix = (uint8_t)((unsigned int)block.prefix + borrowed);
  offset = (uint64_t)i << (32U - prefix);
  subnet.addr = block.addr + (uint32_t)offset;
  subnet.prefix = prefix;
  *out = subnet;
  return true;
}

static bool next_field(const char **cursor, const char **field, size_t *length)
{
  while (isspace((unsigned char)**cursor)) {
    (*cursor)++;
  }
  if (**cursor == '\0') {
    return false;
  }
  *field = *cursor;
  while (**cursor != '\0' && !isspace((unsigned char)**cursor)) {
    (*cursor)++;
  }
  *length = (size_t)(*cursor - *field);
  return true;
}

static bool field_equals(const char *field, size_t length, const char *word)
{
  return strlen(word) == length && memcmp(field, word, length) == 0;
}

static int read_line(FILE *in, char **line, size_t *capacity, size_t *length)
{
  int character;
  *length = 0U;

  while ((character = fgetc(in)) != EOF) {
    if (*length + 1U >= *capacity) {
      size_t new_capacity = *capacity == 0U ? 128U : *capacity * 2U;
      char *grown;
      if (new_capacity <= *capacity) {
        return -1;
      }
      grown = realloc(*line, new_capacity);
      if (grown == NULL) {
        return -1;
      }
      *line = grown;
      *capacity = new_capacity;
    }
    (*line)[(*length)++] = (char)character;
    if (character == '\n') {
      break;
    }
  }
  if (ferror(in)) {
    return -1;
  }
  if (*length == 0U) {
    return 0;
  }
  (*line)[*length] = '\0';
  return 1;
}

bool route_parse(const char *line, route_t *route)
{
  const char *cursor;
  const char *destination;
  const char *gateway;
  const char *device;
  size_t destination_length;
  size_t gateway_length;
  size_t device_length;
  size_t extra_length;
  const char *extra;
  char token[CIDR_STR_LEN];
  route_t parsed;

  if (line == NULL || route == NULL) {
    return false;
  }
  cursor = line;
  if (!next_field(&cursor, &destination, &destination_length) ||
      !next_field(&cursor, &gateway, &gateway_length) ||
      !next_field(&cursor, &device, &device_length) ||
      next_field(&cursor, &extra, &extra_length)) {
    return false;
  }
  if (destination_length >= sizeof(token) || device_length == 0U ||
      device_length >= DEV_NAME_LEN) {
    return false;
  }

  memcpy(token, destination, destination_length);
  token[destination_length] = '\0';
  if (field_equals(destination, destination_length, "default")) {
    parsed.dest.addr = 0U;
    parsed.dest.prefix = 0U;
  } else if (!cidr_parse(token, &parsed.dest) || !cidr_is_network(parsed.dest)) {
    return false;
  }

  if (field_equals(gateway, gateway_length, "direct")) {
    parsed.gateway = 0U;
  } else {
    if (gateway_length >= IP_STR_LEN) {
      return false;
    }
    memcpy(token, gateway, gateway_length);
    token[gateway_length] = '\0';
    if (!ip_parse(token, &parsed.gateway)) {
      return false;
    }
  }
  memcpy(parsed.dev, device, device_length);
  parsed.dev[device_length] = '\0';
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1U, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table != NULL) {
    free(table->routes);
    free(table);
  }
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0U : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  route_t *grown;
  size_t new_capacity;

  if (table == NULL || route == NULL || !cidr_is_network(route->dest)) {
    return false;
  }
  for (size_t index = 0; index < table->count; index++) {
    if (table->routes[index].dest.prefix == route->dest.prefix &&
        table->routes[index].dest.addr == route->dest.addr) {
      return false;
    }
  }
  if (table->count == table->capacity) {
    if (table->capacity == 0U) {
      new_capacity = 4U;
    } else {
      if (table->capacity > SIZE_MAX / 2U) {
        return false;
      }
      new_capacity = table->capacity * 2U;
    }
    if (new_capacity > SIZE_MAX / sizeof(route_t)) {
      return false;
    }
    grown = realloc(table->routes, new_capacity * sizeof(route_t));
    if (grown == NULL) {
      return false;
    }
    table->routes = grown;
    table->capacity = new_capacity;
  }
  table->routes[table->count] = *route;
  table->count++;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t capacity = 0U;
  size_t line_number = 0U;
  size_t length;
  bool success = true;
  int line_status;

  if (bad_line != NULL) {
    *bad_line = 0U;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  while ((line_status = read_line(in, &line, &capacity, &length)) > 0) {
    char *comment;
    route_t route;
    bool blank = true;
    line_number++;
    comment = memchr(line, '#', length);
    if (comment != NULL) {
      *comment = '\0';
    }
    for (char *cursor = line; *cursor != '\0'; cursor++) {
      if (!isspace((unsigned char)*cursor)) {
        blank = false;
        break;
      }
    }
    if (blank) {
      continue;
    }
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      success = false;
      break;
    }
  }
  if (success && line_status < 0) {
    success = false;
    if (bad_line != NULL) {
      *bad_line = 0U;
    }
  }
  free(line);
  return success;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;
  if (table == NULL) {
    return NULL;
  }
  for (size_t index = 0; index < table->count; index++) {
    const route_t *route = &table->routes[index];
    if (cidr_contains(route->dest, dest) &&
        (best == NULL || route->dest.prefix > best->dest.prefix)) {
      best = route;
    }
  }
  return best;
}
