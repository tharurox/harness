#include "ares_setup.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_getopt.h"
#include "ares_ipv6.h"
#include "ares_nowarn.h"
#include <stdlib.h>
#include <string.h>

/* compile with: afl-clang-fast -I. -DCARES_STATICLIB -DHAVE_CONFIG_H -o cares-harness cares-harness.c .libs/libcares.a */
/* Use version v1.11.0 or older. */

static char* ReadInputFile(const char* filename)
{
  FILE* fp = fopen(filename, "rb");
  if (!fp)
    return strdup("");

  fseek(fp, 0, SEEK_END);
  int size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (size == 0)
    return strdup("");

  char* data = (char*)malloc(size + 1);
  data[size] = 0;
  fread(data, size, 1, fp);
  fclose(fp);
  return data;
}

int main(int argc, char* argv[])
{
  char* input = ReadInputFile(argv[1]);
  unsigned char* buf;
  int buflen;
  ares_create_query(input, ns_c_in, ns_t_a, 0x1234, 0, &buf, &buflen, 0);
  free(buf);
  free(input);
  return 0;
}

