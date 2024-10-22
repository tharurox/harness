// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

#include <string>
#include <cstdio>
#include <cstring>
#include "re2/re2.h"

// use https://github.com/google/re2.git commit 499ef7eff7455ce9c9fae86111d4a77b6ac335de
// hint: using persistent mode significantly increases fuzzing speed
// compile with: afl-clang-fast++ -I. -o harness harness.cpp obj/libre2.a

static char* ReadInputFile(const char* filename, size_t* size)
{
  FILE* fp = fopen(filename, "rb");
  if (!fp)
    return strdup("");

  fseek(fp, 0, SEEK_END);
  *size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (*size == 0)
    return strdup("");

  char* data = (char*)malloc(*size + 1);
  data[*size] = 0;
  fread(data, *size, 1, fp);
  fclose(fp);
  return data;
}

int main(int argc, char* argv[])
{
  if (argc < 2)
    return 1;

  size_t size;
  char* data = ReadInputFile(argv[1], &size);
  if (size < 3 || size > 64)
  {
    free(data);
    return 1;
  }

  RE2::Options opts;
  opts.set_log_errors(false);
  if (data[0] & 1)
    opts.set_encoding(RE2::Options::EncodingLatin1);
  opts.set_posix_syntax(data[0] & 2);
  opts.set_longest_match(data[0] & 4);
  opts.set_literal(data[0] & 8);
  opts.set_never_nl(data[0] & 16);
  opts.set_dot_nl(data[0] & 32);
  opts.set_never_capture(data[0] & 64);
  opts.set_case_sensitive(data[0] & 128);
  opts.set_perl_classes(data[1] & 1);
  opts.set_word_boundary(data[1] & 2);
  opts.set_one_line(data[1] & 4);

  RE2 re(data + 2, opts);
  if (re.ok())
    RE2::FullMatch(data + 2, re);

  free(data);

  return 0;
}

