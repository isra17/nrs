%module(package="nrs.ext") bzlib
%include <pybuffer.i>

%inline %{

typedef struct {
  unsigned char *next_in;
  unsigned int avail_in;

  unsigned char *next_out;
  unsigned int avail_out;
  char state;
} State;

%}

%{
#define SWIG_FILE_WITH_INIT
#include "bzlib.h"

void BZ2_SetInBuffer(State* s, char* data, size_t data_size) {
  s->next_in = data;
  s->avail_in = data_size;
}

void BZ2_SetOutBuffer(State* s, char* data, size_t data_size) {
  s->next_out = data;
  s->avail_out = data_size;
}

%}

%pybuffer_binary(char *data, size_t data_size);
void BZ2_SetInBuffer(State* s, char* data, size_t data_size);

%pybuffer_mutable_binary(char *data, size_t data_size);
void BZ2_SetOutBuffer(State* s, char* data, size_t data_size);

%inline %{

State* BZ2_Init() {
  DState* s = malloc(sizeof(DState));
  s->state = BZ_X_BLKHDR_1;
  s->bsLive = 0;
  return (State*)s;
}

void BZ2_Free(State* s) {
  free(s);
}

int BZ2_Decompress(State *s) {
  return BZ2_bzDecompress(s);
}

%}

%pythoncode %{
_OUTBUFSIZE = 0x1000

class BzException(Exception):
  pass

def decompress(data):
  try:
    state = BZ2_Init()
    BZ2_SetInBuffer(state, data)

    outbuf = bytearray(_OUTBUFSIZE)
    out = bytearray()

    while True:
      BZ2_SetOutBuffer(state, outbuf)
      out1 = state.next_out

      err = BZ2_Decompress(state)
      processed = int(state.next_out) - int(out1)
      if err < 0:
        break

      if processed == 0:
        break

      out += outbuf[:processed]
  finally:
    BZ2_Free(state)

  return out
%}

