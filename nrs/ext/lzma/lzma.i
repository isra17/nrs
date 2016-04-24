%module(package="nrs.ext.lzma") lzma
%include <pybuffer.i>

%inline %{

typedef struct {
  unsigned char *next_in;
  unsigned int avail_in;

  unsigned char *next_out;
  unsigned int avail_out;
} State;

%}

%{
#define SWIG_FILE_WITH_INIT
#include "LZMADecode.h"

void LZMA_SetInBuffer(State* s, char* data, size_t data_size) {
  s->next_in = data;
  s->avail_in = data_size;
}

void LZMA_SetOutBuffer(State* s, char* data, size_t data_size) {
  s->next_out = data;
  s->avail_out = data_size;
}

%}

%pybuffer_binary(char *data, size_t data_size);
void LZMA_SetInBuffer(State* s, char* data, size_t data_size);

%pybuffer_mutable_binary(char *data, size_t data_size);
void LZMA_SetOutBuffer(State* s, char* data, size_t data_size);

%inline %{

State* LZMA_Init() {
  lzma_stream* s = malloc(sizeof(lzma_stream));
  lzmaInit(s);
  return (State*)s;
}

void LZMA_Free(State* s) {
  free(s);
}

int LZMA_Decompress(State *s) {
  return lzmaDecode(s);
}

%}

%pythoncode %{
_OUTBUFSIZE = 0x1000

class LzmaException(Exception):
  pass

def decompress(data):
  try:
    state = LZMA_Init()
    LZMA_SetInBuffer(state, data)

    outbuf = bytearray(_OUTBUFSIZE)
    out = bytearray()

    while True:
      LZMA_SetOutBuffer(state, outbuf)
      out1 = state.next_out

      err = LZMA_Decompress(state)
      processed = int(state.next_out) - int(out1)
      if err < 0:
        break

      if processed == 0:
        break

      out += outbuf[:processed]
  finally:
    LZMA_Free(state)

  return out
%}

