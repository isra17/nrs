%module(package="nrs.ext") bzlib

%{
#define SWIG_FILE_WITH_INIT
#include "bzlib.h"
%}

void BZ2_bzDecompressInit(DState* s) {
  s->state = BZ_X_BLKHDR_1;
  s->bsLive = 0;
}

int BZ2_bzDecompress(DState *s);

%pythoncode %{
_OUTBUFSIZE = 0x1000

class BzException(Exception):
  pass

def decompress(data):
  state = DState()
  BZ2_bzDecompressInit(state)

  state.next_in = data
  state.avail_in = len(data)

  outbuff = bytearray(_OUTBUFSIZE)
  out = bytearray()

  while True:
    state.next_out = outbuff
    state.avail_out = len(outbuff)
    err = BZ2_bzDecompress(state)
    if err < 0:
      raise BzException(err)

%}

