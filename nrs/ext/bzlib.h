/*
 * This file is a part of the bzip2 compression module for NSIS.
 *
 * Copyright and license information can be found below.
 * Modifications Copyright (C) 1999-2015 Nullsoft and Contributors
 *
 * The original zlib source code is available at
 * http://www.bzip.org/
 *
 * This modification is not compatible with the original bzip2.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.
 *
 * Reviewed for Unicode support by Jim Park -- 08/27/2007
 */

/*-------------------------------------------------------------*/
/*--- Public header file for the library.                   ---*/
/*---                                               bzlib.h ---*/
/*-------------------------------------------------------------*/

/*--
  This file is a part of bzip2 and/or libbzip2, a program and
  library for lossless, block-sorting data compression.

  Copyright (C) 1996-2000 Julian R Seward.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software.  If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  3. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  4. The name of the author may not be used to endorse or promote
     products derived from this software without specific prior written
     permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Julian Seward, Cambridge, UK.
  jseward@acm.org
  bzip2/libbzip2 version 1.0 of 21 March 2000

  This program is based on (at least) the work of:
     Mike Burrows
     David Wheeler
     Peter Fenwick
     Alistair Moffat
     Radford Neal
     Ian H. Witten
     Robert Sedgewick
     Jon L. Bentley

  For more information on these sources, see the manual.
--*/


#ifndef _BZLIB_H
#define _BZLIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
//#include "../Platform.h"

#define BZ_RUN               0
#define BZ_FLUSH             1
#define BZ_FINISH            2

#define BZ_OK                0
#define BZ_RUN_OK            1
#define BZ_FLUSH_OK          2
#define BZ_FINISH_OK         3
#define BZ_STREAM_END        4
#define BZ_SEQUENCE_ERROR    (-1)
#define BZ_PARAM_ERROR       (-2)
#define BZ_MEM_ERROR         (-3)
#define BZ_DATA_ERROR        (-4)
#define BZ_DATA_ERROR_MAGIC  (-5)
#define BZ_IO_ERROR          (-6)
#define BZ_UNEXPECTED_EOF    (-7)
#define BZ_OUTBUFF_FULL      (-8)
#define BZ_CONFIG_ERROR      (-9)

/*-- Constants for the back end. --*/

#define BZ_MAX_ALPHA_SIZE 258
#define BZ_MAX_CODE_LEN    23

#define BZ_RUNA 0
#define BZ_RUNB 1

#define BZ_N_GROUPS 6
#define BZ_G_SIZE   50
#define BZ_N_ITERS  4

#define BZ_MAX_SELECTORS (2 + (900000 / BZ_G_SIZE))

typedef char            Char;
typedef unsigned char   Bool;
typedef unsigned char   UChar;
typedef int             Int32;
typedef unsigned int    UInt32;
typedef short           Int16;
typedef unsigned short  UInt16;

#define True  ((Bool)1)
#define False ((Bool)0)

#define AssertD(cond,msg) /* */
#define AssertH(cond,errcode) /* */
#define AssertD(cond,msg) /* */
#define VPrintf0(zf) /* */
#define VPrintf1(zf,za1) /* */
#define VPrintf2(zf,za1,za2) /* */
#define VPrintf3(zf,za1,za2,za3) /* */
#define VPrintf4(zf,za1,za2,za3,za4) /* */
#define VPrintf5(zf,za1,za2,za3,za4,za5) /* */

/*-- states for decompression. --*/

#define BZ_X_IDLE        1
#define BZ_X_OUTPUT      2

#define BZ_X_BLKHDR_1    11
#define BZ_X_RANDBIT     12
#define BZ_X_ORIGPTR_1   13
#define BZ_X_ORIGPTR_2   14
#define BZ_X_ORIGPTR_3   15
#define BZ_X_MAPPING_1   16
#define BZ_X_MAPPING_2   17
#define BZ_X_SELECTOR_1  18
#define BZ_X_SELECTOR_2  19
#define BZ_X_SELECTOR_3  20
#define BZ_X_CODING_1    21
#define BZ_X_CODING_2    22
#define BZ_X_CODING_3    23
#define BZ_X_MTF_1       24
#define BZ_X_MTF_2       25
#define BZ_X_MTF_3       26
#define BZ_X_MTF_4       27
#define BZ_X_MTF_5       28
#define BZ_X_MTF_6       29



/*-- Constants for the fast MTF decoder. --*/

#define MTFA_SIZE 4096
#define MTFL_SIZE 16



/* save area for scalars in the main decompress code */
typedef struct {
  Int32    i;
  Int32    j;
  Int32    t;
  Int32    alphaSize;
  Int32    nGroups;
  Int32    nSelectors;
  Int32    EOB;
  Int32    groupNo;
  Int32    groupPos;
  Int32    nextSym;
  Int32    nblockMAX;
  Int32    nblock;
  Int32    es;
  Int32    N;
  Int32    curr;
  Int32    zt;
  Int32    zn;
  Int32    zvec;
  Int32    zj;
  Int32    gSel;
  Int32    gMinlen;
  Int32*   gLimit;
  Int32*   gBase;
  Int32*   gPerm;
} DState_save;

/*-- Structure holding all the decompression-side stuff. --*/

typedef struct {
  /* pointer back to the struct bz_stream */
  unsigned char *next_in;
  unsigned int avail_in;

  unsigned char *next_out;
  unsigned int avail_out;

  /* state indicator for this stream */
  char state;

  UChar    state_out_ch;
  Int32    state_out_len;
  Int32    nblock_used;
  Int32    k0;
  UInt32   tPos;

  /* the buffer for bit stream reading */
  UInt32   bsBuff;
  Int32    bsLive;

  /* for undoing the Burrows-Wheeler transform */
  Int32    origPtr;
  Int32    unzftab[256];
  Int32    cftab[257];
  Int32    cftabCopy[257];

#ifndef NSIS_COMPRESS_BZIP2_SMALLMODE
  /* for undoing the Burrows-Wheeler transform (FAST) */
  UInt32   tt[ NSIS_COMPRESS_BZIP2_LEVEL * 100000 ];
#else
  /* for undoing the Burrows-Wheeler transform (SMALL) */
  UInt16   ll16 [ NSIS_COMPRESS_BZIP2_LEVEL*100000 ];
  UChar    ll4 [((1 + NSIS_COMPRESS_BZIP2_LEVEL*100000) >> 1) ];
#endif

  /* map of bytes used in block */
  Int32    nInUse;
  Bool     inUse[256];
  Bool     inUse16[16];
  UChar    seqToUnseq[256];

  /* for decoding the MTF values */
  UChar    mtfa   [MTFA_SIZE];
  Int32    mtfbase[256 / MTFL_SIZE];
  UChar    selector   [BZ_MAX_SELECTORS];
  UChar    selectorMtf[BZ_MAX_SELECTORS];
  UChar    len  [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];

  Int32    limit  [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
  Int32    base   [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
  Int32    perm   [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
  Int32    minLens[BZ_N_GROUPS];

  /* save area for scalars in the main decompress code */
  DState_save save;
} DState;


#ifndef NSIS_COMPRESS_BZIP2_SMALLMODE
/*-- Macros for decompression. --*/

#define BZ_GET_FAST(cccc)                     \
    s->tPos = s->tt[s->tPos];                 \
    cccc = (UChar)(s->tPos & 0xff);           \
    s->tPos >>= 8;

#define BZ_GET_FAST_C(cccc)                   \
    c_tPos = c_tt[c_tPos];                    \
    cccc = (UChar)(c_tPos & 0xff);            \
    c_tPos >>= 8;


#else//NSIS_COMPRESS_BZIP2_SMALLMODE

#define SET_LL4(i,n)                                          \
   { if (((i) & 0x1) == 0)                                    \
        s->ll4[(i) >> 1] = (s->ll4[(i) >> 1] & 0xf0) | (n); else    \
        s->ll4[(i) >> 1] = (s->ll4[(i) >> 1] & 0x0f) | ((n) << 4);  \
   }

#define GET_LL4(i)                             \
   ((((UInt32)(s->ll4[(i) >> 1])) >> (((i) << 2) & 0x4)) & 0xF)

#define SET_LL(i,n)                          \
   { s->ll16[i] = (UInt16)(n & 0x0000ffff);  \
     SET_LL4(i, n >> 16);                    \
   }

#define GET_LL(i) \
   (((UInt32)s->ll16[i]) | (GET_LL4(i) << 16))

#define BZ_GET_SMALL(cccc)                            \
      cccc = BZ2_indexIntoF ( s->tPos, s->cftab );    \
      s->tPos = GET_LL(s->tPos);

extern Int32 BZ2_indexIntoF( Int32, Int32* );

#endif//smallmode

/*-- externs for decompression. --*/
extern Int32 BZ2_decompress ( DState* );

extern void BZ2_hbCreateDecodeTables ( Int32*, Int32*, Int32*, UChar*,
                           Int32,  Int32, Int32 );


#define BZ2_bzDecompressInit(s) { (s)->state = BZ_X_BLKHDR_1; (s)->bsLive = 0; }
int NSISCALL BZ2_bzDecompress(DState *s);


#ifdef __cplusplus
}
#endif

#endif

/*-------------------------------------------------------------*/
/*--- end                                           bzlib.h ---*/
/*-------------------------------------------------------------*/
