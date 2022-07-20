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
 * Reviewed for Unicode support by Jim Park -- 08/23/2007
 */

#include "bzlib.h"

/*-------------------------------------------------------------*/
/*--- Library top-level functions.                          ---*/
/*---                                               bzlib.c ---*/
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

/*--
   CHANGES
   ~~~~~~~
   0.9.0 -- original version.

   0.9.0a/b -- no changes in this file.

   0.9.0c
      * made zero-length BZ_FLUSH work correctly in bzCompress().
      * fixed bzWrite/bzRead to ignore zero-length requests.
      * fixed bzread to correctly handle read requests after EOF.
      * wrong parameter order in call to bzDecompressInit in
        bzBuffToBuffDecompress.  Fixed.
--*/
#include "bzlib.h"


/*---------------------------------------------------*/
/*--- Compression stuff                           ---*/
/*---------------------------------------------------*/

#ifdef NSIS_COMPRESS_BZIP2_SMALLMODE
/*---------------------------------------------------*/

Int32 NSISCALL BZ2_indexIntoF ( Int32 indx, Int32 *cftab )
{
  Int32 nb, na, mid;
  nb = 0;
  na = 256;
  do {
    mid = (nb + na) >> 1;
    if (indx >= cftab[mid]) nb = mid;
    else na = mid;
  } while (na - nb != 1);
  return nb;
}


static
Bool NSISCALL unRLE_obuf_to_output_SMALL ( DState* s )
{
   UChar k1;
  while (True) {
     /* try to finish existing run */
     while (True) {
        if (s->avail_out == 0) return;
        if (s->state_out_len == 0) break;
        *( (UChar*)(s->next_out) ) = s->state_out_ch;
        s->state_out_len--;
        s->next_out++;
        s->avail_out--;
     }

     /* can a new run be started? */
     if (s->nblock_used == s->save.nblock+1) return False;

     /* Only caused by corrupt data stream? */
     if (s->nblock_used > s->save_nblock+1)
         return True;

     s->state_out_len = 1;
     s->state_out_ch = s->k0;
     BZ_GET_SMALL(k1); s->nblock_used++;
     if (s->nblock_used == s->save.nblock+1) continue;
     if (k1 != s->k0) { s->k0 = k1; continue; };

     s->state_out_len = 2;
     BZ_GET_SMALL(k1); s->nblock_used++;
     if (s->nblock_used == s->save.nblock+1) continue;
     if (k1 != s->k0) { s->k0 = k1; continue; };

     s->state_out_len = 3;
     BZ_GET_SMALL(k1); s->nblock_used++;
     if (s->nblock_used == s->save.nblock+1) continue;
     if (k1 != s->k0) { s->k0 = k1; continue; };

     BZ_GET_SMALL(k1); s->nblock_used++;
     s->state_out_len = ((Int32)k1) + 4;
     BZ_GET_SMALL(s->k0); s->nblock_used++;
  }
}
#else//!small, fast
static Bool NSISCALL unRLE_obuf_to_output_FAST ( DState* s )
{
   UChar k1;

      /* restore */
      UChar         c_state_out_ch       = s->state_out_ch;
      Int32         c_state_out_len      = s->state_out_len;
      Int32         c_nblock_used        = s->nblock_used;
      Int32         c_k0                 = s->k0;
      UInt32        c_tPos               = s->tPos;

      char*         cs_next_out          = (char*) s->next_out;
      unsigned int  cs_avail_out         = s->avail_out;
      /* end restore */

      UInt32*       c_tt                 = s->tt;
      Int32        s_save_nblockPP = s->save.nblock+1;
//      unsigned int total_out_lo32_old;

      while (True) {

         /* try to finish existing run */
         if (c_state_out_len > 0) {
            while (True) {
               if (cs_avail_out == 0) goto return_notr;
               if (c_state_out_len == 1) break;
               *( (UChar*)(cs_next_out) ) = c_state_out_ch;
               c_state_out_len--;
               cs_next_out++;
               cs_avail_out--;
            }
            s_state_out_len_eq_one:
            {
               if (cs_avail_out == 0) {
                  c_state_out_len = 1; goto return_notr;
               };
               *( (UChar*)(cs_next_out) ) = c_state_out_ch;
               cs_next_out++;
               cs_avail_out--;
            }
         }
         /* Only caused by corrupt data stream? */
         if (c_nblock_used > s_save_nblockPP)
             return True;

         /* can a new run be started? */
         if (c_nblock_used == s_save_nblockPP) {
            c_state_out_len = 0; goto return_notr;
         };
         c_state_out_ch = c_k0;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (k1 != c_k0) {
            c_k0 = k1; goto s_state_out_len_eq_one;
         };
         if (c_nblock_used == s_save_nblockPP)
            goto s_state_out_len_eq_one;

         c_state_out_len = 2;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         c_state_out_len = 3;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         BZ_GET_FAST_C(k1); c_nblock_used++;
         c_state_out_len = ((Int32)k1) + 4;
         BZ_GET_FAST_C(c_k0); c_nblock_used++;
      }

      return_notr:
      s->state_out_ch       = c_state_out_ch;
      s->state_out_len      = c_state_out_len;
      s->nblock_used        = c_nblock_used;
      s->k0                 = c_k0;
      s->tPos               = c_tPos;
      s->next_out     = (unsigned char*) cs_next_out;
      s->avail_out    = cs_avail_out;
      /* end save */
      return False;
}

#endif


/*---------------------------------------------------*/
int NSISCALL BZ2_bzDecompress( DState *s )
{
   Bool    corrupt;
   while (True) {
      if (s->state == BZ_X_IDLE) return BZ_SEQUENCE_ERROR;
      if (s->state == BZ_X_OUTPUT) {
#ifdef NSIS_COMPRESS_BZIP2_SMALLMODE
        corrupt = unRLE_obuf_to_output_SMALL ( s );
#else
        corrupt = unRLE_obuf_to_output_FAST ( s );
#endif
         if (corrupt) return BZ_DATA_ERROR;
         if (s->nblock_used == s->save.nblock+1 && s->state_out_len == 0) {
            s->state = BZ_X_BLKHDR_1;
         } else {
            return BZ_OK;
         }
      }
      if (s->state >= BZ_X_BLKHDR_1) {
         Int32 r = BZ2_decompress ( s );
         if (r == BZ_STREAM_END) {
            return r;
         }
         if (s->state != BZ_X_OUTPUT) return r;
      }
   }
}

