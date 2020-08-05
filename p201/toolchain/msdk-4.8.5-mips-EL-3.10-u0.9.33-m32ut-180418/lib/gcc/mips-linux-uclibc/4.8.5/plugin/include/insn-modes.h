/* Generated automatically from machmode.def and config/mips/mips-modes.def
   by genmodes.  */

#ifndef GCC_INSN_MODES_H
#define GCC_INSN_MODES_H

enum machine_mode
{
  VOIDmode,                /* machmode.def:172 */
  BLKmode,                 /* machmode.def:176 */
  CCmode,                  /* machmode.def:206 */
  CCV2mode,                /* config/mips/mips-modes.def:44 */
  CCV4mode,                /* config/mips/mips-modes.def:48 */
  CCDSPmode,               /* config/mips/mips-modes.def:53 */
  BImode,                  /* machmode.def:179 */
  QImode,                  /* machmode.def:184 */
  HImode,                  /* machmode.def:185 */
  SImode,                  /* machmode.def:186 */
  DImode,                  /* machmode.def:187 */
  TImode,                  /* machmode.def:188 */
  QQmode,                  /* machmode.def:209 */
  HQmode,                  /* machmode.def:210 */
  SQmode,                  /* machmode.def:211 */
  DQmode,                  /* machmode.def:212 */
  TQmode,                  /* machmode.def:213 */
  UQQmode,                 /* machmode.def:215 */
  UHQmode,                 /* machmode.def:216 */
  USQmode,                 /* machmode.def:217 */
  UDQmode,                 /* machmode.def:218 */
  UTQmode,                 /* machmode.def:219 */
  HAmode,                  /* machmode.def:221 */
  SAmode,                  /* machmode.def:222 */
  DAmode,                  /* machmode.def:223 */
  TAmode,                  /* machmode.def:224 */
  UHAmode,                 /* machmode.def:226 */
  USAmode,                 /* machmode.def:227 */
  UDAmode,                 /* machmode.def:228 */
  UTAmode,                 /* machmode.def:229 */
  SFmode,                  /* machmode.def:199 */
  DFmode,                  /* machmode.def:200 */
  FSFmode,                 /* machmode.def:201 */
  FDFmode,                 /* machmode.def:202 */
  TFmode,                  /* config/mips/mips-modes.def:25 */
  SDmode,                  /* machmode.def:241 */
  DDmode,                  /* machmode.def:242 */
  TDmode,                  /* machmode.def:243 */
  CQImode,                 /* machmode.def:237 */
  CHImode,                 /* machmode.def:237 */
  CSImode,                 /* machmode.def:237 */
  CDImode,                 /* machmode.def:237 */
  CTImode,                 /* machmode.def:237 */
  SCmode,                  /* machmode.def:238 */
  DCmode,                  /* machmode.def:238 */
  FSCmode,                 /* machmode.def:238 */
  FDCmode,                 /* machmode.def:238 */
  TCmode,                  /* machmode.def:238 */
  V4QImode,                /* config/mips/mips-modes.def:28 */
  V2HImode,                /* config/mips/mips-modes.def:28 */
  V8QImode,                /* config/mips/mips-modes.def:29 */
  V4HImode,                /* config/mips/mips-modes.def:29 */
  V2SImode,                /* config/mips/mips-modes.def:29 */
  V16QImode,               /* config/mips/mips-modes.def:33 */
  V8HImode,                /* config/mips/mips-modes.def:34 */
  V4SImode,                /* config/mips/mips-modes.def:35 */
  V4QQmode,                /* config/mips/mips-modes.def:38 */
  V2HQmode,                /* config/mips/mips-modes.def:38 */
  V4UQQmode,               /* config/mips/mips-modes.def:39 */
  V2UHQmode,               /* config/mips/mips-modes.def:39 */
  V2HAmode,                /* config/mips/mips-modes.def:40 */
  V2UHAmode,               /* config/mips/mips-modes.def:41 */
  V2SFmode,                /* config/mips/mips-modes.def:30 */
  V4SFmode,                /* config/mips/mips-modes.def:36 */
  MAX_MACHINE_MODE,

  MIN_MODE_RANDOM = VOIDmode,
  MAX_MODE_RANDOM = BLKmode,

  MIN_MODE_CC = CCmode,
  MAX_MODE_CC = CCDSPmode,

  MIN_MODE_INT = QImode,
  MAX_MODE_INT = TImode,

  MIN_MODE_PARTIAL_INT = VOIDmode,
  MAX_MODE_PARTIAL_INT = VOIDmode,

  MIN_MODE_FRACT = QQmode,
  MAX_MODE_FRACT = TQmode,

  MIN_MODE_UFRACT = UQQmode,
  MAX_MODE_UFRACT = UTQmode,

  MIN_MODE_ACCUM = HAmode,
  MAX_MODE_ACCUM = TAmode,

  MIN_MODE_UACCUM = UHAmode,
  MAX_MODE_UACCUM = UTAmode,

  MIN_MODE_FLOAT = SFmode,
  MAX_MODE_FLOAT = TFmode,

  MIN_MODE_DECIMAL_FLOAT = SDmode,
  MAX_MODE_DECIMAL_FLOAT = TDmode,

  MIN_MODE_COMPLEX_INT = CQImode,
  MAX_MODE_COMPLEX_INT = CTImode,

  MIN_MODE_COMPLEX_FLOAT = SCmode,
  MAX_MODE_COMPLEX_FLOAT = TCmode,

  MIN_MODE_VECTOR_INT = V4QImode,
  MAX_MODE_VECTOR_INT = V4SImode,

  MIN_MODE_VECTOR_FRACT = V4QQmode,
  MAX_MODE_VECTOR_FRACT = V2HQmode,

  MIN_MODE_VECTOR_UFRACT = V4UQQmode,
  MAX_MODE_VECTOR_UFRACT = V2UHQmode,

  MIN_MODE_VECTOR_ACCUM = V2HAmode,
  MAX_MODE_VECTOR_ACCUM = V2HAmode,

  MIN_MODE_VECTOR_UACCUM = V2UHAmode,
  MAX_MODE_VECTOR_UACCUM = V2UHAmode,

  MIN_MODE_VECTOR_FLOAT = V2SFmode,
  MAX_MODE_VECTOR_FLOAT = V4SFmode,

  NUM_MACHINE_MODES = MAX_MACHINE_MODE
};

#define CONST_MODE_SIZE
#define CONST_MODE_BASE_ALIGN
#define CONST_MODE_IBIT const
#define CONST_MODE_FBIT const

#endif /* insn-modes.h */
