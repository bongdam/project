#define _ASSEMBLER_
#include <sysdefs.h>
#include <mips.h>
//#include <asm/init.h>

	.set noreorder

/************************************************************************
 *
 *                          sys_init_cache
 *  Description :
 *  -------------
 *
 *  Invalidate I and D caches
 *
 *  input : k1 = processor ID
 *
 *  Return values :
 *  ---------------
 *
 *  Always 0
 *
 ************************************************************************/
ULEAF(sys_init_cache)

	/**** Determine cache settings ****/

	/* This code was linked cached, but is running uncached since
	 * caches have not been initialised yet.
	 */

#define RA			t4
#define icache_size		t3
#define icache_linesize		t2
#define dcache_size		t1
#define dcache_linesize		t0

	move	RA, ra

	move	a0, k1

	/*
	 * MIPSCMP
	 * by definition only CPU 0 initialises the L2 cache, so
	 * reset the value of v1
	 */
	move	v1, zero

1:
	/* L1 cache */

	bal	sys_determine_icache_linesize_flash
	nop
	move	icache_linesize, v0

	bal	sys_determine_icache_lines_flash
	nop
	multu	icache_linesize, v0
	mflo	icache_size

	bal	sys_determine_dcache_linesize_flash
	nop
	move	dcache_linesize, v0

	bal	sys_determine_dcache_lines_flash
	nop
	multu	dcache_linesize, v0
	mflo	dcache_size

	beq	icache_size, zero, 1f
	nop
	beq	dcache_size, zero, 1f
	nop

	/* Initialise instruction cache */
	move	a0, icache_size
	move	a1, icache_linesize
	bal	sys_init_icache
	 move	a2, k1

	/* Initialise data cache */
	move	a0, dcache_size
	move	a1, dcache_linesize
	bal	sys_init_dcache
	 move	a2, k1

	/* Done */
	jr	RA
	move	v0, zero

	/* D-cache or I-cache has size 0,  set CPU uncached */
1:
	MFC0(   v0, C0_Config )
	and	v0, ~M_ConfigK0
	or	v0, K_CacheAttrU
	MTC0(   v0, C0_Config )

	/* Done */
	jr	RA
	move	v0, zero

END(sys_init_cache)


/************************************************************************
 *
 *                          sys_determine_icache_linesize_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine ICACHE linesize
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = ICACHE linesize in bytes
 *
 ************************************************************************/
ULEAF(sys_determine_icache_linesize_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), icache_linesize_mips
	 nop

	/* Unknown CPU */
icache_linesize_zero:
	jr	ra
	 move	v0, zero

icache_linesize_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* I-cache line size */
	and	t9, M_Config1IL
	beqz	t9, icache_linesize_zero
	 nop

	srl	t9, S_Config1IL
	li	v0, 0x2
	jr	ra
	 sll	v0, t9

END(sys_determine_icache_linesize_flash)



/************************************************************************
 *
 *                          sys_determine_icache_lines_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine number of ICACHE lines
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = number of ICACHE lines
 *
 ************************************************************************/
ULEAF(sys_determine_icache_lines_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), icache_lines_mips
	 nop

	/* Unknown CPU */
icache_lines_zero:
	jr	ra
	 move	v0, zero

icache_lines_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* I-cache lines
	 * Calculated as associativity * sets per way
	 */
	and	t8, t9, M_Config1IA
	srl	t8, S_Config1IA
	addiu	t8, 1				/* t8 = associativity	*/

	and	t9, M_Config1IS
	srl	t9, S_Config1IS

	/* check for 32 ways */
	beq	t9, 0x7, 1f
	li	t7, 32				/* delay slot */

	li	t7, 0x40
	sll	t7, t9				/* t7 = sets per way	*/
1:

	multu	t8, t7

	jr	ra
	 mflo    v0

END(sys_determine_icache_lines_flash)


/************************************************************************
 *
 *                          sys_determine_icache_assoc_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine ICACHE associativity
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = ICACHE associativity
 *
 ************************************************************************/
ULEAF(sys_determine_icache_assoc_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), icache_assoc_mips
	 nop

	/* Unknown CPU */
icache_assoc_zero:
	jr	ra
	 move	v0, zero

icache_assoc_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* I-cache associativity */
	and	v0, t9, M_Config1IA
	srl	v0, S_Config1IA
	jr	ra
	 addiu	v0, 1

END(sys_determine_icache_assoc_flash)


/************************************************************************
 *
 *                          sys_determine_dcache_linesize_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine DCACHE linesize
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = DCACHE linesize in bytes
 *
 ************************************************************************/
ULEAF(sys_determine_dcache_linesize_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), dcache_linesize_mips
	 nop

	/* Unknown CPU */
dcache_linesize_zero:
	jr	ra
	 move	v0, zero

dcache_linesize_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* D-cache line size */
	and	t9, M_Config1DL
	beqz	t9, dcache_linesize_zero
	 nop

	srl	t9, S_Config1DL
	li	v0, 0x2
	jr	ra
	 sll	v0, t9

END(sys_determine_dcache_linesize_flash)


/************************************************************************
 *
 *                          sys_determine_dcache_lines_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine number of DCACHE lines
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = number of DCACHE lines
 *
 ************************************************************************/
ULEAF(sys_determine_dcache_lines_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), dcache_lines_mips
	 nop

	/* Unknown CPU */
dcache_lines_zero:
	jr	ra
	 move	v0, zero

dcache_lines_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* D-cache lines
	 * Calculated as associativity * sets per way
	 */
	and	t8, t9, M_Config1DA
	srl	t8, S_Config1DA
	addiu	t8, 1				/* t8 = associativity	*/

	and	t9, M_Config1DS
	srl	t9, S_Config1DS

	/* check for 32 ways */
	beq	t9, 0x7, 1f
	li	t7, 32				/* delay slot */

	li	t7, 0x40
	sll	t7, t9				/* t7 = sets per way	*/
1:

	multu	t8, t7

	jr	ra
	 mflo    v0
END(sys_determine_dcache_lines_flash)



/************************************************************************
 *
 *                          sys_determine_dcache_assoc_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine DCACHE associativity
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = DCACHE associativity
 *
 ************************************************************************/
ULEAF(sys_determine_dcache_assoc_flash)
	/* Check if it is a MIPS32/64 processor */
	and     t9, a0, M_PRIdCoID
	bne	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), dcache_assoc_mips
	 nop

	/* Unknown CPU */
dcache_assoc_zero:
	jr	ra
	 move	v0, zero

dcache_assoc_mips:
	/* Read CONFIG1 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config1, R_C0_SelConfig1 )

	/* D-cache associativity */
	and	v0, t9, M_Config1DA
	srl	v0, S_Config1DA
	jr	ra
	 addiu	v0, 1

END(sys_determine_dcache_assoc_flash)

/************************************************************************
 *
 *                          sys_determine_dcache_antialias_flash
 *  Note :
 *  ------
 *  This routine is called also from syscon.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Determine whether CPU has hardware anitialising on Dcache
 *
 *  input : a0 = processor ID
 *
 *  Return values :
 *  ---------------
 *  v0 = TRUE/FALSE
 *
 ************************************************************************/
ULEAF(sys_determine_dcache_antialias_flash)

	/* Only some MIPS32/64 processors support dcache HW antialiasing */
	and     t9, a0, M_PRIdCoID
	beq	t9, (C0_PRID_COMP_NOT_MIPS32_64<<S_PRIdCoID), dcache_antialias_found
	 move	v0, zero

	/* Read CONFIG7 register, which holds implementation data */
	MFC0_SEL_OPCODE( R_t9, R_C0_Config7, R_C0_SelConfig7 )
	and	v0, t9, M_Config7AR
	srl	v0, S_Config7AR

dcache_antialias_found:
	jr	ra
	 nop

END(sys_determine_dcache_antialias_flash)

/*
 * Tag register usage for MIPS 24K processors
 *
 * Proc		Dcache			Icache			L2cache
 * 24K		dtaglo(28/2)		itaglo(28/0)		l23taglo(28/4)
 */

/************************************************************************
 *
 *                          sys_init_icache
 *  Note :
 *  ------
 *  This routine is called also from sys_cpu.c and syscon_cpu.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Invalidate entire ICACHE
 *
 *  Inputs : a0 = cache size (bytes)
 *           a1 = line size  (bytes)
 *
 *  Return values :
 *  ---------------
 *  None
 *
 ************************************************************************/
ULEAF( sys_init_icache )

#ifdef NO_CACHE

	jr	ra
	nop

#else

	beq   a0, zero, 9f		 /* just in case cache size = 0 */
	 nop

	/*
	 * Mask and shift the processor id so that we can
	 * use xori in the tests
	 */
	and	a2, M_PRIdCoID|M_PRIdImp
	srl	a2, S_PRIdImp

#define X(this, last, type) \
	xori	a2, ((MIPS_##last)>>S_PRIdImp)^((MIPS_##this)>>S_PRIdImp); \
	beqz	a2, init_icache_##type
#define MIPS_0	0
	X(24K,		5KE,		itaglo)
	nop
#undef MIPS_0
#undef X

	/* default: Clear TagHi/TagLo */
init_icache_itaglo:
	MTC0( zero, C0_TagLo )

0:
	/* Calc an address that will correspond to the first cache line */
	li	a2, KSEG0BASE

	/* Calc an address that will correspond to the last cache line  */
	addu	a3, a2, a0
	subu    a3, a1

	/* Loop through all lines, invalidating each of them */
1:
SET_MIPS3()
	cache	ICACHE_INDEX_STORE_TAG, 0(a2)	/* clear tag */
SET_MIPS0()
	bne	a2, a3, 1b
	addu	a2, a1

9:
	jr	ra
	nop

#endif

END( sys_init_icache )


/************************************************************************
 *
 *                          sys_init_dcache
 *  Note :
 *  ------
 *  This routine is called also from sys_cpu.c
 *  and must obey c calling conventions - and cannot use k0/k1
 *
 *  Description :
 *  -------------
 *  Invalidate entire DCACHE
 *
 *  Inputs : a0 = cache size (bytes)
 *           a1 = line size  (bytes)
 *           a2 = processor ID
 *
 *  Return values :
 *  ---------------
 *  None
 *
 ************************************************************************/
ULEAF( sys_init_dcache )

#ifdef NO_CACHE

	jr	ra
	 nop

#else

	/*
	 * Mask and shift the processor id so that we can
	 * use xori in the tests
	 */
	and	a2, M_PRIdCoID|M_PRIdImp
	srl	a2, S_PRIdImp

#define X(this, last, type) \
	xori	a2, ((MIPS_##last)>>S_PRIdImp)^((MIPS_##this)>>S_PRIdImp); \
	beqz	a2, init_dcache_##type
#define MIPS_0	0
	X(24K,		5KE,		dtaglo)
	nop
#undef MIPS_0
#undef X

	/* default: Clear TagHi/TagLo */
init_dcache_dtaglo:
	MTC0_SEL_OPCODE( R_zero, R_C0_DTagLo, R_C0_SelDTagLo )

0:
	/* Calc an address that will correspond to the first cache line */
	li	a2, KSEG0BASE

	/* Calc an address that will correspond to the last cache line  */
	addu	a3, a2, a0
	subu    a3, a1

	/* Loop through all lines, invalidating each of them */
1:
SET_MIPS3()
	cache	DCACHE_INDEX_STORE_TAG, 0(a2)	/* clear tag */
SET_MIPS0()
	bne	a2, a3, 1b
	 addu	a2, a1

9:
	jr	ra
	 nop

#endif

END( sys_init_dcache )