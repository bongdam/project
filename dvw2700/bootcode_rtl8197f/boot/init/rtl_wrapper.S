	.file	1 "rtl_wrapper.c"
	.section .mdebug.abi32
	.previous
	.gnu_attribute 4, 3
	.abicalls
	.option	pic0
	.section	.text.mdelay,"ax",@progbits
	.align	2
	.set	nomips16
	.ent	mdelay
	.type	mdelay, @function
mdelay:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	lui	$2,%hi(config_sys_mips_timer_fre)
	lw	$3,%lo(config_sys_mips_timer_fre)($2)
	li	$2,983040			# 0xf0000
	ori	$2,$2,0x4240
	divu	$0,$3,$2
	teq	$2,$0,7
	li	$5,2147418112			# 0x7fff0000
	li	$2,1000			# 0x3e8
	ori	$5,$5,0xffff
	mflo	$3
	.set	noreorder
	.set	nomacro
	j	$L2
	mul	$3,$3,$2
	.set	macro
	.set	reorder

$L4:
 #APP
 # 11 "./main/misc.c" 1
	mfc0	$2, $9
	
 # 0 "" 2
 #NO_APP
	addu	$2,$2,$3
$L3:
 #APP
 # 12 "./main/misc.c" 1
	mfc0	$6, $9
	
 # 0 "" 2
 #NO_APP
	subu	$6,$2,$6
	sltu	$6,$6,$5
	bne	$6,$0,$L3
	addiu	$4,$4,-1
$L2:
	bne	$4,$0,$L4
	j	$31
	.end	mdelay
	.size	mdelay, .-mdelay
	.section	.text.r02,"ax",@progbits
	.align	2
	.globl	r02
	.set	nomips16
	.ent	r02
	.type	r02, @function
r02:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	li	$2,-1191182336			# 0xffffffffb9000000
	ori	$2,$2,0x37
	lbu	$3,0($2)
	andi	$3,$3,0x00ff
	seb	$7,$3
	.set	noreorder
	.set	nomacro
	bgezl	$7,$L20
	li	$3,-1191182336			# 0xffffffffb9000000
	.set	macro
	.set	reorder

	andi	$3,$3,0x7f
	sb	$3,0($2)
	li	$3,-1191182336			# 0xffffffffb9000000
$L20:
	li	$2,983040			# 0xf0000
	ori	$3,$3,0x30
	ori	$2,$2,0x4240
	li	$8,2147418112			# 0x7fff0000
	move	$7,$3
	addu	$5,$5,$4
	ori	$8,$8,0xffff
	lw	$3,0($3)
	lui	$10,%hi(config_sys_mips_timer_fre)
	.set	noreorder
	.set	nomacro
	j	$L10
	move	$9,$2
	.set	macro
	.set	reorder

$L15:
	andi	$11,$4,0x3ff
	sll	$11,$11,8
	divu	$0,$12,$2
	teq	$2,$0,7
	ins	$3,$11,0,18
	and	$11,$3,$8
	sw	$11,0($7)
	move	$11,$9
	mflo	$14
$L14:
 #APP
 # 11 "./main/misc.c" 1
	mfc0	$12, $9
	
 # 0 "" 2
 #NO_APP
	addu	$12,$12,$14
$L11:
 #APP
 # 12 "./main/misc.c" 1
	mfc0	$13, $9
	
 # 0 "" 2
 #NO_APP
	subu	$13,$12,$13
	sltu	$13,$13,$8
	bne	$13,$0,$L11
	addiu	$11,$11,-1
	lw	$13,0($7)
	bne	$11,$0,$L12
	.set	noreorder
	.set	nomacro
	j	$31
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

$L12:
	bgez	$13,$L14
	sb	$13,0($6)
	addiu	$4,$4,1
	addiu	$6,$6,1
$L10:
	sltu	$11,$4,$5
	.set	noreorder
	.set	nomacro
	bne	$11,$0,$L15
	lw	$12,%lo(config_sys_mips_timer_fre)($10)
	.set	macro
	.set	reorder

	move	$2,$0
	j	$31
	.end	r02
	.size	r02, .-r02
	.section	.text.cp,"ax",@progbits
	.align	2
	.globl	cp
	.set	nomips16
	.ent	cp
	.type	cp, @function
cp:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	cp
	.size	cp, .-cp
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC0:
	.ascii	"0123456789ABCDEF\000"
	.section	.text._dprintf,"ax",@progbits
	.align	2
	.set	nomips16
	.ent	_dprintf
	.type	_dprintf, @function
_dprintf:
	.frame	$sp,32,$31		# vars= 24, regs= 0/0, args= 0, gp= 8
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	li	$2,-1206648832			# 0xffffffffb8140000
	lui	$14,%hi($LC0)
	sw	$7,44($sp)
	ori	$8,$2,0x7024
	sw	$5,36($sp)
	sw	$6,40($sp)
	sw	$4,32($sp)
	addiu	$14,$14,%lo($LC0)
	addiu	$3,$sp,36
	li	$13,37			# 0x25
	li	$12,115			# 0x73
	li	$7,10			# 0xa
	addiu	$11,$sp,12
	ori	$2,$2,0x7014
	li	$10,13			# 0xd
	j	$L25
	addiu	$9,$sp,13

$L63:
	beql	$5,$13,$L26
	addiu	$4,$4,1

	sw	$0,8($sp)
	j	$L27
	nop

$L28:
	lw	$6,0($2)
	andi	$6,$6,0x20
	sw	$6,8($sp)
$L27:
	lw	$6,8($sp)
	beq	$6,$0,$L28
	nop

	sw	$5,0($8)
	bnel	$5,$7,$L25
	addiu	$4,$4,1

	sw	$0,8($sp)
	j	$L30
	nop

$L31:
	lw	$5,0($2)
	andi	$5,$5,0x20
	sw	$5,8($sp)
$L30:
	lw	$5,8($sp)
	beq	$5,$0,$L31
	nop

	sw	$10,0($8)
	j	$L25
	addiu	$4,$4,1

$L26:
	lb	$5,0($4)
	bnel	$5,$12,$L32
	andi	$5,$5,0x00ff

	j	$L33
	lw	$5,0($3)

$L39:
	sw	$0,8($sp)
	j	$L34
	nop

$L35:
	lw	$15,0($2)
	andi	$15,$15,0x20
	sw	$15,8($sp)
$L34:
	lw	$15,8($sp)
	beq	$15,$0,$L35
	nop

	sw	$6,0($8)
	bnel	$6,$7,$L33
	addiu	$5,$5,1

	sw	$0,8($sp)
	j	$L37
	nop

$L38:
	lw	$6,0($2)
	andi	$6,$6,0x20
	sw	$6,8($sp)
$L37:
	lw	$6,8($sp)
	beq	$6,$0,$L38
	nop

	sw	$10,0($8)
	addiu	$5,$5,1
$L33:
	lb	$6,0($5)
	bne	$6,$0,$L39
	nop

	j	$L29
	addiu	$3,$3,4

$L32:
	addiu	$24,$5,-48
	andi	$24,$24,0x00ff
	sltu	$24,$24,10
	move	$15,$0
	beq	$24,$0,$L41
	li	$6,28			# 0x1c

	j	$L68
	addiu	$6,$5,-48

$L43:
	addiu	$4,$4,1
	addu	$15,$6,$5
	lbu	$5,0($4)
	addiu	$15,$15,-48
	addiu	$6,$5,-48
$L68:
	andi	$6,$6,0x00ff
	sltu	$6,$6,10
	bne	$6,$0,$L43
	mul	$6,$15,$7

	addiu	$6,$15,-1
	sll	$6,$6,2
$L41:
	lb	$5,0($4)
	li	$15,120			# 0x78
	beq	$5,$15,$L69
	andi	$24,$5,0x20

	li	$15,88			# 0x58
	bnel	$5,$15,$L45
	li	$6,100			# 0x64

	andi	$24,$5,0x20
$L69:
	lw	$15,0($3)
	j	$L46
	move	$5,$11

$L47:
	lbu	$25,0($25)
	addiu	$6,$6,-4
	or	$25,$25,$24
	sb	$25,0($5)
	addiu	$5,$5,1
$L46:
	sra	$25,$15,$6
	andi	$25,$25,0xf
	bgez	$6,$L47
	addu	$25,$25,$14

	j	$L48
	addiu	$3,$3,4

$L45:
	bne	$5,$6,$L49
	li	$6,99			# 0x63

	lw	$15,0($3)
	bgez	$15,$L51
	move	$6,$11

	li	$5,45			# 0x2d
	sb	$5,12($sp)
	subu	$15,$0,$15
	move	$6,$9
$L51:
	move	$5,$6
$L52:
	div	$0,$15,$7
	teq	$7,$0,7
	mfhi	$15
	addiu	$24,$15,48
	sb	$24,0($5)
	mflo	$15
	bne	$15,$0,$L52
	addiu	$5,$5,1

	j	$L53
	move	$15,$5

$L54:
	lb	$24,0($15)
	sb	$25,0($15)
	sb	$24,0($6)
	addiu	$6,$6,1
$L53:
	addiu	$15,$15,-1
	sltu	$24,$6,$15
	bnel	$24,$0,$L54
	lbu	$25,0($6)

	j	$L48
	addiu	$3,$3,4

$L49:
	bnel	$5,$6,$L55
	sb	$5,12($sp)

	lw	$6,0($3)
	move	$5,$9
	addiu	$3,$3,4
	j	$L48
	sb	$6,12($sp)

$L55:
	move	$5,$9
$L48:
	j	$L56
	move	$6,$11

$L62:
	sw	$0,8($sp)
	j	$L57
	nop

$L58:
	lw	$24,0($2)
	andi	$24,$24,0x20
	sw	$24,8($sp)
$L57:
	lw	$24,8($sp)
	beq	$24,$0,$L58
	nop

	sw	$15,0($8)
	bnel	$15,$7,$L56
	addiu	$6,$6,1

	sw	$0,8($sp)
	j	$L60
	nop

$L61:
	lw	$15,0($2)
	andi	$15,$15,0x20
	sw	$15,8($sp)
$L60:
	lw	$15,8($sp)
	beq	$15,$0,$L61
	nop

	sw	$10,0($8)
	addiu	$6,$6,1
$L56:
	sltu	$15,$6,$5
	bnel	$15,$0,$L62
	lb	$15,0($6)

$L29:
	addiu	$4,$4,1
$L25:
	lb	$5,0($4)
	bne	$5,$0,$L63
	nop

	addiu	$sp,$sp,32
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	_dprintf
	.size	_dprintf, .-_dprintf
	.section	.text.T.44,"ax",@progbits
	.align	2
	.set	nomips16
	.ent	T.44
	.type	T.44, @function
T.44:
	.frame	$sp,32,$31		# vars= 0, regs= 2/0, args= 16, gp= 8
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	sw	$31,28($sp)
	sw	$16,24($sp)
	li	$16,-1196425216			# 0xffffffffb8b00000
	ori	$16,$16,0x1008
	li	$4,10			# 0xa
	sw	$0,0($16)
	jal	mdelay
	nop

	li	$2,129			# 0x81
	sw	$2,0($16)
	lw	$31,28($sp)
	lw	$16,24($sp)
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	T.44
	.size	T.44, .-T.44
	.section	.rodata.str1.4
	.align	2
$LC1:
	.ascii	"[%d]\000"
	.align	2
$LC2:
	.ascii	"uuuuuuuuuuuuuuuuuuuuuuuuu\000"
	.section	.text.adj_cpu_freq,"ax",@progbits
	.align	2
	.globl	adj_cpu_freq
	.set	nomips16
	.ent	adj_cpu_freq
	.type	adj_cpu_freq, @function
adj_cpu_freq:
	.frame	$sp,96,$31		# vars= 56, regs= 4/0, args= 16, gp= 8
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-96
	sw	$31,92($sp)
	sw	$18,88($sp)
	sw	$17,84($sp)
	sw	$16,80($sp)
	li	$2,-1207959552			# 0xffffffffb8000000
	ori	$2,$2,0x8
	lw	$3,0($2)
	andi	$4,$3,0x4000
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L74
	li	$2,200			# 0xc8
	.set	macro
	.set	reorder

	ext	$4,$3,15,4
	sltu	$5,$4,7
	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L76
	move	$2,$0
	.set	macro
	.set	reorder

	addiu	$2,$4,-7
	andi	$2,$2,0x00ff
$L76:
	li	$4,50			# 0x32
	mul	$2,$2,$4
	addiu	$2,$2,800
$L74:
	ext	$4,$3,19,2
	srl	$4,$2,$4
	li	$5,983040			# 0xf0000
	ori	$5,$5,0x4240
	srl	$4,$4,1
	mul	$4,$4,$5
	lui	$2,%hi(config_sys_mips_timer_fre)
	addiu	$3,$sp,44
	addiu	$5,$sp,76
	.set	noreorder
	.set	nomacro
	j	$L77
	sw	$4,%lo(config_sys_mips_timer_fre)($2)
	.set	macro
	.set	reorder

$L78:
	addiu	$3,$3,1
$L77:
	.set	noreorder
	.set	nomacro
	bnel	$3,$5,$L78
	sb	$0,0($3)
	.set	macro
	.set	reorder

	li	$2,983040			# 0xf0000
	ori	$2,$2,0x4240
	divu	$0,$4,$2
	teq	$2,$0,7
	li	$3,-1207959552			# 0xffffffffb8000000
	li	$6,17039360			# 0x1040000
	ori	$5,$3,0x708
	ori	$6,$6,0xa4f
	sw	$6,0($5)
	ori	$5,$3,0x704
	lw	$7,0($5)
	li	$6,-2			# 0xfffffffffffffffe
	ori	$3,$3,0x700
	and	$6,$7,$6
	sw	$6,0($5)
	lw	$6,0($3)
	li	$5,-65536			# 0xffffffffffff0000
	ori	$5,$5,0x7fff
	and	$5,$6,$5
	li	$7,2147418112			# 0x7fff0000
	sw	$5,0($3)
	move	$8,$3
	ori	$7,$7,0xffff
	move	$3,$0
	li	$6,65536			# 0x10000
	li	$5,5000			# 0x1388
	mflo	$4
$L81:
	lw	$2,0($8)
	and	$2,$2,$6
	.set	noreorder
	.set	nomacro
	bnel	$2,$0,$L79
	sltu	$3,$3,5000
	.set	macro
	.set	reorder

	addiu	$3,$3,1
 #APP
 # 11 "./main/misc.c" 1
	mfc0	$2, $9
	
 # 0 "" 2
 #NO_APP
	addu	$2,$2,$4
$L80:
 #APP
 # 12 "./main/misc.c" 1
	mfc0	$9, $9
	
 # 0 "" 2
 #NO_APP
	subu	$9,$2,$9
	sltu	$9,$9,$7
	bne	$9,$0,$L80
	.set	noreorder
	.set	nomacro
	bne	$3,$5,$L81
	li	$16,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L196
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

$L79:
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L82
	li	$11,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	ori	$11,$11,0x780
	move	$2,$0
	li	$10,-4			# 0xfffffffffffffffc
	li	$9,2			# 0x2
	li	$8,3			# 0x3
	li	$7,1			# 0x1
	li	$25,15			# 0xf
	addiu	$24,$sp,36
	li	$15,4			# 0x4
	addu	$3,$2,$11
$L202:
	and	$3,$3,$10
	lw	$4,0($3)
	andi	$5,$2,0x3
	.set	noreorder
	.set	nomacro
	beq	$5,$9,$L87
	ext	$3,$4,16,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$5,$8,$L87
	srl	$3,$4,24
	.set	macro
	.set	reorder

	ext	$6,$4,8,8
	xor	$5,$5,$7
	andi	$3,$4,0x00ff
	movz	$3,$6,$5
$L87:
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L88
	addiu	$2,$2,1
	.set	macro
	.set	reorder

	andi	$4,$3,0x1f
	.set	noreorder
	.set	nomacro
	bnel	$4,$25,$L89
	andi	$4,$3,0xf
	.set	macro
	.set	reorder

	addu	$4,$2,$11
	and	$4,$4,$10
	lw	$5,0($4)
	andi	$6,$2,0x3
	.set	noreorder
	.set	nomacro
	beq	$6,$9,$L94
	ext	$4,$5,16,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$6,$8,$L94
	srl	$4,$5,24
	.set	macro
	.set	reorder

	ext	$12,$5,8,8
	xor	$6,$6,$7
	andi	$4,$5,0x00ff
	movz	$4,$12,$6
$L94:
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L95
	andi	$5,$4,0xf0
	.set	macro
	.set	reorder

	sra	$5,$5,1
	srl	$3,$3,5
	or	$3,$5,$3
	addiu	$2,$2,1
	.set	noreorder
	.set	nomacro
	j	$L96
	andi	$4,$4,0xf
	.set	macro
	.set	reorder

$L89:
	.set	noreorder
	.set	nomacro
	j	$L96
	srl	$3,$3,4
	.set	macro
	.set	reorder

$L88:
	li	$3,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L95
	li	$16,3			# 0x3
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L196
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

$L96:
	sll	$3,$3,3
	move	$5,$24
	move	$12,$0
$L110:
	sra	$13,$4,$12
	addu	$6,$2,$11
	andi	$13,$13,0x1
	and	$6,$6,$10
	.set	noreorder
	.set	nomacro
	bne	$13,$0,$L98
	andi	$14,$2,0x3
	.set	macro
	.set	reorder

	lw	$13,0($6)
	xor	$18,$14,$7
	ext	$16,$13,8,8
	.set	noreorder
	.set	nomacro
	beq	$14,$9,$L103
	ext	$6,$13,16,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$14,$8,$L103
	srl	$6,$13,24
	.set	macro
	.set	reorder

	andi	$6,$13,0x00ff
	movz	$6,$16,$18
$L103:
	addiu	$2,$2,1
	addu	$13,$2,$11
	sb	$6,0($5)
	and	$6,$13,$10
	lw	$13,0($6)
	andi	$14,$2,0x3
	xor	$18,$14,$7
	ext	$16,$13,8,8
	.set	noreorder
	.set	nomacro
	beq	$14,$9,$L108
	ext	$6,$13,16,8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$14,$8,$L108
	srl	$6,$13,24
	.set	macro
	.set	reorder

	andi	$6,$13,0x00ff
	movz	$6,$16,$18
$L108:
	sb	$6,1($5)
	.set	noreorder
	.set	nomacro
	j	$L109
	addiu	$2,$2,1
	.set	macro
	.set	reorder

$L98:
	sb	$0,0($5)
	sb	$0,1($5)
$L109:
	addiu	$12,$12,1
	.set	noreorder
	.set	nomacro
	bne	$12,$15,$L110
	addiu	$5,$5,2
	.set	macro
	.set	reorder

	addiu	$4,$3,-509
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L111
	addiu	$4,$3,-517
	.set	macro
	.set	reorder

	lbu	$5,36($sp)
	lbu	$4,40($sp)
	lbu	$3,41($sp)
	sb	$5,44($sp)
	lbu	$5,37($sp)
	andi	$4,$4,0x1
	andi	$3,$3,0xf
	sb	$5,45($sp)
	lbu	$5,38($sp)
	sb	$4,47($sp)
	sb	$3,48($sp)
	.set	noreorder
	.set	nomacro
	j	$L112
	sb	$5,46($sp)
	.set	macro
	.set	reorder

$L111:
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L113
	addiu	$4,$3,-525
	.set	macro
	.set	reorder

	lbu	$6,37($sp)
	lbu	$3,38($sp)
	lbu	$5,36($sp)
	lbu	$4,39($sp)
	sll	$6,$6,8
	sll	$3,$3,16
	or	$3,$6,$3
	or	$3,$3,$5
	sll	$4,$4,24
	or	$3,$3,$4
	.set	noreorder
	.set	nomacro
	j	$L112
	sw	$3,52($sp)
	.set	macro
	.set	reorder

$L113:
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L114
	addiu	$4,$3,-533
	.set	macro
	.set	reorder

	lbu	$6,37($sp)
	lbu	$3,38($sp)
	lbu	$5,36($sp)
	lbu	$4,39($sp)
	sll	$6,$6,8
	sll	$3,$3,16
	or	$3,$6,$3
	or	$3,$3,$5
	sll	$4,$4,24
	or	$3,$3,$4
	.set	noreorder
	.set	nomacro
	j	$L112
	sw	$3,56($sp)
	.set	macro
	.set	reorder

$L114:
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L115
	addiu	$4,$3,-541
	.set	macro
	.set	reorder

	lbu	$4,37($sp)
	lbu	$3,39($sp)
	lbu	$6,36($sp)
	lbu	$5,38($sp)
	sll	$4,$4,8
	sll	$3,$3,8
	or	$4,$4,$6
	or	$3,$3,$5
	sh	$4,60($sp)
	.set	noreorder
	.set	nomacro
	j	$L112
	sh	$3,68($sp)
	.set	macro
	.set	reorder

$L115:
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L116
	addiu	$4,$3,-549
	.set	macro
	.set	reorder

	lbu	$3,36($sp)
	.set	noreorder
	.set	nomacro
	j	$L112
	sb	$3,62($sp)
	.set	macro
	.set	reorder

$L116:
	sltu	$4,$4,4
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L117
	addiu	$3,$3,-557
	.set	macro
	.set	reorder

	lbu	$6,37($sp)
	lbu	$3,38($sp)
	lbu	$5,36($sp)
	lbu	$4,39($sp)
	sll	$6,$6,8
	sll	$3,$3,16
	or	$3,$6,$3
	or	$3,$3,$5
	sll	$4,$4,24
	or	$3,$3,$4
	.set	noreorder
	.set	nomacro
	j	$L112
	sw	$3,64($sp)
	.set	macro
	.set	reorder

$L117:
	sltu	$3,$3,4
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L112
	lbu	$6,37($sp)
	.set	macro
	.set	reorder

	lbu	$3,38($sp)
	lbu	$5,36($sp)
	lbu	$4,39($sp)
	sll	$6,$6,8
	sll	$3,$3,16
	or	$3,$6,$3
	or	$3,$3,$5
	sll	$4,$4,24
	or	$3,$3,$4
	sw	$3,72($sp)
$L112:
	sltu	$3,$2,128
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L202
	addu	$3,$2,$11
	.set	macro
	.set	reorder

$L95:
	lbu	$2,44($sp)
	andi	$2,$2,0x10
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L97
	move	$16,$0
	.set	macro
	.set	reorder

	li	$2,-1207959552			# 0xffffffffb8000000
	ori	$2,$2,0x8
	lw	$4,0($2)
	li	$3,-1638400			# 0xffffffffffe70000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	sw	$3,0($2)
	lw	$2,0($2)
	andi	$4,$2,0x4000
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L121
	li	$3,200			# 0xc8
	.set	macro
	.set	reorder

	ext	$4,$2,15,4
	sltu	$5,$4,7
	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L123
	move	$3,$0
	.set	macro
	.set	reorder

	addiu	$3,$4,-7
	andi	$3,$3,0x00ff
$L123:
	li	$4,50			# 0x32
	mul	$3,$3,$4
	addiu	$3,$3,800
$L121:
	ext	$2,$2,19,2
	srl	$3,$3,$2
	li	$4,983040			# 0xf0000
	ori	$4,$4,0x4240
	srl	$3,$3,1
	mul	$3,$3,$4
	lui	$4,%hi(config_sys_mips_timer_fre)
	move	$16,$0
	.set	noreorder
	.set	nomacro
	j	$L97
	sw	$3,%lo(config_sys_mips_timer_fre)($4)
	.set	macro
	.set	reorder

$L82:
	li	$16,1			# 0x1
$L97:
	li	$2,-1207959552			# 0xffffffffb8000000
$L196:
	li	$3,2			# 0x2
	ori	$2,$2,0x4
	sw	$3,0($2)
	lbu	$3,46($sp)
	li	$2,1			# 0x1
	srl	$3,$3,4
	.set	noreorder
	.set	nomacro
	bnel	$3,$2,$L124
	li	$4,11			# 0xb
	.set	macro
	.set	reorder

	li	$4,15			# 0xf
	.set	noreorder
	.set	nomacro
	j	$L184
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

$L124:
	move	$5,$0
$L184:
	.set	noreorder
	.set	nomacro
	jal	SettingCPUClk
	li	$18,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	ori	$3,$18,0x4
	li	$2,2			# 0x2
	sw	$2,0($3)
	.set	noreorder
	.set	nomacro
	beq	$16,$2,$L128
	li	$2,3			# 0x3
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$16,$2,$L129
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$16,$3,$L127
	ori	$2,$18,0x50
	.set	macro
	.set	reorder

	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,553648128			# 0x21000000
	or	$3,$3,$4
	sw	$3,0($2)
	lbu	$2,45($sp)
	andi	$2,$2,0x4
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L178
	lw	$31,92($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L193
	ori	$2,$18,0x10
	.set	macro
	.set	reorder

$L129:
	ori	$18,$18,0x50
	lw	$3,0($18)
	li	$2,16711680			# 0xff0000
	ori	$2,$2,0xffff
	and	$2,$3,$2
	lui	$4,%hi($LC1)
	li	$3,570425344			# 0x22000000
	or	$2,$2,$3
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L189
	li	$5,197			# 0xc5
	.set	macro
	.set	reorder

$L127:
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,805306368			# 0x30000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L188
	li	$5,202			# 0xca
	.set	macro
	.set	reorder

$L128:
	ori	$18,$18,0x50
	lw	$3,0($18)
	li	$2,16711680			# 0xff0000
	ori	$2,$2,0xffff
	and	$2,$3,$2
	lui	$4,%hi($LC1)
	li	$3,822083584			# 0x31000000
	or	$2,$2,$3
	addiu	$4,$4,%lo($LC1)
	li	$5,207			# 0xcf
$L189:
	sw	$2,0($18)
	j	$L186
$L193:
	lw	$3,0($2)
	li	$4,10			# 0xa
	li	$16,-1196425216			# 0xffffffffb8b00000
	ori	$3,$3,0x7000
	sw	$3,0($2)
	jal	mdelay
	ori	$2,$16,0x100c
	li	$3,256			# 0x100
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	jal	mdelay
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	ori	$2,$18,0x100
	li	$3,8			# 0x8
	sw	$3,0($2)
	li	$3,9			# 0x9
	sw	$3,0($2)
	li	$3,11			# 0xb
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	jal	mdelay
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	T.44
	ori	$18,$18,0x8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	mdelay
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	lw	$2,0($18)
	ext	$2,$2,24,1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L132
	ori	$16,$16,0x1000
	.set	macro
	.set	reorder

	li	$2,308281344			# 0x12600000
	ori	$2,$2,0xf01
	sw	$2,0($16)
	sw	$0,24($sp)
	j	$L133
$L134:
	lw	$2,24($sp)
	addiu	$2,$2,1
	sw	$2,24($sp)
$L133:
	lw	$2,24($sp)
	slt	$2,$2,5555
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L134
	li	$3,7405568			# 0x710000
	.set	macro
	.set	reorder

	li	$2,-1196425216			# 0xffffffffb8b00000
	ori	$3,$3,0x1
	ori	$2,$2,0x1000
	sw	$3,0($2)
	sw	$0,24($sp)
	j	$L135
$L136:
	lw	$2,24($sp)
	addiu	$2,$2,1
	sw	$2,24($sp)
$L135:
	lw	$2,24($sp)
	slt	$2,$2,5555
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L136
	li	$3,448856064			# 0x1ac10000
	.set	macro
	.set	reorder

	li	$2,-1196425216			# 0xffffffffb8b00000
	ori	$3,$3,0x601
	ori	$2,$2,0x1000
	sw	$3,0($2)
	sw	$0,24($sp)
	j	$L137
$L138:
	lw	$2,24($sp)
	addiu	$2,$2,1
	sw	$2,24($sp)
$L137:
	lw	$2,24($sp)
	slt	$2,$2,5555
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L138
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	j	$L197
$L132:
	li	$2,7405568			# 0x710000
	ori	$2,$2,0x1
	sw	$2,0($16)
	sw	$0,24($sp)
	j	$L140
$L141:
	lw	$2,24($sp)
	addiu	$2,$2,1
	sw	$2,24($sp)
$L140:
	lw	$2,24($sp)
	slt	$2,$2,5555
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L141
	li	$3,415301632			# 0x18c10000
	.set	macro
	.set	reorder

	li	$2,-1196425216			# 0xffffffffb8b00000
	ori	$3,$3,0x601
	ori	$2,$2,0x1000
	sw	$3,0($2)
	sw	$0,24($sp)
	j	$L142
$L143:
	lw	$2,24($sp)
	addiu	$2,$2,1
	sw	$2,24($sp)
$L142:
	lw	$2,24($sp)
	slt	$2,$2,5555
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L143
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

$L197:
	.set	noreorder
	.set	nomacro
	jal	mdelay
	li	$16,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	T.44
	ori	$16,$16,0x50
	.set	macro
	.set	reorder

	lw	$18,0($16)
	li	$2,-3			# 0xfffffffffffffffd
	li	$4,300			# 0x12c
	and	$18,$18,$2
	sw	$18,0($16)
	.set	noreorder
	.set	nomacro
	jal	mdelay
	ori	$18,$18,0x2
	.set	macro
	.set	reorder

	sw	$18,0($16)
	.set	noreorder
	.set	nomacro
	jal	mdelay
	li	$4,100			# 0x64
	.set	macro
	.set	reorder

	li	$2,10			# 0xa
	li	$4,10			# 0xa
	li	$18,-1196425216			# 0xffffffffb8b00000
	sw	$2,24($sp)
	.set	noreorder
	.set	nomacro
	jal	mdelay
	ori	$18,$18,0x728
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L144
	li	$16,17			# 0x11
	.set	macro
	.set	reorder

$L146:
	jal	mdelay
	lw	$2,0($18)
	andi	$2,$2,0x1f
	beq	$2,$16,$L145
$L144:
	lw	$2,24($sp)
	li	$4,10			# 0xa
	addiu	$2,$2,-1
	sw	$2,24($sp)
	lw	$2,24($sp)
	bne	$2,$0,$L146
$L145:
	lw	$3,24($sp)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L148
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	li	$7,1048576			# 0x100000
	li	$6,-1196425216			# 0xffffffffb8b00000
	ori	$6,$6,0x4
	ori	$7,$7,0x7
	li	$2,-1196359680			# 0xffffffffb8b10000
	sw	$7,0($6)
	li	$6,1572864			# 0x180000
	ori	$5,$2,0x4
	ori	$6,$6,0x7
	sw	$6,0($5)
	li	$5,415236096			# 0x18c00000
	ori	$4,$2,0x10
	ori	$5,$5,0x1
	sw	$5,0($4)
	li	$4,419430400			# 0x19000000
	ori	$3,$2,0x18
	ori	$4,$4,0x4
	sw	$4,0($3)
	lw	$17,0($2)
	move	$2,$0
$L148:
	lbu	$4,47($sp)
	li	$3,1			# 0x1
	bne	$4,$3,$L149
	.set	noreorder
	.set	nomacro
	beq	$2,$4,$L151
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$4,$4,$3
	li	$5,587202560			# 0x23000000
	or	$4,$4,$5
	sw	$4,0($2)
	li	$4,-1205731328			# 0xffffffffb8220000
	ori	$4,$4,0x10ec
	.set	noreorder
	.set	nomacro
	beql	$17,$4,$L203
	li	$3,-1205731328			# 0xffffffffb8220000
	.set	macro
	.set	reorder

	lw	$4,0($2)
	li	$5,242			# 0xf2
	and	$3,$4,$3
	li	$4,855638016			# 0x33000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	.set	noreorder
	.set	nomacro
	j	$L187
	addiu	$4,$4,%lo($LC1)
	.set	macro
	.set	reorder

$L151:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,838860800			# 0x32000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L187
	li	$5,249			# 0xf9
	.set	macro
	.set	reorder

$L149:
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L155
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,587202560			# 0x23000000
	or	$3,$3,$4
	sw	$3,0($2)
	li	$2,-1205731328			# 0xffffffffb8220000
	ori	$2,$2,0x10ec
	.set	noreorder
	.set	nomacro
	beq	$17,$2,$L152
	li	$3,-1205731328			# 0xffffffffb8220000
	.set	macro
	.set	reorder

	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L186
	li	$5,272			# 0x110
	.set	macro
	.set	reorder

$L155:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,838860800			# 0x32000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L188
	li	$5,279			# 0x117
	.set	macro
	.set	reorder

$L152:
$L203:
	ori	$3,$3,0x10ec
	sb	$0,28($sp)
	sb	$0,29($sp)
	sb	$0,30($sp)
	sb	$0,31($sp)
	sb	$0,32($sp)
	.set	noreorder
	.set	nomacro
	bne	$17,$3,$L158
	li	$2,3			# 0x3
	.set	macro
	.set	reorder

	li	$2,-1191182336			# 0xffffffffb9000000
	ori	$2,$2,0x35
	lbu	$3,0($2)
	andi	$3,$3,0x00ff
	andi	$4,$3,0x3
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L204
	li	$4,1008			# 0x3f0
	.set	macro
	.set	reorder

	andi	$3,$3,0xfc
	sb	$3,0($2)
	lbu	$3,0($2)
	andi	$3,$3,0x3
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L158
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	li	$4,1008			# 0x3f0
$L204:
	li	$5,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	r02
	addiu	$6,$sp,24
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L205
	lbu	$4,47($sp)
	.set	macro
	.set	reorder

	lbu	$3,24($sp)
	li	$2,1			# 0x1
	srl	$3,$3,7
	.set	noreorder
	.set	nomacro
	bnel	$3,$2,$L160
	sb	$2,28($sp)
	.set	macro
	.set	reorder

	sb	$0,28($sp)
$L160:
	li	$4,932			# 0x3a4
	li	$5,4			# 0x4
	.set	noreorder
	.set	nomacro
	jal	r02
	addiu	$6,$sp,29
	.set	macro
	.set	reorder

$L158:
	lbu	$4,47($sp)
$L205:
	li	$5,1			# 0x1
	bne	$4,$5,$L162
	.set	noreorder
	.set	nomacro
	beq	$2,$4,$L165
	slt	$3,$2,2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L168
	li	$3,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L164
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L198
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

$L168:
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L166
	li	$3,3			# 0x3
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bnel	$2,$3,$L163
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L194
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

$L164:
	ori	$2,$2,0x50
	lw	$5,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$5,$5,$3
	li	$6,603979776			# 0x24000000
	or	$5,$5,$6
	sw	$5,0($2)
	lbu	$5,28($sp)
	bne	$5,$4,$L169
	lw	$4,0($2)
	and	$3,$4,$3
	li	$4,620756992			# 0x25000000
	or	$3,$3,$4
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	j	$L199
	lui	$4,%hi($LC2)
	.set	macro
	.set	reorder

$L169:
	lw	$4,0($2)
	and	$3,$4,$3
	li	$4,620756992			# 0x25000000
	or	$3,$3,$4
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	j	$L200
	lw	$31,92($sp)
	.set	macro
	.set	reorder

$L165:
	li	$2,-1207959552			# 0xffffffffb8000000
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,872415232			# 0x34000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L187
	li	$5,322			# 0x142
	.set	macro
	.set	reorder

$L166:
	li	$2,-1207959552			# 0xffffffffb8000000
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,889192448			# 0x35000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L187
	li	$5,328			# 0x148
	.set	macro
	.set	reorder

$L194:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,855638016			# 0x33000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L187
	li	$5,334			# 0x14e
	.set	macro
	.set	reorder

$L163:
$L198:
	addiu	$4,$4,%lo($LC1)
	li	$5,339			# 0x153
$L185:
	jal	_dprintf
	.set	noreorder
	.set	nomacro
	j	$L153
	lui	$4,%hi($LC2)
	.set	macro
	.set	reorder

$L162:
	.set	noreorder
	.set	nomacro
	beql	$2,$5,$L172
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	slt	$3,$2,2
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L175
	li	$3,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L171
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L201
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

$L175:
	.set	noreorder
	.set	nomacro
	beql	$2,$3,$L173
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

	li	$3,3			# 0x3
	.set	noreorder
	.set	nomacro
	bnel	$2,$3,$L170
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L195
	li	$2,-1207959552			# 0xffffffffb8000000
	.set	macro
	.set	reorder

$L171:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	li	$6,603979776			# 0x24000000
	and	$4,$4,$3
	or	$4,$4,$6
	sw	$4,0($2)
	lbu	$6,28($sp)
	.set	noreorder
	.set	nomacro
	bne	$6,$5,$L176
	lui	$4,%hi($LC1)
	.set	macro
	.set	reorder

	lw	$5,0($2)
	addiu	$4,$4,%lo($LC1)
	and	$3,$5,$3
	li	$5,855638016			# 0x33000000
	or	$3,$3,$5
	li	$5,353			# 0x161
$L187:
	sw	$3,0($2)
	j	$L185
$L176:
	lw	$5,0($2)
	addiu	$4,$4,%lo($LC1)
	and	$3,$5,$3
	li	$5,620756992			# 0x25000000
	or	$3,$3,$5
	.set	noreorder
	.set	nomacro
	j	$L188
	li	$5,358			# 0x166
	.set	macro
	.set	reorder

$L172:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,872415232			# 0x34000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L188
	li	$5,365			# 0x16d
	.set	macro
	.set	reorder

$L173:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,889192448			# 0x35000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	.set	noreorder
	.set	nomacro
	j	$L188
	li	$5,370			# 0x172
	.set	macro
	.set	reorder

$L195:
	ori	$2,$2,0x50
	lw	$4,0($2)
	li	$3,16711680			# 0xff0000
	ori	$3,$3,0xffff
	and	$3,$4,$3
	li	$4,855638016			# 0x33000000
	or	$3,$3,$4
	lui	$4,%hi($LC1)
	addiu	$4,$4,%lo($LC1)
	li	$5,375			# 0x177
$L188:
	sw	$3,0($2)
	j	$L186
$L170:
$L201:
	addiu	$4,$4,%lo($LC1)
	li	$5,379			# 0x17b
$L186:
	jal	_dprintf
	.set	noreorder
	.set	nomacro
	j	$L200
	lw	$31,92($sp)
	.set	macro
	.set	reorder

$L153:
$L199:
	.set	noreorder
	.set	nomacro
	jal	_dprintf
	addiu	$4,$4,%lo($LC2)
	.set	macro
	.set	reorder

$L177:
	j	$L177
$L178:
$L200:
	lw	$18,88($sp)
	lw	$17,84($sp)
	lw	$16,80($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,96
	.set	macro
	.set	reorder

	.end	adj_cpu_freq
	.size	adj_cpu_freq, .-adj_cpu_freq

	.comm	config_sys_mips_timer_fre,4,4
	.ident	"GCC: (Realtek MSDK-4.4.7 Build 2001) 4.4.7"
