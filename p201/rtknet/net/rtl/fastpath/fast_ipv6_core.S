	.file	1 "fast_ipv6_core.c"
	.section .mdebug.abi32
	.previous
	.gnu_attribute 4, 3
	.text
	.align	2
	.globl	rtk_flushV6Connection
	.set	nomips16
	.ent	rtk_flushV6Connection
	.type	rtk_flushV6Connection, @function
rtk_flushV6Connection:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(v6_path_table_list_max)
	lw	$11,%lo(v6_path_table_list_max)($2)
	beq	$11,$0,$L18
	lui	$5,%hi(v6_path_list_inuse)

	lui	$3,%hi(v6_path_list_free)
	addiu	$5,$5,%lo(v6_path_list_inuse)
	addiu	$3,$3,%lo(v6_path_list_free)
	move	$8,$0
	move	$10,$0
	lui	$9,%hi(v6_table_path)
$L9:
	lw	$2,%lo(v6_table_path)($9)
	lw	$2,0($2)
	addu	$2,$2,$8
	lw	$2,0($2)
	bne	$2,$0,$L8
	nop

	j	$L17
	addiu	$10,$10,1

$L15:
	lw	$6,60($2)
	sw	$6,60($4)
	lw	$4,60($2)
	lw	$6,56($2)
	sw	$6,0($4)
	lw	$4,%lo(v6_table_path)($9)
	lw	$4,0($4)
	addu	$4,$4,$8
	lw	$6,8($4)
	addiu	$6,$6,-1
	sw	$6,8($4)
	lw	$4,64($2)
	beq	$4,$0,$L6
	nop

$L16:
	lw	$6,68($2)
	sw	$6,68($4)
$L7:
	lw	$4,68($2)
	lw	$7,64($2)
	addiu	$6,$2,64
	sw	$7,0($4)
	lw	$4,8($5)
	addiu	$4,$4,-1
	sw	$4,8($5)
	sw	$0,64($2)
	lw	$4,4($3)
	sw	$4,68($2)
	lw	$4,4($3)
	sw	$2,0($4)
	lw	$4,8($3)
	sw	$6,4($3)
	addiu	$4,$4,1
	sw	$4,8($3)
	lw	$2,56($2)
	beq	$2,$0,$L3
	nop

$L8:
	lw	$4,56($2)
	bne	$4,$0,$L15
	nop

	lw	$4,%lo(v6_table_path)($9)
	lw	$6,60($2)
	lw	$4,0($4)
	addu	$4,$4,$8
	sw	$6,4($4)
	lw	$4,60($2)
	lw	$6,56($2)
	sw	$6,0($4)
	lw	$4,%lo(v6_table_path)($9)
	lw	$4,0($4)
	addu	$4,$4,$8
	lw	$6,8($4)
	addiu	$6,$6,-1
	sw	$6,8($4)
	lw	$4,64($2)
	bne	$4,$0,$L16
	nop

$L6:
	lw	$4,68($2)
	j	$L7
	sw	$4,4($5)

$L3:
	addiu	$10,$10,1
$L17:
	sltu	$2,$10,$11
	bne	$2,$0,$L9
	addiu	$8,$8,12

$L18:
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	rtk_flushV6Connection
	.size	rtk_flushV6Connection, .-rtk_flushV6Connection
	.align	2
	.set	nomips16
	.ent	V6_cache_timeout
	.type	V6_cache_timeout, @function
V6_cache_timeout:
	.frame	$sp,32,$31		# vars= 32, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$2,48($4)
	beq	$2,$0,$L23
	addiu	$sp,$sp,-32

	lw	$10,4($4)
	lw	$9,8($4)
	lw	$8,12($4)
	lw	$7,16($4)
	lhu	$11,36($4)
	sw	$10,16($sp)
	sw	$9,20($sp)
	sw	$8,24($sp)
	sw	$7,28($sp)
	lw	$6,20($4)
	xor	$12,$9,$10
	lw	$5,24($4)
	xor	$12,$12,$8
	lw	$3,28($4)
	xor	$12,$12,$7
	lw	$2,32($4)
	xor	$12,$12,$6
	xor	$12,$12,$5
	xor	$12,$12,$3
	xor	$12,$12,$2
	srl	$10,$10,8
	xor	$10,$12,$10
	srl	$9,$9,8
	xor	$9,$10,$9
	srl	$8,$8,8
	xor	$8,$9,$8
	srl	$7,$7,8
	srl	$12,$6,16
	xor	$7,$8,$7
	xor	$7,$7,$12
	lw	$10,0($4)
	srl	$12,$5,16
	sw	$3,8($sp)
	srl	$9,$3,16
	xor	$7,$7,$12
	lui	$3,%hi(V6_max_udp_frag_entry)
	sw	$6,0($sp)
	sw	$2,12($sp)
	sw	$5,4($sp)
	lw	$3,%lo(V6_max_udp_frag_entry)($3)
	xor	$7,$7,$9
	srl	$2,$2,16
	xor	$2,$7,$2
	xor	$6,$11,$10
	lw	$5,80($4)
	xor	$6,$6,$2
	srl	$2,$2,16
	xor	$2,$6,$2
	addiu	$3,$3,-1
	and	$2,$2,$3
	beq	$5,$0,$L21
	sb	$0,48($4)

	lw	$6,84($4)
	sll	$3,$2,4
	sll	$2,$2,2
	sw	$6,84($5)
	subu	$3,$3,$2
	lui	$5,%hi(V6_udp_cache_table)
$L22:
	lw	$6,84($4)
	lw	$7,80($4)
	lui	$2,%hi(V6_udp_cache_list_free)
	addiu	$2,$2,%lo(V6_udp_cache_list_free)
	sw	$7,0($6)
	lw	$6,%lo(V6_udp_cache_table)($5)
	addiu	$5,$4,88
	lw	$6,0($6)
	addu	$3,$6,$3
	lw	$6,8($3)
	addiu	$6,$6,-1
	sw	$6,8($3)
	sw	$0,88($4)
	lw	$3,4($2)
	sw	$3,92($4)
	lw	$3,4($2)
	sw	$4,0($3)
	lw	$3,8($2)
	sw	$5,4($2)
	addiu	$3,$3,1
	sw	$3,8($2)
$L23:
	addiu	$sp,$sp,32
	j	$31
	nop

$L21:
	lui	$5,%hi(V6_udp_cache_table)
	lw	$6,%lo(V6_udp_cache_table)($5)
	sll	$3,$2,4
	sll	$2,$2,2
	lw	$7,0($6)
	lw	$6,84($4)
	subu	$3,$3,$2
	addu	$2,$7,$3
	j	$L22
	sw	$6,4($2)

	.set	macro
	.set	reorder
	.end	V6_cache_timeout
	.size	V6_cache_timeout, .-V6_cache_timeout
	.align	2
	.set	nomips16
	.ent	ipv6_fast_forward_single_write
	.type	ipv6_fast_forward_single_write, @function
ipv6_fast_forward_single_write:
	.frame	$sp,32,$31		# vars= 8, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	sw	$31,28($sp)
	sw	$16,24($sp)
	sltu	$2,$6,2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L29
	move	$16,$6
	.set	macro
	.set	reorder

$L25:
	li	$2,-14			# 0xfffffffffffffff2
$L27:
	lw	$31,28($sp)
	lw	$16,24($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L29:
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L27
	li	$2,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addiu	$2,$5,1
	or	$3,$2,$5
	lw	$2,24($28)
	and	$3,$3,$2
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L25
	addiu	$4,$sp,16
	.set	macro
	.set	reorder

	li	$6,1			# 0x1
 #APP
 # 1203 "net/rtl/fastpath/fast_ipv6_core.c" 1
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
 # 0 "" 2
 #NO_APP
	.set	noreorder
	.set	nomacro
	bne	$6,$0,$L25
	lb	$2,16($sp)
	.set	macro
	.set	reorder

	lui	$3,%hi(fast_ipv6_fw)
	addiu	$2,$2,-48
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L30
	sw	$2,%lo(fast_ipv6_fw)($3)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L27
	move	$2,$16
	.set	macro
	.set	reorder

$L30:
	jal	rtk_flushV6Connection
	.set	noreorder
	.set	nomacro
	j	$L27
	move	$2,$16
	.set	macro
	.set	reorder

	.end	ipv6_fast_forward_single_write
	.size	ipv6_fast_forward_single_write, .-ipv6_fast_forward_single_write
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC0:
	.ascii	"ipv6_fast_forward\000"
	.section	.exit.text,"ax",@progbits
	.align	2
	.globl	ipv6_fast_forward_exit
	.set	nomips16
	.ent	ipv6_fast_forward_exit
	.type	ipv6_fast_forward_exit, @function
ipv6_fast_forward_exit:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,20($sp)
	lui	$2,%hi(ipv6_res)
	lw	$2,%lo(ipv6_res)($2)
	beq	$2,$0,$L32
	lui	$4,%hi($LC0)

	lui	$5,%hi(proc_root)
	addiu	$4,$4,%lo($LC0)
	jal	remove_proc_entry
	addiu	$5,$5,%lo(proc_root)

$L32:
	lw	$31,20($sp)
	lui	$2,%hi(fast_ipv6_fw)
	sw	$0,%lo(fast_ipv6_fw)($2)
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	ipv6_fast_forward_exit
	.size	ipv6_fast_forward_exit, .-ipv6_fast_forward_exit
	.section	.init.text,"ax",@progbits
	.align	2
	.globl	ipv6_fast_forward_init
	.set	nomips16
	.ent	ipv6_fast_forward_init
	.type	ipv6_fast_forward_init, @function
ipv6_fast_forward_init:
	.frame	$sp,32,$31		# vars= 0, regs= 1/0, args= 24, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	sw	$31,28($sp)
	lui	$4,%hi($LC0)
	lui	$6,%hi(proc_root)
	lui	$7,%hi(ipv6_fast_forward_proc_fops)
	addiu	$4,$4,%lo($LC0)
	addiu	$6,$6,%lo(proc_root)
	addiu	$7,$7,%lo(ipv6_fast_forward_proc_fops)
	move	$5,$0
	jal	proc_create_data
	sw	$0,16($sp)

	lw	$31,28($sp)
	lui	$3,%hi(ipv6_res)
	sw	$2,%lo(ipv6_res)($3)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	ipv6_fast_forward_init
	.size	ipv6_fast_forward_init, .-ipv6_fast_forward_init
	.text
	.align	2
	.globl	ipv6_fast_forward_single_open
	.set	nomips16
	.ent	ipv6_fast_forward_single_open
	.type	ipv6_fast_forward_single_open, @function
ipv6_fast_forward_single_open:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	move	$4,$5
	lui	$5,%hi(ipv6_forward_read_proc)
	addiu	$5,$5,%lo(ipv6_forward_read_proc)
	move	$6,$0
	j	single_open
	nop

	.set	macro
	.set	reorder
	.end	ipv6_fast_forward_single_open
	.size	ipv6_fast_forward_single_open, .-ipv6_fast_forward_single_open
	.section	.rodata.str1.4
	.align	2
$LC1:
	.ascii	"%c\012\000"
	.text
	.align	2
	.set	nomips16
	.ent	ipv6_forward_read_proc
	.type	ipv6_forward_read_proc, @function
ipv6_forward_read_proc:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,20($sp)
	lui	$2,%hi(fast_ipv6_fw)
	lw	$6,%lo(fast_ipv6_fw)($2)
	lui	$5,%hi($LC1)
	addiu	$5,$5,%lo($LC1)
	jal	seq_printf
	addiu	$6,$6,48

	lw	$31,20($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	ipv6_forward_read_proc
	.size	ipv6_forward_read_proc, .-ipv6_forward_read_proc
	.align	2
	.globl	init_V6_table_path
	.set	nomips16
	.ent	init_V6_table_path
	.type	init_V6_table_path, @function
init_V6_table_path:
	.frame	$sp,48,$31		# vars= 0, regs= 7/0, args= 16, gp= 0
	.mask	0x803f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-48
	sw	$31,44($sp)
	sw	$21,40($sp)
	sw	$20,36($sp)
	sw	$19,32($sp)
	sw	$18,28($sp)
	sw	$17,24($sp)
	sw	$16,20($sp)
	lui	$20,%hi(kmalloc_caches)
	addiu	$20,$20,%lo(kmalloc_caches)
	move	$18,$4
	lw	$4,28($20)
	move	$19,$5
	jal	kmem_cache_alloc
	li	$5,32800			# 0x8020

	lui	$17,%hi(v6_table_path)
	move	$21,$2
	beq	$2,$0,$L41
	sw	$2,%lo(v6_table_path)($17)

	lui	$6,%hi(v6_path_list_inuse)
	sll	$2,$18,2
	sll	$4,$18,4
	lui	$3,%hi(v6_path_list_free)
	subu	$4,$4,$2
	addiu	$2,$6,%lo(v6_path_list_inuse)
	addiu	$16,$3,%lo(v6_path_list_free)
	sw	$0,%lo(v6_path_list_free)($3)
	li	$5,32			# 0x20
	lui	$3,%hi(v6_path_table_list_max)
	sw	$2,4($2)
	sw	$0,8($2)
	sw	$0,%lo(v6_path_list_inuse)($6)
	sw	$18,%lo(v6_path_table_list_max)($3)
	sw	$0,8($16)
	jal	__kmalloc
	sw	$16,4($16)

	sw	$2,0($21)
	lw	$2,%lo(v6_table_path)($17)
	lw	$4,0($2)
	beq	$4,$0,$L41
	nop

	blez	$18,$L42
	move	$2,$0

	move	$3,$0
	j	$L43
	move	$5,$17

$L50:
	lw	$4,%lo(v6_table_path)($5)
	lw	$4,0($4)
$L43:
	addu	$4,$4,$2
	sw	$0,8($4)
	lw	$4,%lo(v6_table_path)($17)
	addiu	$3,$3,1
	lw	$4,0($4)
	addu	$4,$4,$2
	sw	$0,0($4)
	lw	$4,%lo(v6_table_path)($17)
	lw	$4,0($4)
	addu	$4,$4,$2
	sw	$4,4($4)
	bne	$3,$18,$L50
	addiu	$2,$2,12

$L42:
	blez	$19,$L44
	move	$17,$0

	j	$L51
	lw	$4,28($20)

$L45:
	sw	$0,64($2)
	lw	$5,4($16)
	sw	$5,68($2)
	lw	$5,4($16)
	sw	$2,0($5)
	lw	$2,8($16)
	sw	$4,4($16)
	addiu	$2,$2,1
	beq	$3,$0,$L44
	sw	$2,8($16)

	lw	$4,28($20)
$L51:
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	addiu	$17,$17,1

	addiu	$4,$2,64
	bne	$2,$0,$L45
	slt	$3,$17,$19

	li	$2,-2			# 0xfffffffffffffffe
$L46:
	lw	$31,44($sp)
	lw	$21,40($sp)
	lw	$20,36($sp)
	lw	$19,32($sp)
	lw	$18,28($sp)
	lw	$17,24($sp)
	lw	$16,20($sp)
	j	$31
	addiu	$sp,$sp,48

$L44:
	j	$L46
	move	$2,$0

$L41:
	j	$L46
	li	$2,-1			# 0xffffffffffffffff

	.set	macro
	.set	reorder
	.end	init_V6_table_path
	.size	init_V6_table_path, .-init_V6_table_path
	.align	2
	.globl	rtk_idleV6Connection
	.set	nomips16
	.ent	rtk_idleV6Connection
	.type	rtk_idleV6Connection, @function
rtk_idleV6Connection:
	.frame	$sp,120,$31		# vars= 64, regs= 9/0, args= 16, gp= 0
	.mask	0x80ff0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-120
	sw	$31,116($sp)
	sw	$23,112($sp)
	sw	$22,108($sp)
	sw	$21,104($sp)
	sw	$20,100($sp)
	sw	$19,96($sp)
	sw	$18,92($sp)
	sw	$17,88($sp)
	sw	$16,84($sp)
	lw	$9,0($4)
	lw	$3,40($4)
	lw	$8,4($4)
	lw	$7,8($4)
	move	$17,$4
	xor	$14,$9,$3
	lw	$4,12($4)
	lw	$13,16($17)
	xor	$14,$14,$8
	lw	$12,20($17)
	xor	$14,$14,$7
	lw	$11,24($17)
	xor	$14,$14,$4
	lw	$10,28($17)
	xor	$14,$14,$13
	xor	$14,$14,$12
	xor	$14,$14,$11
	srl	$2,$9,8
	xor	$14,$14,$10
	xor	$14,$14,$2
	srl	$2,$8,8
	xor	$14,$14,$2
	srl	$2,$7,8
	xor	$14,$14,$2
	srl	$2,$4,8
	xor	$14,$14,$2
	srl	$2,$13,16
	xor	$14,$14,$2
	srl	$15,$12,16
	lw	$2,36($17)
	xor	$14,$14,$15
	srl	$15,$11,16
	lhu	$24,32($17)
	xor	$14,$14,$15
	srl	$15,$10,16
	xor	$14,$14,$15
	lui	$18,%hi(v6_path_table_list_max)
	srl	$15,$2,4
	xor	$14,$14,$15
	lui	$19,%hi(v6_table_path)
	lw	$15,%lo(v6_path_table_list_max)($18)
	xor	$14,$14,$24
	lw	$16,%lo(v6_table_path)($19)
	srl	$25,$14,12
	xor	$25,$25,$14
	sw	$9,16($sp)
	sw	$8,20($sp)
	sw	$7,24($sp)
	sw	$4,28($sp)
	sw	$13,32($sp)
	sw	$12,36($sp)
	sw	$11,40($sp)
	sw	$10,44($sp)
	addiu	$15,$15,-1
	and	$25,$25,$15
	lw	$14,0($16)
	sll	$16,$25,4
	sll	$25,$25,2
	subu	$25,$16,$25
	addu	$25,$14,$25
	lw	$16,0($25)
	move	$22,$5
	lui	$5,%hi(jiffies)
	move	$21,$6
	lw	$23,%lo(jiffies)($5)
	move	$6,$3
	beq	$16,$0,$L53
	move	$5,$2

	j	$L58
	addiu	$20,$17,16

$L54:
	lw	$16,56($16)
	beq	$16,$0,$L72
	lw	$4,%lo(v6_table_path)($19)

$L58:
	lw	$4,36($16)
	bne	$4,$2,$L54
	nop

	lw	$4,40($16)
	bne	$4,$3,$L54
	move	$4,$16

	move	$5,$17
	jal	memcmp
	li	$6,16			# 0x10

	beq	$2,$0,$L66
	addiu	$4,$16,16

$L69:
	lw	$16,56($16)
	lw	$2,36($17)
	bne	$16,$0,$L58
	lw	$3,40($17)

	lw	$4,%lo(v6_table_path)($19)
$L72:
	lw	$15,%lo(v6_path_table_list_max)($18)
	lhu	$24,32($17)
	lw	$14,0($4)
	lw	$9,0($17)
	lw	$8,4($17)
	lw	$7,8($17)
	lw	$4,12($17)
	lw	$13,16($17)
	lw	$12,20($17)
	lw	$11,24($17)
	lw	$10,28($17)
	move	$6,$3
	move	$5,$2
	addiu	$15,$15,-1
$L53:
	xor	$2,$12,$13
	xor	$2,$2,$11
	xor	$2,$2,$10
	xor	$2,$2,$9
	xor	$2,$2,$8
	xor	$2,$2,$7
	srl	$3,$13,8
	xor	$2,$2,$4
	xor	$2,$2,$3
	srl	$3,$12,8
	xor	$2,$2,$3
	srl	$3,$11,8
	xor	$2,$2,$3
	srl	$3,$10,8
	xor	$2,$2,$3
	srl	$3,$9,16
	xor	$2,$2,$3
	srl	$3,$8,16
	xor	$2,$2,$3
	srl	$3,$7,16
	xor	$2,$2,$3
	srl	$3,$4,16
	xor	$2,$2,$3
	xor	$2,$2,$5
	xor	$24,$2,$24
	srl	$6,$6,4
	xor	$24,$24,$6
	srl	$2,$24,12
	xor	$24,$2,$24
	and	$15,$24,$15
	sll	$2,$15,4
	sll	$15,$15,2
	subu	$15,$2,$15
	addu	$14,$14,$15
	sw	$13,48($sp)
	sw	$12,52($sp)
	sw	$11,56($sp)
	sw	$10,60($sp)
	sw	$9,64($sp)
	sw	$8,68($sp)
	sw	$7,72($sp)
	sw	$4,76($sp)
	lw	$16,0($14)
	beq	$16,$0,$L59
	addiu	$18,$17,16

	j	$L73
	lw	$2,36($16)

$L60:
	lw	$16,56($16)
	beq	$16,$0,$L56
	move	$2,$0

	lw	$5,36($17)
	lw	$2,36($16)
$L73:
	bne	$2,$5,$L60
	nop

	lw	$3,40($16)
	lw	$2,40($17)
	bne	$3,$2,$L60
	move	$4,$16

	move	$5,$17
	jal	memcmp
	li	$6,16			# 0x10

	bne	$2,$0,$L60
	addiu	$4,$16,16

	move	$5,$18
	jal	memcmp
	li	$6,16			# 0x10

	bne	$2,$0,$L60
	nop

	lw	$3,32($16)
	lw	$2,32($17)
	bne	$3,$2,$L60
	nop

	lw	$2,44($16)
	subu	$22,$23,$22
	subu	$22,$22,$2
	bgez	$22,$L59
	nop

$L70:
	sw	$2,0($21)
	j	$L56
	li	$2,-1			# 0xffffffffffffffff

$L59:
	move	$2,$0
$L56:
	lw	$31,116($sp)
	lw	$23,112($sp)
	lw	$22,108($sp)
	lw	$21,104($sp)
	lw	$20,100($sp)
	lw	$19,96($sp)
	lw	$18,92($sp)
	lw	$17,88($sp)
	lw	$16,84($sp)
	j	$31
	addiu	$sp,$sp,120

$L66:
	move	$5,$20
	jal	memcmp
	li	$6,16			# 0x10

	bne	$2,$0,$L69
	nop

	lw	$24,32($16)
	lw	$2,32($17)
	bne	$24,$2,$L69
	subu	$3,$23,$22

	lw	$2,44($16)
	subu	$3,$3,$2
	bltz	$3,$L70
	lw	$15,%lo(v6_path_table_list_max)($18)

	lw	$2,%lo(v6_table_path)($19)
	andi	$24,$24,0xffff
	lw	$14,0($2)
	addiu	$15,$15,-1
	lw	$6,40($17)
	lw	$5,36($17)
	lw	$9,0($17)
	lw	$8,4($17)
	lw	$7,8($17)
	lw	$4,12($17)
	lw	$13,16($17)
	lw	$12,20($17)
	lw	$11,24($17)
	j	$L53
	lw	$10,28($17)

	.set	macro
	.set	reorder
	.end	rtk_idleV6Connection
	.size	rtk_idleV6Connection, .-rtk_idleV6Connection
	.align	2
	.globl	rtk_delV6Connection
	.set	nomips16
	.ent	rtk_delV6Connection
	.type	rtk_delV6Connection, @function
rtk_delV6Connection:
	.frame	$sp,80,$31		# vars= 32, regs= 8/0, args= 16, gp= 0
	.mask	0x807f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-80
	sw	$31,76($sp)
	sw	$22,72($sp)
	sw	$21,68($sp)
	sw	$20,64($sp)
	sw	$19,60($sp)
	sw	$18,56($sp)
	sw	$17,52($sp)
	sw	$16,48($sp)
	lw	$10,0($4)
	lw	$11,40($4)
	lw	$9,4($4)
	lw	$8,8($4)
	lw	$7,12($4)
	xor	$11,$10,$11
	lw	$6,16($4)
	xor	$11,$11,$9
	lw	$5,20($4)
	xor	$11,$11,$8
	move	$17,$4
	xor	$11,$11,$7
	lw	$4,24($4)
	lw	$3,28($17)
	xor	$11,$11,$6
	xor	$11,$11,$5
	xor	$11,$11,$4
	xor	$11,$11,$3
	srl	$2,$10,8
	xor	$11,$11,$2
	srl	$2,$9,8
	xor	$11,$11,$2
	srl	$2,$8,8
	xor	$11,$11,$2
	srl	$2,$7,8
	xor	$11,$11,$2
	srl	$2,$6,16
	xor	$11,$11,$2
	srl	$12,$5,16
	lw	$2,36($17)
	xor	$11,$11,$12
	srl	$12,$4,16
	srl	$13,$3,16
	xor	$11,$11,$12
	xor	$11,$11,$13
	lhu	$12,32($17)
	srl	$13,$2,4
	xor	$11,$11,$13
	lui	$13,%hi(v6_path_table_list_max)
	lw	$13,%lo(v6_path_table_list_max)($13)
	lui	$19,%hi(v6_table_path)
	xor	$11,$11,$12
	lw	$12,%lo(v6_table_path)($19)
	srl	$18,$11,12
	sw	$4,40($sp)
	sw	$3,44($sp)
	xor	$11,$18,$11
	sw	$10,16($sp)
	sw	$9,20($sp)
	sw	$8,24($sp)
	sw	$7,28($sp)
	sw	$6,32($sp)
	sw	$5,36($sp)
	addiu	$4,$13,-1
	and	$3,$11,$4
	lw	$4,0($12)
	sll	$18,$3,4
	sll	$3,$3,2
	subu	$18,$18,$3
	addu	$3,$4,$18
	lw	$16,0($3)
	beq	$16,$0,$L83
	lui	$21,%hi(v6_path_list_free)

	lui	$22,%hi(v6_path_list_inuse)
	addiu	$21,$21,%lo(v6_path_list_free)
	addiu	$22,$22,%lo(v6_path_list_inuse)
	j	$L81
	addiu	$20,$17,16

$L76:
	lw	$16,56($16)
	beq	$16,$0,$L84
	lw	$31,76($sp)

	lw	$2,36($17)
$L81:
	lw	$3,36($16)
	bne	$3,$2,$L76
	nop

	lw	$3,40($16)
	lw	$2,40($17)
	bne	$3,$2,$L76
	move	$4,$16

	move	$5,$17
	jal	memcmp
	li	$6,16			# 0x10

	bne	$2,$0,$L76
	addiu	$4,$16,16

	move	$5,$20
	jal	memcmp
	li	$6,16			# 0x10

	bne	$2,$0,$L76
	nop

	lw	$3,32($16)
	lw	$2,32($17)
	bne	$3,$2,$L76
	nop

	lw	$2,56($16)
	beq	$2,$0,$L77
	nop

	lw	$3,60($16)
	sw	$3,60($2)
$L78:
	lw	$2,60($16)
	lw	$3,56($16)
	sw	$3,0($2)
	lw	$2,%lo(v6_table_path)($19)
	lw	$2,0($2)
	addu	$2,$2,$18
	lw	$3,8($2)
	addiu	$3,$3,-1
	sw	$3,8($2)
	lw	$3,64($16)
	beq	$3,$0,$L79
	move	$2,$22

	lw	$4,68($16)
	sw	$4,68($3)
$L80:
	lw	$4,68($16)
	lw	$5,64($16)
	addiu	$3,$16,64
	sw	$5,0($4)
	lw	$4,8($2)
	addiu	$4,$4,-1
	sw	$4,8($2)
	sw	$0,64($16)
	lw	$2,4($21)
	sw	$2,68($16)
	lw	$2,4($21)
	sw	$16,0($2)
	lw	$2,8($21)
	sw	$3,4($21)
	addiu	$2,$2,1
	j	$L76
	sw	$2,8($21)

$L83:
	lw	$31,76($sp)
$L84:
	lw	$22,72($sp)
	lw	$21,68($sp)
	lw	$20,64($sp)
	lw	$19,60($sp)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	j	$31
	addiu	$sp,$sp,80

$L77:
	lw	$2,%lo(v6_table_path)($19)
	lw	$3,60($16)
	lw	$2,0($2)
	addu	$2,$2,$18
	j	$L78
	sw	$3,4($2)

$L79:
	lw	$3,68($16)
	j	$L80
	sw	$3,4($22)

	.set	macro
	.set	reorder
	.end	rtk_delV6Connection
	.size	rtk_delV6Connection, .-rtk_delV6Connection
	.align	2
	.globl	ipv6_fast_enter
	.set	nomips16
	.ent	ipv6_fast_enter
	.type	ipv6_fast_enter, @function
ipv6_fast_enter:
	.frame	$sp,296,$31		# vars= 240, regs= 10/0, args= 16, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-296
	sw	$31,292($sp)
	sw	$fp,288($sp)
	sw	$23,284($sp)
	sw	$22,280($sp)
	sw	$21,276($sp)
	sw	$20,272($sp)
	sw	$19,268($sp)
	sw	$18,264($sp)
	sw	$17,260($sp)
	sw	$16,256($sp)
	.set	noreorder
	.set	nomacro
	jal	rtl_skb_mac_header
	move	$17,$4
	.set	macro
	.set	reorder

	move	$4,$17
	.set	noreorder
	.set	nomacro
	jal	rtl_ipv6_hdr
	move	$16,$2
	.set	macro
	.set	reorder

	move	$4,$17
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_pppoe_flag
	move	$18,$2
	.set	macro
	.set	reorder

	bne	$2,$0,$L86
	lbu	$3,13($16)
	lbu	$2,12($16)
	sll	$3,$3,8
	or	$3,$3,$2
	li	$2,56710			# 0xdd86
	beq	$3,$2,$L86
$L87:
	move	$3,$0
$L103:
	lw	$31,292($sp)
$L124:
	lw	$fp,288($sp)
	lw	$23,284($sp)
	lw	$22,280($sp)
	lw	$21,276($sp)
	lw	$20,272($sp)
	lw	$19,268($sp)
	lw	$18,264($sp)
	lw	$17,260($sp)
	lw	$16,256($sp)
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,296
	.set	macro
	.set	reorder

$L86:
	.set	noreorder
	.set	nomacro
	jal	__ipv6_addr_type
	addiu	$4,$18,8
	.set	macro
	.set	reorder

	andi	$2,$2,0x20
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L103
	move	$3,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	__ipv6_addr_type
	addiu	$4,$18,24
	.set	macro
	.set	reorder

	andi	$2,$2,0x22
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L87
	li	$3,6			# 0x6
	.set	macro
	.set	reorder

	lbu	$2,6($18)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L88
	addiu	$4,$18,40
	.set	macro
	.set	reorder

	li	$3,17			# 0x11
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L89
	li	$3,44			# 0x2c
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L103
	move	$3,$0
	.set	macro
	.set	reorder

$L89:
	lw	$6,8($18)
	lw	$5,12($18)
	lw	$3,16($18)
	lw	$2,20($18)
	sw	$6,16($sp)
	sw	$5,20($sp)
	sw	$3,24($sp)
	sw	$2,28($sp)
	lw	$2,36($18)
	lw	$6,24($18)
	lw	$5,28($18)
	lw	$3,32($18)
	sw	$2,44($sp)
	sw	$6,32($sp)
	sw	$5,36($sp)
	sw	$3,40($sp)
	lbu	$22,6($18)
	li	$2,44			# 0x2c
	lhu	$19,40($18)
	.set	noreorder
	.set	nomacro
	beq	$22,$2,$L90
	lhu	$20,2($4)
	.set	macro
	.set	reorder

	andi	$23,$22,0xffff
	move	$21,$0
	move	$fp,$0
	sw	$0,240($sp)
	sw	$0,244($sp)
$L91:
	lw	$9,16($sp)
	lw	$8,20($sp)
	lw	$7,24($sp)
	lw	$6,28($sp)
	lw	$5,32($sp)
	xor	$10,$8,$9
	lw	$4,36($sp)
	xor	$10,$10,$7
	lw	$3,40($sp)
	xor	$10,$10,$6
	lw	$2,44($sp)
	xor	$10,$10,$5
	xor	$10,$10,$4
	xor	$10,$10,$3
	xor	$10,$10,$2
	srl	$11,$9,8
	xor	$10,$10,$11
	srl	$11,$8,8
	xor	$10,$10,$11
	srl	$11,$7,8
	xor	$10,$10,$11
	srl	$11,$6,8
	xor	$10,$10,$11
	srl	$11,$5,16
	xor	$10,$10,$11
	srl	$11,$4,16
	xor	$10,$10,$11
	srl	$11,$3,16
	xor	$10,$10,$11
	srl	$11,$2,16
	xor	$10,$10,$11
	xor	$10,$10,$20
	lui	$11,%hi(v6_path_table_list_max)
	lw	$12,%lo(v6_path_table_list_max)($11)
	xor	$10,$10,$23
	srl	$11,$19,4
	xor	$10,$10,$11
	lui	$11,%hi(v6_table_path)
	lw	$11,%lo(v6_table_path)($11)
	srl	$13,$10,12
	sw	$4,132($sp)
	sw	$3,136($sp)
	sw	$2,140($sp)
	sw	$9,112($sp)
	sw	$8,116($sp)
	sw	$7,120($sp)
	sw	$6,124($sp)
	sw	$5,128($sp)
	addiu	$3,$12,-1
	xor	$10,$13,$10
	and	$2,$10,$3
	lw	$3,0($11)
	sll	$4,$2,4
	sll	$2,$2,2
	subu	$2,$4,$2
	addu	$2,$3,$2
	lw	$16,0($2)
	.set	noreorder
	.set	nomacro
	bne	$16,$0,$L117
	move	$3,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L124
	lw	$31,292($sp)
	.set	macro
	.set	reorder

$L99:
	lw	$16,56($16)
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L103
	move	$3,$0
	.set	macro
	.set	reorder

$L117:
	lw	$2,36($16)
	bne	$2,$19,$L99
	lw	$2,40($16)
	.set	noreorder
	.set	nomacro
	bne	$2,$20,$L99
	move	$4,$16
	.set	macro
	.set	reorder

	addiu	$5,$sp,16
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L99
	addiu	$4,$16,16
	.set	macro
	.set	reorder

	addiu	$5,$sp,32
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	bne	$2,$0,$L99
	lw	$2,32($16)
	.set	noreorder
	.set	nomacro
	bne	$2,$22,$L99
	lui	$2,%hi(ipv6_rtcache)
	.set	macro
	.set	reorder

	lw	$2,%lo(ipv6_rtcache)($2)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L100
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	lw	$7,48($16)
	move	$5,$17
	.set	noreorder
	.set	nomacro
	jal	rtl_ip_route_input
	move	$6,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L103
	move	$3,$0
	.set	macro
	.set	reorder

$L101:
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_ipv6_dst
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L103
	move	$3,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_skb_ipv6_dst_check
	move	$4,$17
	.set	macro
	.set	reorder

	li	$3,-1			# 0xffffffffffffffff
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L106
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_check_dst_input
	sw	$3,248($sp)
	.set	macro
	.set	reorder

	lw	$3,248($sp)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L106
	lw	$2,244($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L105
	lw	$2,240($sp)
	.set	macro
	.set	reorder

	lui	$3,%hi(V6_udp_cache_list_free)
	lw	$11,16($sp)
	lw	$10,20($sp)
	lw	$9,24($sp)
	lw	$8,28($sp)
	lw	$7,32($sp)
	lw	$6,36($sp)
	lw	$5,40($sp)
	lw	$4,44($sp)
	lw	$2,%lo(V6_udp_cache_list_free)($3)
	lui	$13,%hi(V6_max_udp_frag_entry)
	lw	$12,4($fp)
	lw	$14,%lo(V6_max_udp_frag_entry)($13)
	sw	$11,144($sp)
	sw	$10,148($sp)
	sw	$9,152($sp)
	sw	$8,156($sp)
	sw	$7,160($sp)
	sw	$6,164($sp)
	sw	$5,168($sp)
	sw	$4,172($sp)
	sw	$11,192($sp)
	sw	$10,196($sp)
	sw	$9,200($sp)
	sw	$8,204($sp)
	sw	$7,176($sp)
	sw	$6,180($sp)
	sw	$5,184($sp)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L106
	sw	$4,188($sp)
	.set	macro
	.set	reorder

	sw	$12,0($2)
	lw	$24,148($sp)
	lw	$15,152($sp)
	lw	$13,156($sp)
	lw	$25,144($sp)
	sw	$24,8($2)
	sw	$13,16($2)
	sw	$25,4($2)
	sw	$15,12($2)
	lw	$15,172($sp)
	lw	$25,164($sp)
	lw	$24,168($sp)
	lw	$21,160($sp)
	lw	$13,88($2)
	andi	$19,$19,0xffff
	andi	$20,$20,0xffff
	sw	$15,32($2)
	li	$15,1			# 0x1
	sw	$21,20($2)
	sw	$25,24($2)
	sw	$24,28($2)
	sw	$22,36($2)
	sw	$19,40($2)
	sw	$20,44($2)
	.set	noreorder
	.set	nomacro
	beq	$13,$0,$L107
	sb	$15,48($2)
	.set	macro
	.set	reorder

	lw	$15,92($2)
	addiu	$3,$3,%lo(V6_udp_cache_list_free)
	sw	$15,92($13)
$L108:
	xor	$24,$10,$11
	xor	$24,$24,$9
	xor	$24,$24,$8
	xor	$24,$24,$7
	xor	$24,$24,$6
	xor	$24,$24,$5
	lw	$13,92($2)
	lw	$15,88($2)
	xor	$24,$24,$4
	srl	$11,$11,8
	xor	$11,$24,$11
	srl	$10,$10,8
	xor	$10,$11,$10
	srl	$9,$9,8
	sw	$15,0($13)
	xor	$9,$10,$9
	srl	$8,$8,8
	xor	$8,$9,$8
	srl	$7,$7,16
	lw	$9,8($3)
	xor	$7,$8,$7
	srl	$6,$6,16
	xor	$6,$7,$6
	srl	$5,$5,16
	xor	$5,$6,$5
	srl	$4,$4,16
	addiu	$6,$9,-1
	sw	$6,8($3)
	xor	$4,$5,$4
	sw	$0,80($2)
	lui	$5,%hi(V6_udp_cache_table)
	lw	$3,%lo(V6_udp_cache_table)($5)
	xor	$12,$4,$12
	srl	$4,$4,16
	xor	$4,$12,$4
	xor	$23,$4,$23
	addiu	$4,$14,-1
	and	$23,$23,$4
	lw	$4,0($3)
	sll	$3,$23,4
	sll	$23,$23,2
	subu	$3,$3,$23
	addu	$4,$4,$3
	lw	$4,4($4)
	addiu	$7,$2,80
	sw	$4,84($2)
	lw	$6,%lo(V6_udp_cache_table)($5)
	addiu	$4,$2,52
	lw	$6,0($6)
	addu	$6,$6,$3
	lw	$6,4($6)
	sw	$2,0($6)
	lw	$6,%lo(V6_udp_cache_table)($5)
	lw	$6,0($6)
	addu	$6,$6,$3
	sw	$7,4($6)
	lw	$5,%lo(V6_udp_cache_table)($5)
	lw	$5,0($5)
	addu	$3,$5,$3
	lw	$5,8($3)
	addiu	$5,$5,1
	sw	$5,8($3)
	lui	$3,%hi(jiffies)
	lw	$3,%lo(jiffies)($3)
	addiu	$3,$3,1000
	.set	noreorder
	.set	nomacro
	jal	add_timer
	sw	$3,60($2)
	.set	macro
	.set	reorder

$L109:
	move	$4,$17
$L123:
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_dev
	move	$5,$0
	.set	macro
	.set	reorder

	lbu	$2,7($18)
	sltu	$3,$2,2
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L112
	addiu	$2,$2,-1
	.set	macro
	.set	reorder

	sb	$2,7($18)
	lw	$5,52($16)
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_mark
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_len
	move	$4,$17
	.set	macro
	.set	reorder

	move	$4,$17
	.set	noreorder
	.set	nomacro
	jal	rtl_ip6_skb_dst_mtu
	move	$18,$2
	.set	macro
	.set	reorder

	sltu	$2,$2,$18
	beq	$2,$0,$L113
	.set	noreorder
	.set	nomacro
	jal	rtl_skb_is_gso
	move	$4,$17
	.set	macro
	.set	reorder

	beq	$2,$0,$L112
$L113:
	.set	noreorder
	.set	nomacro
	jal	rtl_dst_allfrag
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L122
	lui	$2,%hi(jiffies)
	.set	macro
	.set	reorder

$L112:
	.set	noreorder
	.set	nomacro
	jal	kfree_skb
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L103
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

$L88:
	lw	$2,12($4)
	andi	$2,$2,0x700
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L89
	move	$3,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L124
	lw	$31,292($sp)
	.set	macro
	.set	reorder

$L90:
	lbu	$3,40($18)
	li	$2,17			# 0x11
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L92
	move	$fp,$4
	.set	macro
	.set	reorder

	li	$23,44			# 0x2c
	move	$21,$0
	sw	$0,240($sp)
	.set	noreorder
	.set	nomacro
	j	$L91
	sw	$0,244($sp)
	.set	macro
	.set	reorder

$L92:
 #APP
 # 20 "/home/rock_liu/RELEASE_GIT_SDK/3414b_20190823/3414b/pre_build_sdk/sdk/linux-3.10/arch/mips-ori/include/uapi/asm/swab.h" 1
		wsbh	$20, $20			

 # 0 "" 2
 #NO_APP
	andi	$20,$20,0xffff
	andi	$3,$20,0xfff9
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L93
	andi	$2,$20,0xfff8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L95
	sw	$0,240($sp)
	.set	macro
	.set	reorder

	andi	$20,$20,0x1
	xori	$20,$20,0x1
	sw	$20,240($sp)
$L95:
	lw	$10,16($sp)
	lw	$9,20($sp)
	lw	$8,24($sp)
	lw	$7,28($sp)
	lw	$6,32($sp)
	xor	$13,$9,$10
	lw	$5,36($sp)
	xor	$13,$13,$8
	lw	$3,40($sp)
	xor	$13,$13,$7
	lw	$2,44($sp)
	xor	$13,$13,$6
	xor	$13,$13,$5
	xor	$13,$13,$3
	xor	$13,$13,$2
	srl	$11,$10,8
	xor	$13,$13,$11
	srl	$11,$9,8
	xor	$13,$13,$11
	srl	$11,$8,8
	xor	$13,$13,$11
	srl	$11,$7,8
	xor	$13,$13,$11
	srl	$11,$6,16
	lw	$16,4($4)
	xor	$13,$13,$11
	srl	$4,$5,16
	xor	$13,$13,$4
	srl	$4,$3,16
	xor	$13,$13,$4
	lui	$4,%hi(V6_max_udp_frag_entry)
	srl	$11,$2,16
	lw	$12,%lo(V6_max_udp_frag_entry)($4)
	lui	$4,%hi(V6_udp_cache_table)
	xor	$11,$13,$11
	lw	$4,%lo(V6_udp_cache_table)($4)
	xori	$13,$16,0x11
	xor	$13,$13,$11
	srl	$11,$11,16
	sw	$2,76($sp)
	sw	$2,92($sp)
	sw	$10,48($sp)
	sw	$9,52($sp)
	sw	$8,56($sp)
	sw	$7,60($sp)
	sw	$6,64($sp)
	sw	$5,68($sp)
	sw	$3,72($sp)
	sw	$10,96($sp)
	sw	$9,100($sp)
	sw	$8,104($sp)
	sw	$7,108($sp)
	sw	$6,80($sp)
	sw	$5,84($sp)
	sw	$3,88($sp)
	xor	$11,$13,$11
	addiu	$2,$12,-1
	and	$2,$11,$2
	lw	$3,0($4)
	sll	$4,$2,4
	sll	$2,$2,2
	subu	$2,$4,$2
	addu	$2,$3,$2
	lw	$21,0($2)
	.set	noreorder
	.set	nomacro
	beq	$21,$0,$L87
	addiu	$19,$sp,48
	.set	macro
	.set	reorder

	addiu	$22,$sp,64
	.set	noreorder
	.set	nomacro
	j	$L118
	li	$20,17			# 0x11
	.set	macro
	.set	reorder

$L96:
	lw	$21,80($21)
	.set	noreorder
	.set	nomacro
	beq	$21,$0,$L103
	move	$3,$0
	.set	macro
	.set	reorder

$L118:
	lw	$2,0($21)
	.set	noreorder
	.set	nomacro
	bne	$16,$2,$L96
	addiu	$4,$21,4
	.set	macro
	.set	reorder

	move	$5,$19
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L96
	addiu	$4,$21,20
	.set	macro
	.set	reorder

	move	$5,$22
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	bne	$2,$0,$L96
	lw	$2,36($21)
	bne	$2,$20,$L96
	.set	noreorder
	.set	nomacro
	beq	$21,$0,$L87
	li	$23,17			# 0x11
	.set	macro
	.set	reorder

	lw	$19,40($21)
	lw	$20,44($21)
	sw	$0,244($sp)
	.set	noreorder
	.set	nomacro
	j	$L91
	li	$22,17			# 0x11
	.set	macro
	.set	reorder

$L93:
	li	$2,1			# 0x1
	lhu	$19,8($4)
	lhu	$20,50($18)
	li	$23,17			# 0x11
	move	$21,$0
	sw	$0,240($sp)
	sw	$2,244($sp)
	.set	noreorder
	.set	nomacro
	j	$L91
	li	$22,17			# 0x11
	.set	macro
	.set	reorder

$L100:
	.set	noreorder
	.set	nomacro
	jal	rtl_ip6_route_input
	move	$4,$17
	.set	macro
	.set	reorder

	li	$3,-1			# 0xffffffffffffffff
	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L101
	move	$3,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L124
	lw	$31,292($sp)
	.set	macro
	.set	reorder

$L122:
	lw	$2,%lo(jiffies)($2)
	move	$4,$17
	.set	noreorder
	.set	nomacro
	jal	fast_path_post_process_xmit_check6
	sw	$2,44($16)
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$4,$L103
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	ip_finish_output6
	move	$4,$17
	.set	macro
	.set	reorder

	lui	$2,%hi(statistic_ipv6_fp)
	lw	$4,%lo(statistic_ipv6_fp)($2)
	li	$3,1			# 0x1
	addiu	$4,$4,1
	.set	noreorder
	.set	nomacro
	j	$L103
	sw	$4,%lo(statistic_ipv6_fp)($2)
	.set	macro
	.set	reorder

$L106:
	.set	noreorder
	.set	nomacro
	jal	rtl_dst_release_ipv6
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L103
	move	$3,$0
	.set	macro
	.set	reorder

$L107:
	lw	$13,92($2)
	addiu	$3,$3,%lo(V6_udp_cache_list_free)
	.set	noreorder
	.set	nomacro
	j	$L108
	sw	$13,4($3)
	.set	macro
	.set	reorder

$L105:
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L123
	move	$4,$17
	.set	macro
	.set	reorder

	beq	$21,$0,$L123
	.set	noreorder
	.set	nomacro
	jal	del_timer
	addiu	$4,$21,52
	.set	macro
	.set	reorder

	lw	$9,4($21)
	lw	$8,8($21)
	lw	$7,12($21)
	lw	$6,16($21)
	lw	$10,0($21)
	lhu	$11,36($21)
	sw	$9,224($sp)
	sw	$8,228($sp)
	sw	$7,232($sp)
	sw	$6,236($sp)
	lw	$5,20($21)
	xor	$12,$8,$9
	lw	$4,24($21)
	xor	$12,$12,$7
	lw	$2,28($21)
	xor	$12,$12,$6
	lw	$3,32($21)
	xor	$12,$12,$5
	xor	$12,$12,$4
	xor	$12,$12,$2
	xor	$12,$12,$3
	srl	$9,$9,8
	xor	$9,$12,$9
	srl	$8,$8,8
	xor	$8,$9,$8
	srl	$7,$7,8
	xor	$7,$8,$7
	srl	$6,$6,8
	xor	$6,$7,$6
	srl	$7,$5,16
	xor	$7,$6,$7
	srl	$6,$4,16
	sw	$2,216($sp)
	xor	$7,$7,$6
	srl	$6,$2,16
	lui	$2,%hi(V6_max_udp_frag_entry)
	sw	$5,208($sp)
	sw	$3,220($sp)
	sw	$4,212($sp)
	lw	$2,%lo(V6_max_udp_frag_entry)($2)
	xor	$6,$7,$6
	srl	$3,$3,16
	xor	$3,$6,$3
	xor	$5,$11,$10
	lw	$4,80($21)
	xor	$5,$5,$3
	srl	$3,$3,16
	xor	$3,$5,$3
	addiu	$2,$2,-1
	and	$2,$3,$2
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L110
	sb	$0,48($21)
	.set	macro
	.set	reorder

	lw	$5,84($21)
	sll	$3,$2,4
	sll	$2,$2,2
	sw	$5,84($4)
	subu	$3,$3,$2
	lui	$4,%hi(V6_udp_cache_table)
$L111:
	lw	$5,84($21)
	lw	$6,80($21)
	lui	$2,%hi(V6_udp_cache_list_free)
	addiu	$2,$2,%lo(V6_udp_cache_list_free)
	sw	$6,0($5)
	lw	$5,%lo(V6_udp_cache_table)($4)
	addiu	$4,$21,88
	lw	$5,0($5)
	addu	$3,$5,$3
	lw	$5,8($3)
	addiu	$5,$5,-1
	sw	$5,8($3)
	sw	$0,88($21)
	lw	$3,4($2)
	sw	$3,92($21)
	lw	$3,4($2)
	sw	$21,0($3)
	lw	$3,8($2)
	sw	$4,4($2)
	addiu	$3,$3,1
	.set	noreorder
	.set	nomacro
	j	$L109
	sw	$3,8($2)
	.set	macro
	.set	reorder

$L110:
	lui	$4,%hi(V6_udp_cache_table)
	lw	$5,%lo(V6_udp_cache_table)($4)
	sll	$6,$2,4
	sll	$3,$2,2
	lw	$2,0($5)
	lw	$5,84($21)
	subu	$3,$6,$3
	addu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	j	$L111
	sw	$5,4($2)
	.set	macro
	.set	reorder

	.end	ipv6_fast_enter
	.size	ipv6_fast_enter, .-ipv6_fast_enter
	.align	2
	.globl	V6_udp_fragCache_init
	.set	nomips16
	.ent	V6_udp_fragCache_init
	.type	V6_udp_fragCache_init, @function
V6_udp_fragCache_init:
	.frame	$sp,56,$31		# vars= 8, regs= 7/0, args= 16, gp= 0
	.mask	0x803f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-56
	sw	$31,52($sp)
	sw	$21,48($sp)
	sw	$20,44($sp)
	sw	$19,40($sp)
	sw	$18,36($sp)
	sw	$17,32($sp)
	sw	$16,28($sp)
	lui	$19,%hi(kmalloc_caches)
	addiu	$19,$19,%lo(kmalloc_caches)
	move	$20,$4
	lw	$4,28($19)
	li	$5,32800			# 0x8020
	jal	kmem_cache_alloc
	lui	$17,%hi(V6_udp_cache_table)

	move	$21,$2
	beq	$2,$0,$L126
	sw	$2,%lo(V6_udp_cache_table)($17)

	lui	$2,%hi(V6_udp_cache_list_free)
	sll	$3,$20,2
	sll	$4,$20,4
	subu	$4,$4,$3
	addiu	$16,$2,%lo(V6_udp_cache_list_free)
	lui	$18,%hi(V6_max_udp_frag_entry)
	li	$5,32			# 0x20
	sw	$0,%lo(V6_udp_cache_list_free)($2)
	sw	$0,8($16)
	sw	$16,4($16)
	jal	__kmalloc
	sw	$20,%lo(V6_max_udp_frag_entry)($18)

	sw	$2,0($21)
	lw	$3,%lo(V6_udp_cache_table)($17)
	lw	$4,0($3)
	beq	$4,$0,$L128
	li	$2,-1			# 0xffffffffffffffff

	blez	$20,$L129
	move	$2,$0

	move	$3,$0
	j	$L130
	move	$5,$17

$L135:
	lw	$4,%lo(V6_udp_cache_table)($5)
	lw	$4,0($4)
$L130:
	addu	$4,$4,$2
	sw	$0,8($4)
	lw	$4,%lo(V6_udp_cache_table)($17)
	addiu	$3,$3,1
	lw	$4,0($4)
	addu	$4,$4,$2
	sw	$0,0($4)
	lw	$4,%lo(V6_udp_cache_table)($17)
	lw	$4,0($4)
	addu	$4,$4,$2
	sw	$4,4($4)
	bne	$3,$20,$L135
	addiu	$2,$2,12

$L129:
	lw	$2,%lo(V6_max_udp_frag_entry)($18)
	blez	$2,$L131
	lui	$20,%hi(V6_cache_timeout)

	addiu	$20,$20,%lo(V6_cache_timeout)
	j	$L132
	move	$17,$0

$L136:
	jal	init_timer_key
	sw	$2,16($sp)

	lw	$2,16($sp)
	sw	$2,72($2)
	sw	$20,68($2)
	sw	$0,88($2)
	lw	$3,4($16)
	addiu	$4,$2,88
	sw	$3,92($2)
	lw	$3,4($16)
	sw	$2,0($3)
	lw	$3,8($16)
	lw	$2,%lo(V6_max_udp_frag_entry)($18)
	sw	$4,4($16)
	addiu	$3,$3,1
	slt	$2,$17,$2
	beq	$2,$0,$L131
	sw	$3,8($16)

$L132:
	lw	$4,28($19)
	li	$5,32			# 0x20
	jal	kmem_cache_alloc
	addiu	$17,$17,1

	addiu	$4,$2,52
	move	$5,$0
	move	$6,$0
	bne	$2,$0,$L136
	move	$7,$0

$L126:
	move	$2,$0
$L128:
	lw	$31,52($sp)
	lw	$21,48($sp)
	lw	$20,44($sp)
	lw	$19,40($sp)
	lw	$18,36($sp)
	lw	$17,32($sp)
	lw	$16,28($sp)
	j	$31
	addiu	$sp,$sp,56

$L131:
	j	$L128
	li	$2,1			# 0x1

	.set	macro
	.set	reorder
	.end	V6_udp_fragCache_init
	.size	V6_udp_fragCache_init, .-V6_udp_fragCache_init
	.align	2
	.globl	rtl_V6_Cache_Timer_update
	.set	nomips16
	.ent	rtl_V6_Cache_Timer_update
	.type	rtl_V6_Cache_Timer_update, @function
rtl_V6_Cache_Timer_update:
	.frame	$sp,88,$31		# vars= 48, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-88
	sw	$31,84($sp)
	sw	$19,80($sp)
	sw	$18,76($sp)
	sw	$17,72($sp)
	sw	$16,68($sp)
	lui	$2,%hi(jiffies)
	move	$5,$0
	lw	$18,%lo(jiffies)($2)
	jal	rtl_get_ct_protonum
	move	$16,$4

	li	$3,17			# 0x11
	beq	$2,$3,$L144
	move	$4,$16

	jal	rtl_get_ct_protonum
	move	$5,$0

	li	$3,6			# 0x6
	beq	$2,$3,$L145
	nop

$L141:
	li	$2,-1			# 0xffffffffffffffff
$L142:
	lw	$31,84($sp)
	lw	$19,80($sp)
	lw	$18,76($sp)
	lw	$17,72($sp)
	lw	$16,68($sp)
	j	$31
	addiu	$sp,$sp,88

$L144:
	jal	rtl_get_ct_udp_status
	move	$4,$16

	andi	$2,$2,0x2
	bne	$2,$0,$L146
	nop

	move	$4,$0
	move	$5,$16
	jal	udp_get_timeouts_by_state
	li	$6,1			# 0x1

	move	$19,$2
$L140:
	addiu	$17,$sp,20
	li	$6,44			# 0x2c
	move	$5,$0
	jal	memset
	move	$4,$17

	move	$4,$16
	jal	rtl_get_ct_protonum_ipv6
	move	$5,$0

	move	$5,$0
	move	$6,$0
	move	$7,$17
	move	$4,$16
	jal	rtl_get_ct_v6_ip_by_dir
	sw	$2,52($sp)

	addiu	$7,$sp,36
	move	$4,$16
	move	$5,$0
	jal	rtl_get_ct_v6_ip_by_dir
	li	$6,1			# 0x1

	move	$4,$16
	move	$5,$0
	jal	rtl_get_ct_port_by_dir
	move	$6,$0

	move	$4,$16
	move	$5,$0
	li	$6,1			# 0x1
	jal	rtl_get_ct_port_by_dir
	sw	$2,56($sp)

	move	$4,$17
	move	$5,$19
	addiu	$6,$sp,16
	jal	rtk_idleV6Connection
	sw	$2,60($sp)

	beq	$2,$0,$L141
	move	$4,$16

	lw	$5,16($sp)
	jal	rtl_set_ct_timeout_expires
	addu	$5,$19,$5

	move	$4,$16
	jal	rtl_check_for_acc
	addu	$5,$19,$18

	j	$L142
	move	$2,$0

$L146:
	li	$4,1			# 0x1
	move	$5,$16
	jal	udp_get_timeouts_by_state
	li	$6,1			# 0x1

	j	$L140
	move	$19,$2

$L145:
	jal	rtl_get_ct_tcp_state
	move	$4,$16

	sltu	$2,$2,6
	beq	$2,$0,$L142
	li	$2,-1			# 0xffffffffffffffff

	jal	rtl_tcp_get_timeouts
	move	$4,$16

	j	$L140
	move	$19,$2

	.set	macro
	.set	reorder
	.end	rtl_V6_Cache_Timer_update
	.size	rtl_V6_Cache_Timer_update, .-rtl_V6_Cache_Timer_update
	.align	2
	.globl	rtk_addV6Connection
	.set	nomips16
	.ent	rtk_addV6Connection
	.type	rtk_addV6Connection, @function
rtk_addV6Connection:
	.frame	$sp,184,$31		# vars= 128, regs= 10/0, args= 16, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-184
	sw	$31,180($sp)
	sw	$fp,176($sp)
	sw	$23,172($sp)
	sw	$22,168($sp)
	sw	$21,164($sp)
	sw	$20,160($sp)
	sw	$19,156($sp)
	sw	$18,152($sp)
	sw	$17,148($sp)
	sw	$16,144($sp)
	move	$19,$5
	move	$16,$4
	move	$4,$5
	.set	noreorder
	.set	nomacro
	jal	rtl_store_skb_ipv6_dst
	move	$fp,$6
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_dev
	move	$4,$19
	.set	macro
	.set	reorder

	move	$4,$19
	.set	noreorder
	.set	nomacro
	jal	rtl_ip6_route_input
	sw	$2,124($sp)
	.set	macro
	.set	reorder

	li	$3,-1			# 0xffffffffffffffff
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L176
	lw	$31,180($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_ipv6_dst
	move	$4,$19
	.set	macro
	.set	reorder

	beq	$2,$0,$L172
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_ipv6_dst_dev
	move	$4,$19
	.set	macro
	.set	reorder

	move	$4,$19
	.set	noreorder
	.set	nomacro
	jal	rtl_dst_release
	sw	$2,136($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_ipv6_dst
	move	$4,$19
	.set	macro
	.set	reorder

	lw	$2,136($sp)
	sw	$2,132($sp)
$L150:
	lw	$10,0($16)
	lw	$11,40($16)
	lw	$9,4($16)
	lw	$8,8($16)
	lw	$7,12($16)
	xor	$11,$10,$11
	lw	$6,16($16)
	xor	$11,$11,$9
	lw	$5,20($16)
	xor	$11,$11,$8
	lw	$4,24($16)
	xor	$11,$11,$7
	lw	$3,28($16)
	xor	$11,$11,$6
	xor	$11,$11,$5
	xor	$11,$11,$4
	xor	$11,$11,$3
	srl	$2,$10,8
	xor	$11,$11,$2
	srl	$2,$9,8
	xor	$11,$11,$2
	srl	$2,$8,8
	xor	$11,$11,$2
	srl	$2,$7,8
	xor	$11,$11,$2
	srl	$2,$6,16
	xor	$11,$11,$2
	srl	$12,$5,16
	lw	$2,36($16)
	xor	$11,$11,$12
	srl	$12,$4,16
	srl	$13,$3,16
	xor	$11,$11,$12
	lhu	$12,32($16)
	xor	$11,$11,$13
	lui	$23,%hi(v6_path_table_list_max)
	srl	$13,$2,4
	xor	$11,$11,$13
	lui	$20,%hi(v6_table_path)
	lw	$13,%lo(v6_path_table_list_max)($23)
	xor	$11,$11,$12
	lw	$12,%lo(v6_table_path)($20)
	srl	$14,$11,12
	sw	$4,72($sp)
	sw	$3,76($sp)
	sw	$10,48($sp)
	sw	$9,52($sp)
	sw	$8,56($sp)
	sw	$7,60($sp)
	sw	$6,64($sp)
	sw	$5,68($sp)
	addiu	$4,$13,-1
	xor	$11,$14,$11
	and	$3,$11,$4
	lw	$4,0($12)
	sll	$21,$3,4
	sll	$3,$3,2
	subu	$21,$21,$3
	addu	$3,$4,$21
	lw	$17,0($3)
	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L151
	addiu	$18,$16,16
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L179
	lw	$3,36($17)
	.set	macro
	.set	reorder

$L152:
	lw	$17,56($17)
	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L177
	lui	$22,%hi(v6_path_list_free)
	.set	macro
	.set	reorder

	lw	$2,36($16)
	lw	$3,36($17)
$L179:
	bne	$3,$2,$L152
	lw	$3,40($17)
	lw	$2,40($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L152
	move	$4,$17
	.set	macro
	.set	reorder

	move	$5,$16
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L152
	addiu	$4,$17,16
	.set	macro
	.set	reorder

	move	$5,$18
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	bne	$2,$0,$L152
	lw	$12,32($17)
	lw	$2,32($16)
	bne	$12,$2,$L152
	.set	noreorder
	.set	nomacro
	j	$L175
	lw	$10,16($16)
	.set	macro
	.set	reorder

$L151:
	lui	$22,%hi(v6_path_list_free)
$L177:
	lw	$18,%lo(v6_path_list_free)($22)
	beq	$18,$0,$L171
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_protocol
	move	$4,$19
	.set	macro
	.set	reorder

	move	$4,$19
 #APP
 # 20 "/home/rock_liu/RELEASE_GIT_SDK/3414b_20190823/3414b/pre_build_sdk/sdk/linux-3.10/arch/mips-ori/include/uapi/asm/swab.h" 1
		wsbh	$2, $2			

 # 0 "" 2
 #NO_APP
	andi	$3,$2,0xffff
	.set	noreorder
	.set	nomacro
	jal	rtl_ipv6_hdr
	sw	$3,136($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_mark
	move	$17,$2
	.set	macro
	.set	reorder

	sw	$2,128($sp)
	lw	$6,8($17)
	lw	$5,12($17)
	lw	$4,16($17)
	lw	$2,20($17)
	sw	$6,16($sp)
	sw	$5,20($sp)
	sw	$4,24($sp)
	sw	$2,28($sp)
	lw	$2,36($17)
	lw	$6,24($17)
	lw	$5,28($17)
	lw	$4,32($17)
	lhu	$7,40($17)
	sw	$2,44($sp)
	addiu	$2,$17,40
	sw	$6,32($sp)
	sw	$5,36($sp)
	sw	$4,40($sp)
	sw	$2,112($sp)
	sw	$7,120($sp)
	lhu	$7,2($2)
	move	$4,$19
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_mark
	sw	$7,116($sp)
	.set	macro
	.set	reorder

	lw	$6,0($16)
	lw	$5,4($16)
	lw	$4,8($16)
	lw	$2,12($16)
	sw	$6,8($17)
	sw	$5,12($17)
	sw	$4,16($17)
	sw	$2,20($17)
	lw	$2,36($16)
	sh	$2,40($17)
	lw	$4,24($16)
	lw	$2,28($16)
	lw	$6,16($16)
	lw	$5,20($16)
	sw	$4,32($17)
	sw	$6,24($17)
	sw	$5,28($17)
	sw	$2,36($17)
	lw	$2,40($16)
	lw	$4,112($sp)
	sh	$2,2($4)
	lw	$3,136($sp)
	li	$2,34525			# 0x86dd
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L173
	lui	$2,%hi(nf_hooks+640)
	.set	macro
	.set	reorder

$L156:
	lw	$5,128($sp)
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_mark
	move	$4,$19
	.set	macro
	.set	reorder

	lw	$4,20($sp)
	lw	$3,24($sp)
	lw	$2,28($sp)
	lw	$5,16($sp)
	sw	$4,12($17)
	sw	$3,16($17)
	sw	$5,8($17)
	sw	$2,20($17)
	lw	$7,120($sp)
	sh	$7,40($17)
	lw	$4,36($sp)
	lw	$2,40($sp)
	lw	$3,44($sp)
	lw	$5,32($sp)
	sw	$4,28($17)
	sw	$3,36($17)
	sw	$5,24($17)
	sw	$2,32($17)
	lw	$3,116($sp)
	lw	$2,112($sp)
	sh	$3,2($2)
	lw	$5,0($16)
	lw	$4,4($16)
	lw	$3,8($16)
	lw	$2,12($16)
	sw	$5,0($18)
	sw	$4,4($18)
	sw	$3,8($18)
	sw	$2,12($18)
	lw	$3,24($16)
	lw	$2,28($16)
	lw	$4,20($16)
	lw	$5,16($16)
	sw	$5,16($18)
	sw	$2,28($18)
	sw	$4,20($18)
	sw	$3,24($18)
	lw	$3,32($16)
	lw	$2,64($18)
	sw	$3,32($18)
	lw	$3,36($16)
	sw	$3,36($18)
	lw	$3,40($16)
	sw	$3,40($18)
	lui	$3,%hi(jiffies)
	lw	$3,%lo(jiffies)($3)
	sw	$fp,48($18)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L159
	sw	$3,44($18)
	.set	macro
	.set	reorder

	lw	$3,68($18)
	lui	$22,%hi(v6_path_list_free)
	addiu	$22,$22,%lo(v6_path_list_free)
	sw	$3,68($2)
$L160:
	lw	$3,68($18)
	lw	$4,64($18)
	lui	$2,%hi(v6_path_list_inuse)
	addiu	$2,$2,%lo(v6_path_list_inuse)
	sw	$4,0($3)
	lw	$4,8($22)
	addiu	$5,$18,64
	addiu	$3,$18,56
	addiu	$4,$4,-1
	sw	$4,8($22)
	sw	$0,64($18)
	lw	$4,4($2)
	sw	$4,68($18)
	lw	$4,4($2)
	sw	$18,0($4)
	lw	$4,8($2)
	sw	$5,4($2)
	addiu	$4,$4,1
	sw	$4,8($2)
	sw	$0,56($18)
	lw	$2,%lo(v6_table_path)($20)
	lw	$2,0($2)
	addu	$2,$2,$21
	lw	$2,4($2)
	sw	$2,60($18)
	lw	$2,%lo(v6_table_path)($20)
	lw	$2,0($2)
	addu	$2,$2,$21
	lw	$2,4($2)
	sw	$18,0($2)
	lw	$2,%lo(v6_table_path)($20)
	lw	$2,0($2)
	addu	$2,$2,$21
	sw	$3,4($2)
	lw	$2,%lo(v6_table_path)($20)
	lw	$2,0($2)
	addu	$21,$2,$21
	lw	$2,8($21)
	addiu	$2,$2,1
	sw	$2,8($21)
$L171:
	lw	$12,32($16)
$L153 = .
	lw	$10,16($16)
$L175:
	lw	$11,36($16)
	lw	$9,20($16)
	lw	$8,24($16)
	lw	$7,28($16)
	xor	$11,$10,$11
	lw	$6,0($16)
	xor	$11,$11,$9
	lw	$5,4($16)
	xor	$11,$11,$8
	lw	$4,8($16)
	xor	$11,$11,$7
	lw	$3,12($16)
	xor	$11,$11,$6
	xor	$11,$11,$5
	xor	$11,$11,$4
	xor	$11,$11,$3
	srl	$2,$10,8
	xor	$11,$11,$2
	srl	$2,$9,8
	xor	$11,$11,$2
	srl	$2,$8,8
	xor	$11,$11,$2
	srl	$2,$7,8
	xor	$11,$11,$2
	srl	$2,$6,16
	xor	$11,$11,$2
	srl	$13,$5,16
	lw	$2,40($16)
	xor	$11,$11,$13
	srl	$13,$4,16
	xor	$11,$11,$13
	srl	$13,$3,16
	xor	$11,$11,$13
	srl	$13,$2,4
	xor	$11,$11,$13
	andi	$12,$12,0xffff
	lw	$13,%lo(v6_path_table_list_max)($23)
	xor	$11,$11,$12
	lw	$12,%lo(v6_table_path)($20)
	srl	$14,$11,12
	sw	$4,104($sp)
	sw	$3,108($sp)
	sw	$10,80($sp)
	sw	$9,84($sp)
	sw	$8,88($sp)
	sw	$7,92($sp)
	sw	$6,96($sp)
	sw	$5,100($sp)
	addiu	$4,$13,-1
	xor	$11,$14,$11
	and	$3,$11,$4
	lw	$4,0($12)
	sll	$21,$3,4
	sll	$3,$3,2
	subu	$21,$21,$3
	addu	$3,$4,$21
	lw	$17,0($3)
	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L161
	addiu	$18,$16,16
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L180
	lw	$3,36($17)
	.set	macro
	.set	reorder

$L162:
	lw	$17,56($17)
	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L178
	lui	$22,%hi(v6_path_list_free)
	.set	macro
	.set	reorder

	lw	$2,40($16)
	lw	$3,36($17)
$L180:
	bne	$3,$2,$L162
	lw	$3,40($17)
	lw	$2,36($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L162
	move	$4,$17
	.set	macro
	.set	reorder

	move	$5,$18
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L162
	addiu	$4,$17,16
	.set	macro
	.set	reorder

	move	$5,$16
	.set	noreorder
	.set	nomacro
	jal	memcmp
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	bne	$2,$0,$L162
	lw	$3,32($17)
	lw	$2,32($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L162
	lw	$31,180($sp)
	.set	macro
	.set	reorder

$L176:
	lw	$fp,176($sp)
	lw	$23,172($sp)
	lw	$22,168($sp)
	lw	$21,164($sp)
	lw	$20,160($sp)
	lw	$19,156($sp)
	lw	$18,152($sp)
	lw	$17,148($sp)
	lw	$16,144($sp)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,184
	.set	macro
	.set	reorder

$L161:
	lui	$22,%hi(v6_path_list_free)
$L178:
	lw	$18,%lo(v6_path_list_free)($22)
	.set	noreorder
	.set	nomacro
	beq	$18,$0,$L176
	lw	$31,180($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_protocol
	move	$4,$19
	.set	macro
	.set	reorder

	move	$4,$19
 #APP
 # 20 "/home/rock_liu/RELEASE_GIT_SDK/3414b_20190823/3414b/pre_build_sdk/sdk/linux-3.10/arch/mips-ori/include/uapi/asm/swab.h" 1
		wsbh	$2, $2			

 # 0 "" 2
 #NO_APP
	andi	$3,$2,0xffff
	.set	noreorder
	.set	nomacro
	jal	rtl_ipv6_hdr
	sw	$3,136($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_mark
	move	$17,$2
	.set	macro
	.set	reorder

	sw	$2,120($sp)
	lw	$6,8($17)
	lw	$5,12($17)
	lw	$4,16($17)
	lw	$2,20($17)
	sw	$6,16($sp)
	sw	$5,20($sp)
	sw	$4,24($sp)
	sw	$2,28($sp)
	lw	$6,24($17)
	lw	$5,28($17)
	lw	$4,32($17)
	lw	$2,36($17)
	lhu	$7,40($17)
	addiu	$23,$17,40
	sw	$6,32($sp)
	sw	$5,36($sp)
	sw	$4,40($sp)
	sw	$7,116($sp)
	sw	$2,44($sp)
	lhu	$2,2($23)
	move	$4,$19
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_mark
	sw	$2,112($sp)
	.set	macro
	.set	reorder

	lw	$6,16($16)
	lw	$5,20($16)
	lw	$4,24($16)
	lw	$2,28($16)
	sw	$6,8($17)
	sw	$5,12($17)
	sw	$4,16($17)
	sw	$2,20($17)
	lw	$2,40($16)
	sh	$2,40($17)
	lw	$2,12($16)
	lw	$6,0($16)
	lw	$5,4($16)
	lw	$4,8($16)
	sw	$6,24($17)
	sw	$5,28($17)
	sw	$4,32($17)
	sw	$2,36($17)
	lw	$2,36($16)
	sh	$2,2($23)
	lw	$3,136($sp)
	li	$2,34525			# 0x86dd
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L174
	lui	$2,%hi(nf_hooks+640)
	.set	macro
	.set	reorder

$L164:
	lw	$5,120($sp)
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_mark
	move	$4,$19
	.set	macro
	.set	reorder

	lw	$4,20($sp)
	lw	$3,24($sp)
	lw	$2,28($sp)
	lw	$5,16($sp)
	sw	$4,12($17)
	sw	$3,16($17)
	sw	$5,8($17)
	sw	$2,20($17)
	lw	$3,116($sp)
	sh	$3,40($17)
	lw	$4,36($sp)
	lw	$2,40($sp)
	lw	$3,44($sp)
	lw	$5,32($sp)
	sw	$4,28($17)
	sw	$3,36($17)
	sw	$5,24($17)
	sw	$2,32($17)
	lw	$4,112($sp)
	sh	$4,2($23)
	lw	$5,16($16)
	lw	$4,20($16)
	lw	$3,24($16)
	lw	$2,28($16)
	sw	$5,0($18)
	sw	$4,4($18)
	sw	$3,8($18)
	sw	$2,12($18)
	lw	$3,8($16)
	lw	$2,12($16)
	lw	$5,0($16)
	lw	$4,4($16)
	sw	$5,16($18)
	sw	$4,20($18)
	sw	$2,28($18)
	sw	$3,24($18)
	lw	$3,32($16)
	lw	$2,64($18)
	sw	$3,32($18)
	lw	$3,40($16)
	sw	$3,36($18)
	lw	$3,36($16)
	sw	$3,40($18)
	lui	$3,%hi(jiffies)
	lw	$3,%lo(jiffies)($3)
	sw	$fp,48($18)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L167
	sw	$3,44($18)
	.set	macro
	.set	reorder

	lw	$3,68($18)
	lui	$22,%hi(v6_path_list_free)
	addiu	$22,$22,%lo(v6_path_list_free)
	sw	$3,68($2)
$L168:
	lw	$2,68($18)
	lw	$4,64($18)
	lui	$3,%hi(v6_path_list_inuse)
	addiu	$3,$3,%lo(v6_path_list_inuse)
	sw	$4,0($2)
	lw	$2,8($22)
	addiu	$6,$18,64
	addiu	$4,$18,56
	addiu	$2,$2,-1
	sw	$2,8($22)
	sw	$0,64($18)
	lw	$5,4($3)
	li	$2,1			# 0x1
	sw	$5,68($18)
	lw	$5,4($3)
	sw	$18,0($5)
	lw	$5,8($3)
	sw	$6,4($3)
	addiu	$5,$5,1
	sw	$5,8($3)
	sw	$0,56($18)
	lw	$3,%lo(v6_table_path)($20)
	lw	$3,0($3)
	addu	$3,$3,$21
	lw	$3,4($3)
	sw	$3,60($18)
	lw	$3,%lo(v6_table_path)($20)
	lw	$3,0($3)
	addu	$3,$3,$21
	lw	$3,4($3)
	sw	$18,0($3)
	lw	$3,%lo(v6_table_path)($20)
	lw	$3,0($3)
	addu	$3,$3,$21
	sw	$4,4($3)
	lw	$3,%lo(v6_table_path)($20)
	lw	$3,0($3)
	addu	$21,$3,$21
	lw	$3,8($21)
	addiu	$3,$3,1
	sw	$3,8($21)
	lw	$31,180($sp)
	lw	$fp,176($sp)
	lw	$23,172($sp)
	lw	$22,168($sp)
	lw	$21,164($sp)
	lw	$20,160($sp)
	lw	$19,156($sp)
	lw	$18,152($sp)
	lw	$17,148($sp)
	lw	$16,144($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,184
	.set	macro
	.set	reorder

$L174:
	lw	$3,%lo(nf_hooks+640)($2)
	addiu	$2,$2,%lo(nf_hooks+640)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L165
	lw	$6,132($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	rtl_ipt6_do_table
	move	$7,$0
	.set	macro
	.set	reorder

$L165:
	lui	$2,%hi(nf_hooks+672)
	lw	$3,%lo(nf_hooks+672)($2)
	addiu	$2,$2,%lo(nf_hooks+672)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L166
	lw	$7,124($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	li	$5,4			# 0x4
	.set	noreorder
	.set	nomacro
	jal	rtl_ipt6_do_table
	move	$6,$0
	.set	macro
	.set	reorder

$L166:
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_mark
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L164
	sw	$2,52($18)
	.set	macro
	.set	reorder

$L173:
	lw	$3,%lo(nf_hooks+640)($2)
	addiu	$2,$2,%lo(nf_hooks+640)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L157
	lw	$6,124($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	rtl_ipt6_do_table
	move	$7,$0
	.set	macro
	.set	reorder

$L157:
	lui	$2,%hi(nf_hooks+672)
	lw	$3,%lo(nf_hooks+672)($2)
	addiu	$2,$2,%lo(nf_hooks+672)
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L158
	lw	$7,132($sp)
	.set	macro
	.set	reorder

	move	$4,$19
	li	$5,4			# 0x4
	.set	noreorder
	.set	nomacro
	jal	rtl_ipt6_do_table
	move	$6,$0
	.set	macro
	.set	reorder

$L158:
	.set	noreorder
	.set	nomacro
	jal	rtl_get_skb_mark
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L156
	sw	$2,52($18)
	.set	macro
	.set	reorder

$L172:
	.set	noreorder
	.set	nomacro
	jal	rtl_set_skb_ipv6_dst
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L150
	sw	$0,132($sp)
	.set	macro
	.set	reorder

$L167:
	lw	$2,68($18)
	addiu	$22,$22,%lo(v6_path_list_free)
	.set	noreorder
	.set	nomacro
	j	$L168
	sw	$2,4($22)
	.set	macro
	.set	reorder

$L159:
	lw	$2,68($18)
	addiu	$22,$22,%lo(v6_path_list_free)
	.set	noreorder
	.set	nomacro
	j	$L160
	sw	$2,4($22)
	.set	macro
	.set	reorder

	.end	rtk_addV6Connection
	.size	rtk_addV6Connection, .-rtk_addV6Connection
	.globl	fast_ipv6_fw
	.section	.bss,"aw",@nobits
	.align	2
	.type	fast_ipv6_fw, @object
	.size	fast_ipv6_fw, 4
fast_ipv6_fw:
	.space	4
	.globl	ipv6_rtcache
	.data
	.align	2
	.type	ipv6_rtcache, @object
	.size	ipv6_rtcache, 4
ipv6_rtcache:
	.word	1
	.globl	ipv6_fast_forward_proc_fops
	.align	2
	.type	ipv6_fast_forward_proc_fops, @object
	.size	ipv6_fast_forward_proc_fops, 108
ipv6_fast_forward_proc_fops:
	.space	4
	.word	seq_lseek
	.word	seq_read
	.word	ipv6_fast_forward_single_write
	.space	28
	.word	ipv6_fast_forward_single_open
	.space	4
	.word	single_release
	.space	52
	.local	ipv6_res
	.comm	ipv6_res,4,4
	.local	v6_path_table_list_max
	.comm	v6_path_table_list_max,4,4
	.local	V6_max_udp_frag_entry
	.comm	V6_max_udp_frag_entry,4,4
	.globl	v6_path_list_inuse
	.section	.bss
	.align	2
	.type	v6_path_list_inuse, @object
	.size	v6_path_list_inuse, 12
v6_path_list_inuse:
	.space	12
	.globl	v6_path_list_free
	.align	2
	.type	v6_path_list_free, @object
	.size	v6_path_list_free, 12
v6_path_list_free:
	.space	12
	.globl	v6_table_path
	.align	2
	.type	v6_table_path, @object
	.size	v6_table_path, 4
v6_table_path:
	.space	4
	.globl	V6_udp_cache_list_free
	.align	2
	.type	V6_udp_cache_list_free, @object
	.size	V6_udp_cache_list_free, 12
V6_udp_cache_list_free:
	.space	12
	.globl	V6_udp_cache_table
	.align	2
	.type	V6_udp_cache_table, @object
	.size	V6_udp_cache_table, 4
V6_udp_cache_table:
	.space	4
	.ident	"GCC: (Realtek MSDK-4.4.7 Build 2001) 4.4.7"
