// SIDH: an efficient supersingular isogeny-based cryptography library for
//       ephemeral Diffie-Hellman key exchange.
//
//    Copyright (c) Microsoft Corporation. All rights reserved.
//
//
// Abstract: field arithmetic in x64 assembly for Linux

// p751 + 1
#define p751p1_5	0xEEB0000000000000
#define p751p1_6	0xE3EC968549F878A8
#define p751p1_7	0xDA959B1A13F7CC76
#define p751p1_8	0x084E9867D6EBE876
#define p751p1_9	0x8562B5045CB25748
#define p751p1_10	0x0E12909F97BADC66
#define p751p1_11	0x00006FE5D541F71C

#define p751x2_0	0xFFFFFFFFFFFFFFFE
#define p751x2_1	0xFFFFFFFFFFFFFFFF
#define p751x2_5	0xDD5FFFFFFFFFFFFF
#define p751x2_6	0xC7D92D0A93F0F151
#define p751x2_7	0xB52B363427EF98ED
#define p751x2_8	0x109D30CFADD7D0ED
#define p751x2_9	0x0AC56A08B964AE90
#define p751x2_10	0x1C25213F2F75B8CD
#define p751x2_11	0x0000DFCBAA83EE38

//  Field addition
//  Operation: c [%rdx] = a [%rdi] + b [%rsi]
.globl	fpadd751_asm
fpadd751_asm:
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	64(%rdi),%rcx
	addq	(%rsi),%r8
	adcq	8(%rsi),%r9
	adcq	16(%rsi),%r10
	adcq	24(%rsi),%r11
	adcq	32(%rsi),%r12
	adcq	40(%rsi),%r13
	adcq	48(%rsi),%r14
	adcq	56(%rsi),%r15
	adcq	64(%rsi),%rcx
	movq	72(%rdi),%rax
	adcq	72(%rsi),%rax
	movq	%rax,72(%rdx)
	movq	80(%rdi),%rax
	adcq	80(%rsi),%rax
	movq	%rax,80(%rdx)
	movq	88(%rdi),%rax
	adcq	88(%rsi),%rax
	movq	%rax,88(%rdx)

	movq	$p751x2_0,%rax
	subq	%rax,%r8
	movq	$p751x2_1,%rax
	sbbq	%rax,%r9
	sbbq	%rax,%r10
	sbbq	%rax,%r11
	sbbq	%rax,%r12
	movabs	$p751x2_5,%rax
	sbbq	%rax,%r13
	movabs	$p751x2_6,%rax
	sbbq	%rax,%r14
	movabs	$p751x2_7,%rax
	sbbq	%rax,%r15
	movabs	$p751x2_8,%rax
	sbbq	%rax,%rcx
	movq	%r8,(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%r14,48(%rdx)
	movq	%r15,56(%rdx)
	movq	%rcx,64(%rdx)
	movq	72(%rdx),%r8
	movq	80(%rdx),%r9
	movq	88(%rdx),%r10
	movabs	$p751x2_9,%rax
	sbbq	%rax,%r8
	movabs	$p751x2_10,%rax
	sbbq	%rax,%r9
	movabs	$p751x2_11,%rax
	sbbq	%rax,%r10
	movq	%r8,72(%rdx)
	movq	%r9,80(%rdx)
	movq	%r10,88(%rdx)
	movq	$0,%rax
	sbbq	$0,%rax

	movq	$p751x2_0,%rsi
	andq	%rax,%rsi
	movq	$p751x2_1,%r8
	andq	%rax,%r8
	movabs	$p751x2_5,%r9
	andq	%rax,%r9
	movabs	$p751x2_6,%r10
	andq	%rax,%r10
	movabs	$p751x2_7,%r11
	andq	%rax,%r11
	movabs	$p751x2_8,%r12
	andq	%rax,%r12
	movabs	$p751x2_9,%r13
	andq	%rax,%r13
	movabs	$p751x2_10,%r14
	andq	%rax,%r14
	movabs	$p751x2_11,%r15
	andq	%rax,%r15

	movq	(%rdx),%rax
	addq	%rsi,%rax
	movq	%rax,(%rdx)
	movq	8(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,8(%rdx)
	movq	16(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,16(%rdx)
	movq	24(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,24(%rdx)
	movq	32(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,32(%rdx)
	movq	40(%rdx),%rax
	adcq	%r9,%rax
	movq	%rax,40(%rdx)
	movq	48(%rdx),%rax
	adcq	%r10,%rax
	movq	%rax,48(%rdx)
	movq	56(%rdx),%rax
	adcq	%r11,%rax
	movq	%rax,56(%rdx)
	movq	64(%rdx),%rax
	adcq	%r12,%rax
	movq	%rax,64(%rdx)
	movq	72(%rdx),%rax
	adcq	%r13,%rax
	movq	%rax,72(%rdx)
	movq	80(%rdx),%rax
	adcq	%r14,%rax
	movq	%rax,80(%rdx)
	movq	88(%rdx),%rax
	adcq	%r15,%rax
	movq	%rax,88(%rdx)

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size	fpadd751_asm,.-fpadd751_asm


//  Field subtraction
//  Operation: c [%rdx] = a [%rdi] - b [%rsi]
.globl	fpsub751_asm
fpsub751_asm:
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	64(%rdi),%rcx
	subq	(%rsi),%r8
	sbbq	8(%rsi),%r9
	sbbq	16(%rsi),%r10
	sbbq	24(%rsi),%r11
	sbbq	32(%rsi),%r12
	sbbq	40(%rsi),%r13
	sbbq	48(%rsi),%r14
	sbbq	56(%rsi),%r15
	sbbq	64(%rsi),%rcx
	movq	%r8,(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%r14,48(%rdx)
	movq	%r15,56(%rdx)
	movq	%rcx,64(%rdx)
	movq	72(%rdi),%rax
	sbbq	72(%rsi),%rax
	movq	%rax,72(%rdx)
	movq	80(%rdi),%rax
	sbbq	80(%rsi),%rax
	movq	%rax,80(%rdx)
	movq	88(%rdi),%rax
	sbbq	88(%rsi),%rax
	movq	%rax,88(%rdx)
	movq	$0,%rax
	sbbq	$0,%rax

	movq	$p751x2_0,%rsi
	andq	%rax,%rsi
	movq	$p751x2_1,%r8
	andq	%rax,%r8
	movabs	$p751x2_5,%r9
	andq	%rax,%r9
	movabs	$p751x2_6,%r10
	andq	%rax,%r10
	movabs	$p751x2_7,%r11
	andq	%rax,%r11
	movabs	$p751x2_8,%r12
	andq	%rax,%r12
	movabs	$p751x2_9,%r13
	andq	%rax,%r13
	movabs	$p751x2_10,%r14
	andq	%rax,%r14
	movabs	$p751x2_11,%r15
	andq	%rax,%r15

	movq	(%rdx),%rax
	addq	%rsi,%rax
	movq	%rax,(%rdx)
	movq	8(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,8(%rdx)
	movq	16(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,16(%rdx)
	movq	24(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,24(%rdx)
	movq	32(%rdx),%rax
	adcq	%r8,%rax
	movq	%rax,32(%rdx)
	movq	40(%rdx),%rax
	adcq	%r9,%rax
	movq	%rax,40(%rdx)
	movq	48(%rdx),%rax
	adcq	%r10,%rax
	movq	%rax,48(%rdx)
	movq	56(%rdx),%rax
	adcq	%r11,%rax
	movq	%rax,56(%rdx)
	movq	64(%rdx),%rax
	adcq	%r12,%rax
	movq	%rax,64(%rdx)
	movq	72(%rdx),%rax
	adcq	%r13,%rax
	movq	%rax,72(%rdx)
	movq	80(%rdx),%rax
	adcq	%r14,%rax
	movq	%rax,80(%rdx)
	movq	88(%rdx),%rax
	adcq	%r15,%rax
	movq	%rax,88(%rdx)

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size	fpsub751_asm,.-fpsub751_asm


//  Integer multiplication
//  Based on Karatsuba method
//  Operation: c [%rdx] = a [%rdi] * b [%rsi]
//  NOTE: a=c or b=c are not allowed
.globl	mul751_asm
mul751_asm:
	pushq	%r12
	pushq	%r13
	pushq	%r14

	movq	%rdx,%rcx
	xorq	%rax,%rax
	movq	48(%rdi),%r8
	movq	56(%rdi),%r9
	movq	64(%rdi),%r10
	movq	72(%rdi),%r11
	movq	80(%rdi),%r12
	movq	88(%rdi),%r13
	addq	(%rdi),%r8
	adcq	8(%rdi),%r9
	adcq	16(%rdi),%r10
	adcq	24(%rdi),%r11
	adcq	32(%rdi),%r12
	adcq	40(%rdi),%r13
	pushq	%r15
	movq	%r8,(%rcx)
	movq	%r9,8(%rcx)
	movq	%r10,16(%rcx)
	movq	%r11,24(%rcx)
	movq	%r12,32(%rcx)
	movq	%r13,40(%rcx)
	sbbq	$0,%rax
	subq	$96,%rsp					// Allocating space in stack

	xorq	%rdx,%rdx
	movq	48(%rsi),%r8
	movq	56(%rsi),%r9
	movq	64(%rsi),%r10
	movq	72(%rsi),%r11
	movq	80(%rsi),%r12
	movq	88(%rsi),%r13
	addq	(%rsi),%r8
	adcq	8(%rsi),%r9
	adcq	16(%rsi),%r10
	adcq	24(%rsi),%r11
	adcq	32(%rsi),%r12
	adcq	40(%rsi),%r13
	movq	%r8,48(%rcx)
	movq	%r9,56(%rcx)
	movq	%r10,64(%rcx)
	movq	%r11,72(%rcx)
	movq	%r12,80(%rcx)
	movq	%r13,88(%rcx)
	sbbq	$0,%rdx
	movq	%rax,80(%rsp)
	movq	%rdx,88(%rsp)

// (rsp[0-8],r10,r8,r9) <- (AH+AL)*(BH+BL)
	movq	(%rcx),%r11
	movq	%r8,%rax
	mulq	%r11
	movq	%rax,(%rsp)				// c0
	movq	%rdx,%r14

	xorq	%r15,%r15
	movq	%r9,%rax
	mulq	%r11
	xorq	%r9,%r9
	addq	%rax,%r14
	adcq	%rdx,%r9

	movq	8(%rcx),%r12
	movq	%r8,%rax
	mulq	%r12
	addq	%rax,%r14
	movq	%r14,8(%rsp)			// c1
	adcq	%rdx,%r9
	adcq	$0,%r15

	xorq	%r8,%r8
	movq	%r10,%rax
	mulq	%r11
	addq	%rax,%r9
	movq	48(%rcx),%r13
	adcq	%rdx,%r15
	adcq	$0,%r8

	movq	16(%rcx),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r15
	movq	56(%rcx),%rax
	adcq	$0,%r8

	mulq	%r12
	addq	%rax,%r9
	movq	%r9,16(%rsp)			// c2
	adcq	%rdx,%r15
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	72(%rcx),%rax
	mulq	%r11
	addq	%rax,%r15
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	24(%rcx),%rax
	mulq	%r13
	addq	%rax,%r15
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	%r10,%rax
	mulq	%r12
	addq	%rax,%r15
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	16(%rcx),%r14
	movq	56(%rcx),%rax
	mulq	%r14
	addq	%rax,%r15
	movq	%r15,24(%rsp)			// c3
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	80(%rcx),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	64(%rcx),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	48(%rcx),%r15
	movq	32(%rcx),%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	72(%rcx),%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	24(%rcx),%r13
	movq	56(%rcx),%rax
	mulq	%r13
	addq	%rax,%r8
	movq	%r8,32(%rsp)			// c4
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	88(%rcx),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	64(%rcx),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	72(%rcx),%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	40(%rcx),%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	80(%rcx),%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	32(%rcx),%r15
	movq	56(%rcx),%rax
	mulq	%r15
	addq	%rax,%r9
	movq	%r9,40(%rsp)			// c5
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	64(%rcx),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	88(%rcx),%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	80(%rcx),%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	40(%rcx),%r11
	movq	56(%rcx),%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	72(%rcx),%rax
	mulq	%r13
	addq	%rax,%r10
	movq	%r10,48(%rsp)			// c6
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	88(%rcx),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	64(%rcx),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	80(%rcx),%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	72(%rcx),%rax
	mulq	%r15
	addq	%rax,%r8
	movq	%r8,56(%rsp)			// c7
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	72(%rcx),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	80(%rcx),%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	88(%rcx),%rax
	mulq	%r13
	addq	%rax,%r9
	movq	%r9,64(%rsp)			// c8
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	88(%rcx),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	80(%rcx),%rax
	mulq	%r11
	addq	%rax,%r10					// c9
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	88(%rcx),%rax
	mulq	%r11
	addq	%rax,%r8					// c10
	adcq	%rdx,%r9					// c11

	movq	88(%rsp),%rax
	movq	(%rcx),%rdx
	andq	%rax,%r12
	andq	%rax,%r14
	andq	%rax,%rdx
	andq	%rax,%r13
	andq	%rax,%r15
	andq	%rax,%r11
	movq	48(%rsp),%rax
	addq	%rax,%rdx
	movq	56(%rsp),%rax
	adcq	%rax,%r12
	movq	64(%rsp),%rax
	adcq	%rax,%r14
	adcq	%r10,%r13
	adcq	%r8,%r15
	adcq	%r9,%r11
	movq	80(%rsp),%rax
	movq	%rdx,48(%rsp)
	movq	%r12,56(%rsp)
	movq	%r14,64(%rsp)
	movq	%r13,72(%rsp)
	movq	%r15,80(%rsp)
	movq	%r11,88(%rsp)

	movq	48(%rcx),%r8
	movq	56(%rcx),%r9
	movq	64(%rcx),%r10
	movq	72(%rcx),%r11
	movq	80(%rcx),%r12
	movq	88(%rcx),%r13
	andq	%rax,%r8
	andq	%rax,%r9
	andq	%rax,%r10
	andq	%rax,%r11
	andq	%rax,%r12
	andq	%rax,%r13
	movq	48(%rsp),%rax
	addq	%rax,%r8
	movq	56(%rsp),%rax
	adcq	%rax,%r9
	movq	64(%rsp),%rax
	adcq	%rax,%r10
	movq	72(%rsp),%rax
	adcq	%rax,%r11
	movq	80(%rsp),%rax
	adcq	%rax,%r12
	movq	88(%rsp),%rax
	adcq	%rax,%r13
	movq	%r8,48(%rsp)
	movq	%r9,56(%rsp)
	movq	%r11,72(%rsp)

// rcx[0-11] <- AL*BL
	movq	(%rdi),%r11
	movq	(%rsi),%rax
	mulq	%r11
	xorq	%r9,%r9
	movq	%rax,(%rcx)				// c0
	movq	%r10,64(%rsp)
	movq	%rdx,%r8

	movq	8(%rsi),%rax
	mulq	%r11
	xorq	%r10,%r10
	addq	%rax,%r8
	movq	%r12,80(%rsp)
	adcq	%rdx,%r9

	movq	8(%rdi),%r12
	movq	(%rsi),%rax
	mulq	%r12
	addq	%rax,%r8
	movq	%r8,8(%rcx)				// c1
	adcq	%rdx,%r9
	movq	%r13,88(%rsp)
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	16(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	(%rsi),%r13
	movq	16(%rdi),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	8(%rsi),%rax
	mulq	%r12
	addq	%rax,%r9
	movq	%r9,16(%rcx)			// c2
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	24(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	24(%rdi),%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	16(%rsi),%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	16(%rdi),%r14
	movq	8(%rsi),%rax
	mulq	%r14
	addq	%rax,%r10
	movq	%r10,24(%rcx)			// c3
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	32(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	16(%rsi),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	32(%rdi),%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	24(%rsi),%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	24(%rdi),%r13
	movq	8(%rsi),%rax
	mulq	%r13
	addq	%rax,%r8
	movq	%r8,32(%rcx)			// c4
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	40(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	16(%rsi),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	24(%rsi),%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	40(%rdi),%r11
	movq	(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	32(%rsi),%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	32(%rdi),%r15
	movq	8(%rsi),%rax
	mulq	%r15
	addq	%rax,%r9
	movq	%r9,40(%rcx)			// c5
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	16(%rsi),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	40(%rsi),%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	32(%rsi),%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	8(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	24(%rsi),%rax
	mulq	%r13
	addq	%rax,%r10
	movq	%r10,48(%rcx)			// c6
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	40(%rsi),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	16(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	32(%rsi),%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	24(%rsi),%rax
	mulq	%r15
	addq	%rax,%r8
	movq	%r8,56(%rcx)			// c7
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	24(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	32(%rsi),%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	40(%rsi),%rax
	mulq	%r13
	addq	%rax,%r9
	movq	%r9,64(%rcx)			// c8
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	40(%rsi),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	32(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	movq	%r10,72(%rcx)			// c9
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	40(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	movq	%r8,80(%rcx)			// c10
	adcq	%rdx,%r9
	movq	%r9,88(%rcx)			// c11

// rcx[12-23] <- AH*BH
	movq	48(%rdi),%r11
	movq	48(%rsi),%rax
	mulq	%r11
	xorq	%r9,%r9
	movq	%rax,96(%rcx)			// c0
	movq	%rdx,%r8

	movq	56(%rsi),%rax
	mulq	%r11
	xorq	%r10,%r10
	addq	%rax,%r8
	adcq	%rdx,%r9

	movq	56(%rdi),%r12
	movq	48(%rsi),%rax
	mulq	%r12
	addq	%rax,%r8
	movq	%r8,104(%rcx)			// c1
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	64(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	48(%rsi),%r13
	movq	64(%rdi),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	56(%rsi),%rax
	mulq	%r12
	addq	%rax,%r9
	movq	%r9,112(%rcx)			// c2
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	72(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	72(%rdi),%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	64(%rsi),%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	64(%rdi),%r14
	movq	56(%rsi),%rax
	mulq	%r14
	addq	%rax,%r10
	movq	%r10,120(%rcx)		// c3
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	80(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	64(%rsi),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	80(%rdi),%r15
	movq	%r13,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	72(%rsi),%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	72(%rdi),%r13
	movq	56(%rsi),%rax
	mulq	%r13
	addq	%rax,%r8
	movq	%r8,128(%rcx)			// c4
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	88(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	64(%rsi),%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	72(%rsi),%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	88(%rdi),%r11
	movq	48(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	80(%rsi),%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	56(%rsi),%rax
	mulq	%r15
	addq	%rax,%r9
	movq	%r9,136(%rcx)			// c5
	adcq	%rdx,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movq	64(%rsi),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	88(%rsi),%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	80(%rsi),%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	56(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	72(%rsi),%rax
	mulq	%r13
	addq	%rax,%r10
	movq	%r10,144(%rcx)		// c6
	adcq	%rdx,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movq	88(%rsi),%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	64(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	80(%rsi),%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	72(%rsi),%rax
	mulq	%r15
	addq	%rax,%r8
	movq	%r8,152(%rcx)			// c7
	adcq	%rdx,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movq	72(%rsi),%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	80(%rsi),%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	88(%rsi),%rax
	mulq	%r13
	addq	%rax,%r9
	movq	%r9,160(%rcx)			// c8
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	88(%rsi),%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8

	movq	80(%rsi),%rax
	mulq	%r11
	addq	%rax,%r10
	movq	%r10,168(%rcx)		// c9
	adcq	%rdx,%r8

	movq	88(%rsi),%rax
	mulq	%r11
	addq	%rax,%r8
	movq	%r8,176(%rcx)			// c10
	adcq	$0,%rdx
	movq	%rdx,184(%rcx)		// c11

// [r8-r15,rax,rdx,rdi,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL
	movq	(%rsp),%r8
	subq	(%rcx),%r8
	movq	8(%rsp),%r9
	sbbq	8(%rcx),%r9
	movq	16(%rsp),%r10
	sbbq	16(%rcx),%r10
	movq	24(%rsp),%r11
	sbbq	24(%rcx),%r11
	movq	32(%rsp),%r12
	sbbq	32(%rcx),%r12
	movq	40(%rsp),%r13
	sbbq	40(%rcx),%r13
	movq	48(%rsp),%r14
	sbbq	48(%rcx),%r14
	movq	56(%rsp),%r15
	sbbq	56(%rcx),%r15
	movq	64(%rsp),%rax
	sbbq	64(%rcx),%rax
	movq	72(%rsp),%rdx
	sbbq	72(%rcx),%rdx
	movq	80(%rsp),%rdi
	sbbq	80(%rcx),%rdi
	movq	88(%rsp),%rsi
	sbbq	88(%rcx),%rsi
	movq	%rsi,(%rsp)

// [r8-r15,rax,rdx,rdi,[rsp]] <- (AH+AL)*(BH+BL) - AL*BL - AH*BH
	movq	96(%rcx),%rsi
	subq	%rsi,%r8
	movq	104(%rcx),%rsi
	sbbq	%rsi,%r9
	movq	112(%rcx),%rsi
	sbbq	%rsi,%r10
	movq	120(%rcx),%rsi
	sbbq	%rsi,%r11
	movq	128(%rcx),%rsi
	sbbq	%rsi,%r12
	movq	136(%rcx),%rsi
	sbbq	%rsi,%r13
	movq	144(%rcx),%rsi
	sbbq	%rsi,%r14
	movq	152(%rcx),%rsi
	sbbq	%rsi,%r15
	movq	160(%rcx),%rsi
	sbbq	%rsi,%rax
	movq	168(%rcx),%rsi
	sbbq	%rsi,%rdx
	movq	176(%rcx),%rsi
	sbbq	%rsi,%rdi
	movq	(%rsp),%rsi
	sbbq	184(%rcx),%rsi

// Final result
	addq	48(%rcx),%r8
	movq	%r8,48(%rcx)
	adcq	56(%rcx),%r9
	movq	%r9,56(%rcx)
	adcq	64(%rcx),%r10
	movq	%r10,64(%rcx)
	adcq	72(%rcx),%r11
	movq	%r11,72(%rcx)
	adcq	80(%rcx),%r12
	movq	%r12,80(%rcx)
	adcq	88(%rcx),%r13
	movq	%r13,88(%rcx)
	adcq	96(%rcx),%r14
	movq	%r14,96(%rcx)
	adcq	104(%rcx),%r15
	movq	%r15,104(%rcx)
	adcq	112(%rcx),%rax
	movq	%rax,112(%rcx)
	adcq	120(%rcx),%rdx
	movq	%rdx,120(%rcx)
	adcq	128(%rcx),%rdi
	movq	%rdi,128(%rcx)
	adcq	136(%rcx),%rsi
	movq	%rsi,136(%rcx)
	movq	144(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,144(%rcx)
	movq	152(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,152(%rcx)
	movq	160(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,160(%rcx)
	movq	168(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,168(%rcx)
	movq	176(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,176(%rcx)
	movq	184(%rcx),%rax
	adcq	$0,%rax
	movq	%rax,184(%rcx)

	addq	$96,%rsp					// Restoring space in stack
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size mul751_asm,.-mul751_asm


//  Montgomery reduction
//  Based on comba method
//  Operation: c [%rsi] = a [%rdi]
//  NOTE: a=c is not allowed
.globl	rdc751_asm
rdc751_asm:
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	(%rdi),%r11
	movabs	$p751p1_5,%rax
	mulq	%r11
	xorq	%r8,%r8
	addq	40(%rdi),%rax
	movq	%rax,40(%rsi)			// z5
	adcq	%rdx,%r8

	xorq	%r9,%r9
	movabs	$p751p1_6,%rax
	mulq	%r11
	xorq	%r10,%r10
	addq	%rax,%r8
	adcq	%rdx,%r9

	movq	8(%rdi),%r12
	movabs	$p751p1_5,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	48(%rdi),%r8
	movq	%r8,48(%rsi)			// z6
	adcq	$0,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movabs	$p751p1_7,%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_6,%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	16(%rdi),%r13
	movabs	$p751p1_5,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8
	addq	56(%rdi),%r9
	movq	%r9,56(%rsi)			// z7
	adcq	$0,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movabs	$p751p1_8,%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_7,%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_6,%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	24(%rdi),%r14
	movabs	$p751p1_5,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9
	addq	64(%rdi),%r10
	movq	%r10,64(%rsi)			// z8
	adcq	$0,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movabs	$p751p1_9,%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_8,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_7,%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_6,%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	32(%rdi),%r15
	movabs	$p751p1_5,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	72(%rdi),%r8
	movq	%r8,72(%rsi)			// z9
	adcq	$0,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movabs	$p751p1_10,%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_9,%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_8,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_7,%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_6,%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	40(%rsi),%rcx
	movabs	$p751p1_5,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8
	addq	80(%rdi),%r9
	movq	%r9,80(%rsi)			// z10
	adcq	$0,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movabs	$p751p1_11,%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_10,%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_9,%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_8,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_7,%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_6,%rax
	mulq	%rcx
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	48(%rsi),%r11
	movabs	$p751p1_5,%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9
	addq	88(%rdi),%r10
	movq	%r10,88(%rsi)			// z11
	adcq	$0,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movabs	$p751p1_11,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_10,%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_9,%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_8,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_7,%rax
	mulq	%rcx
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_6,%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	56(%rsi),%r12
	movabs	$p751p1_5,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	96(%rdi),%r8
	movq	%r8,(%rsi)				// z0
	adcq	$0,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movabs	$p751p1_11,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_10,%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_9,%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_8,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_7,%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_6,%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	64(%rsi),%r13
	movabs	$p751p1_5,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8
	addq	104(%rdi),%r9
	movq	%r9,8(%rsi)				// z1
	adcq	$0,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movabs	$p751p1_11,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_10,%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_9,%rax
	mulq	%rcx
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_8,%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_7,%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_6,%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movq	72(%rsi),%r14
	movabs	$p751p1_5,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9
	addq	112(%rdi),%r10
	movq	%r10,16(%rsi)			// z2
	adcq	$0,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movabs	$p751p1_11,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_10,%rax
	mulq	%rcx
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_9,%rax
	mulq	%r11
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_8,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_7,%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_6,%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movq	80(%rsi),%r15
	movabs	$p751p1_5,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	120(%rdi),%r8
	movq	%r8,24(%rsi)			// z3
	adcq	$0,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movabs	$p751p1_11,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_10,%rax
	mulq	%r11
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_9,%rax
	mulq	%r12
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_8,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_7,%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_6,%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movq	88(%rsi),%rcx
	movabs	$p751p1_5,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8
	addq	128(%rdi),%r9
	movq	%r9,32(%rsi)			// z4
	adcq	$0,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movabs	$p751p1_11,%rax
	mulq	%r11
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_10,%rax
	mulq	%r12
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_9,%rax
	mulq	%r13
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_8,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_7,%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_6,%rax
	mulq	%rcx
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9
	addq	136(%rdi),%r10
	movq	%r10,40(%rsi)			// z5
	adcq	$0,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movabs	$p751p1_11,%rax
	mulq	%r12
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_10,%rax
	mulq	%r13
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_9,%rax
	mulq	%r14
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_8,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_7,%rax
	mulq	%rcx
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	144(%rdi),%r8
	movq	%r8,48(%rsi)			// z6
	adcq	$0,%r9
	adcq	$0,%r10

	xorq	%r8,%r8
	movabs	$p751p1_11,%rax
	mulq	%r13
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_10,%rax
	mulq	%r14
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_9,%rax
	mulq	%r15
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8

	movabs	$p751p1_8,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	adcq	$0,%r8
	addq	152(%rdi),%r9
	movq	%r9,56(%rsi)			// z7
	adcq	$0,%r10
	adcq	$0,%r8

	xorq	%r9,%r9
	movabs	$p751p1_11,%rax
	mulq	%r14
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_10,%rax
	mulq	%r15
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9

	movabs	$p751p1_9,%rax
	mulq	%rcx
	addq	%rax,%r10
	adcq	%rdx,%r8
	adcq	$0,%r9
	addq	160(%rdi),%r10
	movq	%r10,64(%rsi)			// z8
	adcq	$0,%r8
	adcq	$0,%r9

	xorq	%r10,%r10
	movabs	$p751p1_11,%rax
	mulq	%r15
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10

	movabs	$p751p1_10,%rax
	mulq	%rcx
	addq	%rax,%r8
	adcq	%rdx,%r9
	adcq	$0,%r10
	addq	168(%rdi),%r8			// z9
	movq	%r8,72(%rsi)			// z9
	adcq	$0,%r9
	adcq	$0,%r10

	movabs	$p751p1_11,%rax
	mulq	%rcx
	addq	%rax,%r9
	adcq	%rdx,%r10
	addq	176(%rdi),%r9			// z10
	movq	%r9,80(%rsi)			// z10
	adcq	$0,%r10
	addq	184(%rdi),%r10		// z11
	movq	%r10,88(%rsi)			// z11

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size	rdc751_asm,.-rdc751_asm

//  751-bit multiprecision addition
//  Operation: c [rdx] = a [rdi] + b [rsi]
.globl	mp_add751_asm
mp_add751_asm:
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushq	%rbx

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	64(%rdi),%rax
	movq	72(%rdi),%rbx
	movq	80(%rdi),%rcx
	movq	88(%rdi),%rdi

	addq	(%rsi),%r8
	adcq	8(%rsi),%r9
	adcq	16(%rsi),%r10
	adcq	24(%rsi),%r11
	adcq	32(%rsi),%r12
	adcq	40(%rsi),%r13
	adcq	48(%rsi),%r14
	adcq	56(%rsi),%r15
	adcq	64(%rsi),%rax
	adcq	72(%rsi),%rbx
	adcq	80(%rsi),%rcx
	adcq	88(%rsi),%rdi

	movq	%r8,(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%r14,48(%rdx)
	movq	%r15,56(%rdx)
	movq	%rax,64(%rdx)
	movq	%rbx,72(%rdx)
	movq	%rcx,80(%rdx)
	movq	%rdi,88(%rdx)

	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size	mp_add751_asm,.-mp_add751_asm

//  2x751-bit multiprecision addition
//  Operation: c [rdx] = a [rdi] + b [rsi]
.globl	mp_add751x2_asm
mp_add751x2_asm:
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	64(%rdi),%rax
	movq	72(%rdi),%rbx
	movq	80(%rdi),%rcx

	addq	(%rsi),%r8
	adcq	8(%rsi),%r9
	adcq	16(%rsi),%r10
	adcq	24(%rsi),%r11
	adcq	32(%rsi),%r12
	adcq	40(%rsi),%r13
	adcq	48(%rsi),%r14
	adcq	56(%rsi),%r15
	adcq	64(%rsi),%rax
	adcq	72(%rsi),%rbx
	adcq	80(%rsi),%rcx

	movq	%r8,(%rdx)
	movq	%r9,8(%rdx)
	movq	%r10,16(%rdx)
	movq	%r11,24(%rdx)
	movq	%r12,32(%rdx)
	movq	%r13,40(%rdx)
	movq	%r14,48(%rdx)
	movq	%r15,56(%rdx)
	movq	%rax,64(%rdx)
	movq	%rbx,72(%rdx)
	movq	%rcx,80(%rdx)
	movq	88(%rdi),%rax
	adcq	88(%rsi),%rax
	movq	%rax,88(%rdx)

	movq	96(%rdi),%r8
	movq	104(%rdi),%r9
	movq	112(%rdi),%r10
	movq	120(%rdi),%r11
	movq	128(%rdi),%r12
	movq	136(%rdi),%r13
	movq	144(%rdi),%r14
	movq	152(%rdi),%r15
	movq	160(%rdi),%rax
	movq	168(%rdi),%rbx
	movq	176(%rdi),%rcx
	movq	184(%rdi),%rdi

	adcq	96(%rsi),%r8
	adcq	104(%rsi),%r9
	adcq	112(%rsi),%r10
	adcq	120(%rsi),%r11
	adcq	128(%rsi),%r12
	adcq	136(%rsi),%r13
	adcq	144(%rsi),%r14
	adcq	152(%rsi),%r15
	adcq	160(%rsi),%rax
	adcq	168(%rsi),%rbx
	adcq	176(%rsi),%rcx
	adcq	184(%rsi),%rdi

	movq	%r8,96(%rdx)
	movq	%r9,104(%rdx)
	movq	%r10,112(%rdx)
	movq	%r11,120(%rdx)
	movq	%r12,128(%rdx)
	movq	%r13,136(%rdx)
	movq	%r14,144(%rdx)
	movq	%r15,152(%rdx)
	movq	%rax,160(%rdx)
	movq	%rbx,168(%rdx)
	movq	%rcx,176(%rdx)
	movq	%rdi,184(%rdx)

	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	retq
.size	mp_add751x2_asm,.-mp_add751x2_asm
