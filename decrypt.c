/*
 * SKINNY-128-128
 * @Time 2016
 * @Author luopeng(luopeng@iie.ac.cn)
 */

/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>

#include "cipher.h"
#include "constants.h"

#ifdef AVR
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*--------------------------------------*/
	/* r6-r7    : temp use                  */
	/* r8-r23   : cipher text               */
	/* r24      : loop control              */
	/* r25      : const 0x02                */
	/* r26-r27  : X points to plain text    */
	/* r30-r31  : Z points to roundKeys     */
	/* -------------------------------------*/
	// s0  s1  s2  s3       r8  r9  r10 r11
	// s4  s5  s6  s7   =   r12 r13 r14 r15
	// s8  s9  s10 s11  =   r16 r17 r18 r19
	// s12 s13 s14 s15      r20 r21 r22 r23
	asm volatile(
	/*
	 * http://www.atmel.com/webdoc/AVRLibcReferenceManual/FAQ_1faq_reg_usage.html
	 * 
	 * GCC AVR passes arguments from left to right in r25-r8.
	 * All arguments are aligned to start in even-numbered registers. 
	 * Pointers are 16-bits, so arguments are in r25:r24 and r23:22
	 * 
	 * [r18-r27, r30-r31]: You may use them freely in assembler subroutines.
	 *     The caller is responsible for saving and restoring.
	 * [r2-r17, r28-r29]: Calling C subroutines leaves them unchanged.
	 *     Assembler subroutines are responsible for saving and restoring these registers.
	 * [r0, r1]: Fixed registers. Never allocated by gcc for local data.
	 */
		"push        r6         \n\t"
		"push        r7         \n\t"
		"push        r8         \n\t"
		"push        r9         \n\t"
		"push        r10        \n\t"
		"push        r11        \n\t"
		"push        r12        \n\t"
		"push        r13        \n\t"
		"push        r14        \n\t"
		"push        r15        \n\t"
		"push        r16        \n\t"
		"push        r17        \n\t"
		"push        r28        \n\t"
		"push        r29        \n\t"
		// load plain text
		//                s0  s1  s2  s3
		//                s4  s5  s6  s7
		// Cipher State   s8  s9  s10 s11
		//                s12 s13 s14 s15
		"ld          r8,           x+        \n\t"
		"ld          r9,           x+        \n\t"
		"ld          r10,          x+        \n\t"
		"ld          r11,          x+        \n\t"
		"ld          r12,          x+        \n\t"
		"ld          r13,          x+        \n\t"
		"ld          r14,          x+        \n\t"
		"ld          r15,          x+        \n\t"
		"ld          r16,          x+        \n\t"
		"ld          r17,          x+        \n\t"
		"ld          r18,          x+        \n\t"
		"ld          r19,          x+        \n\t"
		"ld          r20,          x+        \n\t"
		"ld          r21,          x+        \n\t"
		"ld          r22,          x+        \n\t"
		"ld          r23,          x         \n\t"
		// set currentRound
		"ldi         r24,          40        \n\t"
		// used for const 0x02
		"ldi         r25,          0x02      \n\t"
		"ldi         r29,          hi8(SBOX_INV)\n\t"
		// encryption
	"dec_loop:                               \n\t"
		// mix column
		// eor s0, s12
		// eor s12, s4
		// eor s8, s12
		//                s4  s5  s6  s7
		//                s8  s9  s10 s11
		// Cipher State   s12 s13 s14 s15
		//                s0  s1  s2  s3
		// first column
		"eor         r8,          r20        \n\t"
		"eor         r20,         r12        \n\t"
		"eor         r16,         r20        \n\t"
		// second column
		"eor         r9,          r21        \n\t"
		"eor         r21,         r13        \n\t"
		"eor         r17,         r21        \n\t"
		// third column
		"eor         r10,         r22        \n\t"
		"eor         r22,         r14        \n\t"
		"eor         r18,         r22        \n\t"
		// fourth column
		"eor         r11,         r23        \n\t"
		"eor         r23,         r15        \n\t"
		"eor         r19,         r23        \n\t"
		// shift row, add_round_const_round_key
		//                s4  s5  s6  s7
		//                s9  s10 s11 s8
		// Cipher State   s14 s15 s12 s13
		//                s3  s0  s1  s2
		"ld          r6,          z+         \n\t"
		"eor         r12,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r13,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r14,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r15,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r17,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r18,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r19,         r6         \n\t"
		"ld          r6,          z+         \n\t"
		"eor         r16,         r6         \n\t"
		"eor         r22,         r25        \n\t"
		// shift_row_with_sub_column
		//                s4  s5  s6  s7       r12 r13 r14 r15
		//                s9  s10 s11 s8   =   r17 r18 r19 r16
		// Cipher State   s14 s15 s12 s13  =   r22 r23 r20 r21
		//                s3  s0  s1  s2       r11 r8  r9  r10
		"movw        r6,          r8         \n\t"
		"mov         r28,         r12        \n\t"
		"ld          r8,          y          \n\t"
		"mov         r28,         r17        \n\t"
		"ld          r12,         y          \n\t"
		"mov         r28,         r23        \n\t"
		"ld          r17,         y          \n\t"
		"mov         r28,         r10        \n\t"
		"ld          r23,         y          \n\t"
		"mov         r28,         r14        \n\t"
		"ld          r10,         y          \n\t"
		"mov         r28,         r19        \n\t"
		"ld          r14,         y          \n\t"
		"mov         r28,         r21        \n\t"
		"ld          r19,         y          \n\t"
		"mov         r28,         r8         \n\t"
		"ld          r21,         y          \n\t"
		// second pa  rt
		"mov          r28,        r13        \n\t"
		"ld          r9,          y          \n\t"
		"mov         r28,         r18        \n\t"
		"ld          r13,         y          \n\t"
		"mov         r28,         r20        \n\t"
		"ld          r18,         y          \n\t"
		"mov         r28,         r11        \n\t"
		"ld          r20,         y          \n\t"
		"mov         r28,         r15        \n\t"
		"ld          r11,         y          \n\t"
		"mov         r28,         r16        \n\t"
		"ld          r15,         y          \n\t"
		"mov         r28,         r22        \n\t"
		"ld          r16,         y          \n\t"
		"mov         r28,         r7         \n\t"
		"ld          r22,         y          \n\t"
		"dec         r24                     \n\t"
	"brne        enc_loop        \n\t"
		//                s0  s1  s2  s3       r8  r9  r10 r11
		//                s4  s5  s6  s7   =   r12 r13 r14 r15
		// Cipher State   s8  s9  s10 s11  =   r16 r17 r18 r19
		//                s12 s13 s14 s15      r20 r21 r22 r23
		// store cipher text
		"st          x-,          r23        \n\t"
		"st          x-,          r22        \n\t"
		"st          x-,          r21        \n\t"
		"st          x-,          r20        \n\t"
		"st          x-,          r19        \n\t"
		"st          x-,          r18        \n\t"
		"st          x-,          r17        \n\t"
		"st          x-,          r16        \n\t"
		"st          x-,          r15        \n\t"
		"st          x-,          r14        \n\t"
		"st          x-,          r13        \n\t"
		"st          x-,          r12        \n\t"
		"st          x-,          r11        \n\t"
		"st          x-,          r10        \n\t"
		"st          x-,          r9         \n\t"
		"st          x,           r8         \n\t"
		// --------------------------------------
		"pop         r29        \n\t"
		"pop         r28        \n\t"
		"pop         r17        \n\t"
		"pop         r16        \n\t"
		"pop         r15        \n\t"
		"pop         r14        \n\t"
		"pop         r13        \n\t"
		"pop         r12        \n\t"
		"pop         r11        \n\t"
		"pop         r10        \n\t"
		"pop         r9         \n\t"
		"pop         r8         \n\t"
		"pop         r7         \n\t"
		"pop         r6         \n\t"
	:
	: [block] "x" (block), [roundKeys] "z" (roundKeys), [SBOX_INV] "" (SBOX_INV));
}

#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/* Add here the cipher decryption implementation */
}
#endif
