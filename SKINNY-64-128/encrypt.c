/*
 * SKINNY-64-128
 * @Time 2017
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
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    /* r14-r21  : plain text                */
    /* r22-r23  : temp use                  */
    /* r24      : loop control              */
    /* r25      : const 0x02                */
    /* r26-r27  : X points to plain text    */
    /* r28-r29  : Y points to roundKeys     */
    /* r30-r31  : Z points to SBOX          */
    /* -------------------------------------*/
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
        "push        r14        \n\t"
        "push        r15        \n\t"
        "push        r16        \n\t"
        "push        r17        \n\t"
        "push        r28        \n\t"
        "push        r29        \n\t"
        // load plain text
        "ld          r14,         x+        \n\t"
        "ld          r15,         x+        \n\t"
        "ld          r16,         x+        \n\t"
        "ld          r17,         x+        \n\t"
        "ld          r18,         x+        \n\t"
        "ld          r19,         x+        \n\t"
        "ld          r20,         x+        \n\t"
        "ld          r21,         x         \n\t"
        // set currentRound
        "ldi         r24,         32        \n\t"
        // used for constant 0x02
        "ldi         r25,         0x02      \n\t"
        "ldi         r31,         hi8(SBOX) \n\t"
        // encryption
    "enc_loop:                              \n\t"
        // SubColumn
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi         r31,         hi8(SBOX) \n\t"
        #endif
        "mov         r30,         r14       \n\t"
        "lpm         r14,         z         \n\t"
        "mov         r30,         r15       \n\t"
        "lpm         r15,         z         \n\t"
        "mov         r30,         r16       \n\t"
        "lpm         r16,         z         \n\t"
        "mov         r30,         r17       \n\t"
        "lpm         r17,         z         \n\t"
        "mov         r30,         r18       \n\t"
        "lpm         r18,         z         \n\t"
        "mov         r30,         r19       \n\t"
        "lpm         r19,         z         \n\t"
        "mov         r30,         r20       \n\t"
        "lpm         r20,         z         \n\t"
        "mov         r30,         r21       \n\t"
        "lpm         r21,         z         \n\t"
        // AddRoundConstant and AddRoundKeys
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "movw        r30,         r28       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r14,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r15,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r16,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r17,         r22       \n\t"
        "eor         r18,         r25       \n\t"
        "movw        r28,         r30       \n\t"
        #else
        "ld          r22,         y+        \n\t"
        "eor         r14,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r15,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r16,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r17,         r22       \n\t"
        "eor         r18,         r25       \n\t"
        #endif
        // ShiftRow, but the third line is unchanged
        "swap        r16                    \n\t"
        "swap        r17                    \n\t"
        "mov         r22,         r16       \n\t"
        "eor         r22,         r17       \n\t"
        "andi        r22,         0xf0      \n\t"
        "eor         r16,         r22       \n\t"
        "eor         r17,         r22       \n\t"
        "swap        r20                    \n\t"
        "swap        r21                    \n\t"
        "mov         r22,         r20       \n\t"
        "eor         r22,         r21       \n\t"
        "andi        r22,         0x0f      \n\t"
        "eor         r20,         r22       \n\t"
        "eor         r21,         r22       \n\t"       
        // MixColumn
        "eor         r16,         r19       \n\t"
        "eor         r19,         r14       \n\t"
        "eor         r20,         r19       \n\t"
        "eor         r17,         r18       \n\t"
        "eor         r18,         r15       \n\t"
        "eor         r21,         r18       \n\t"
        "movw        r22,         r14       \n\t"
        "movw        r14,         r20       \n\t"
        "mov         r20,         r19       \n\t"
        "mov         r21,         r18       \n\t"
        "movw        r18,         r16       \n\t"
        "movw        r16,         r22       \n\t"       
    "dec             r24                    \n\t"
    "brne            enc_loop               \n\t"
        // store cipher text
        "st          x,           r23       \n\t"
        "st          -x,          r22       \n\t"
        "st          -x,          r21       \n\t"
        "st          -x,          r20       \n\t"
        "st          -x,          r19       \n\t"
        "st          -x,          r18       \n\t"
        "st          -x,          r17       \n\t"
        "st          -x,          r16       \n\t"
        // --------------------------------------
        "pop         r29        \n\t"
        "pop         r28        \n\t"
        "pop         r17        \n\t"
        "pop         r16        \n\t"
        "pop         r15        \n\t"
        "pop         r14        \n\t"
    :
    : [block] "x" (block), [roundKeys] "y" (roundKeys), [SBOX] "" (SBOX));
}

#elif defined MSP
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
}

#elif defined ARM
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
}

#else
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* Add here the cipher encryption implementation */
}

#endif
