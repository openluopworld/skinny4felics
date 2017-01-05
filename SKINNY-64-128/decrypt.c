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
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    /* r14-r21  : cipher text               */
    /* r22-r23  : temp use                  */
    /* r24      : loop control              */
    /* r25      : const 0x02                */
    /* r26-r27  : X points to cipher text   */
    /* r28-r29  : Y points to roundKeys     */
    /* r30-r31  : Z points to INV_SBOX      */
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
        "movw        r28,          r22       \n\t"
        // Load cipher text
        "ld          r14,          x+        \n\t"
        "ld          r15,          x+        \n\t"
        "ld          r16,          x+        \n\t"
        "ld          r17,          x+        \n\t"
        "ld          r18,          x+        \n\t"
        "ld          r19,          x+        \n\t"
        "ld          r20,          x+        \n\t"
        "ld          r21,          x         \n\t"
        // Init
        "ldi         r24,          140       \n\t"
        "clr         r25                     \n\t"
        "add         r28,          r24       \n\t"
        "adc         r29,          r25       \n\t"
        "ldi         r24,          36        \n\t"
        "ldi         r25,          0x02      \n\t"
        "ldi         r30,          hi8(INV_SBOX)\n\t"
    "dec_loop:                               \n\t"
        // Inverse MixColumn
        // eor s0,  s12
        // eor s12, s4
        // eor s8,  s12
        "eor         r14,         r20        \n\t"
        "eor         r20,         r16        \n\t"
        "eor         r18,         r20        \n\t"
        "eor         r15,         r21        \n\t"
        "eor         r21,         r17        \n\t"
        "eor         r19,         r21        \n\t"
        // Inverse ShiftRow
        "swap        r18                     \n\t"
        "swap        r19                     \n\t"
        "mov         r22,         r18        \n\t"
        "eor         r22,         r19        \n\t"
        "andi        r22,         0xf0       \n\t"
        "eor         r18,         r22        \n\t"
        "eor         r19,         r22        \n\t"
        "swap        r14                     \n\t"
        "swap        r15                     \n\t"
        "mov         r22,         r14        \n\t"
        "eor         r22,         r15        \n\t"
        "andi        r22,         0x0f       \n\t"
        "eor         r14,         r22        \n\t"
        "eor         r15,         r22        \n\t"
        // Inverse AddRoundKey and Inverse AddRondConstant
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "movw        r30,         r28        \n\t"
        "lpm         r22,         z+         \n\t"
        "eor         r16,         r22        \n\t"
        "lpm         r22,         z+         \n\t"
        "eor         r17,         r22        \n\t"
        "lpm         r22,         z+         \n\t"
        "eor         r18,         r22        \n\t"
        "lpm         r22,         z+         \n\t"
        "eor         r19,         r22        \n\t"
        "eor         r21,         r25        \n\t"
        "sbiw        r30,         8          \n\t"
        "movw        r28,         r30        \n\t"
        #else
        "ld          r22,         y+         \n\t"
        "eor         r16,         r22        \n\t"
        "ld          r22,         y+         \n\t"
        "eor         r17,         r22        \n\t"
        "ld          r22,         y+         \n\t"
        "eor         r18,         r22        \n\t"
        "ld          r22,         y+         \n\t"
        "eor         r19,         r22        \n\t"
        "eor         r21,         r25        \n\t"
        "sbiw        r28,         8          \n\t"
        #endif
        // Inverse SubColumn
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi         r31,         hi8(SBOX)  \n\t"
        #endif
        "movw        r22,         r14        \n\t"
        "mov         r30,         r16        \n\t"
        "lpm         r14,         z          \n\t"
        "mov         r30,         r17        \n\t"
        "lpm         r15,         z          \n\t"
        "mov         r30,         r18        \n\t"
        "lpm         r16,         z          \n\t"
        "mov         r30,         r19        \n\t"
        "lpm         r17,         z          \n\t"
        "mov         r30,         r21        \n\t"
        "lpm         r18,         z          \n\t"
        "mov         r30,         r20        \n\t"
        "lpm         r19,         z          \n\t"
        "mov         r30,         r22        \n\t"
        "lpm         r20,         z          \n\t"
        "mov         r30,         r23        \n\t"
        "lpm         r21,         z          \n\t"
    "dec             r24                     \n\t"
    "brne            dec_loop                \n\t"
        // Store cipher text
        "st          x,           r21        \n\t"
        "st          -x,          r20        \n\t"
        "st          -x,          r19        \n\t"
        "st          -x,          r18        \n\t"
        "st          -x,          r17        \n\t"
        "st          -x,          r16        \n\t"
        "st          -x,          r15        \n\t"
        "st          -x,          r14        \n\t"
        "pop         r29        \n\t"
        "pop         r28        \n\t"
        "pop         r17        \n\t"
        "pop         r16        \n\t"
        "pop         r15        \n\t"
        "pop         r14        \n\t"
    :
    : [block] "x" (block), [roundKeys] "" (roundKeys), [INV_SBOX] "" (INV_SBOX));
}

#elif defined MSP
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r4-r7   : cipher state                */
    /* r10-r12 : temp use                    */
    /* r13     : currentRound                */
    /* r14     : point to round keys         */
    /* r15     : point to block              */
    asm volatile(
        "push        r4         \n\t"
        "push        r5         \n\t"
        "push        r6         \n\t"
        "push        r7         \n\t"
        "push        r10        \n\t"
        "push        r11        \n\t"
        // Init
        "mov         #36,           r13      \n\t"
        "add         #140,          r14      \n\t"
        "mov         0(r15),        r4       \n\t"
        "mov         2(r15),        r5       \n\t"
        "mov         4(r15),        r6       \n\t"
        "mov         6(r15),        r7       \n\t"
    "dec_loop:                               \n\t"
        // Inverse MixColumn
        // xor s12, s0 
        // xor s4,  s12
        // xor s12, s8 
        "xor         r7,            r4       \n\t"
        "xor         r5,            r7       \n\t"
        "xor         r7,            r6       \n\t"
        // Inverse ShiftRows
        "bit         #1,            r6       \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,            r6       \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,            r6       \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,            r6       \n\t"
        "rrc         r6                      \n\t"
        "swpb        r7                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        //Inverse AddRoundKeys, Inverse AddConstant
        // and Inverse SubColumn
        "xor         @r14+,         r5       \n\t"
        "mov.b       r5,            r12      \n\t" 
        "mov.b       INV_SBOX(r12), r11      \n\t"
        "swpb        r5                      \n\t"
        "mov.b       r5,            r12      \n\t"
        "mov.b       INV_SBOX(r12), r10      \n\t"
        "swpb        r10                     \n\t"
        "xor         r11,           r10      \n\t" // first line
        "xor         @r14+,         r6       \n\t"
        "mov.b       r6,            r12      \n\t" 
        "mov.b       INV_SBOX(r12), r11      \n\t"
        "swpb        r6                      \n\t"
        "mov.b       r6,            r12      \n\t"
        "mov.b       INV_SBOX(r12), r5       \n\t"
        "swpb        r5                      \n\t"
        "xor         r11,           r5       \n\t" // second line
        "xor         #0x2,          r7       \n\t"
        "mov.b       r7,            r12      \n\t" 
        "mov.b       INV_SBOX(r12), r11      \n\t"
        "swpb        r7                      \n\t"
        "mov.b       r7,            r12      \n\t"
        "mov.b       INV_SBOX(r12), r6       \n\t"
        "swpb        r6                      \n\t"
        "xor         r11,           r6       \n\t" // third line
        "mov.b       r4,            r12      \n\t" 
        "mov.b       INV_SBOX(r12), r11      \n\t"
        "swpb        r4                      \n\t"
        "mov.b       r4,            r12      \n\t"
        "mov.b       INV_SBOX(r12), r7       \n\t"
        "swpb        r7                      \n\t"
        "xor         r11,           r7       \n\t" // fourth line        
        "mov         r10,           r4       \n\t"
        "sub         #8,            r14      \n\t"  
    "dec             r13                     \n\t"
    "jne             dec_loop                \n\t"
        "pop         r11        \n\t"
        "pop         r10        \n\t"
        "pop         r7         \n\t"
        "pop         r6         \n\t"
        "pop         r5         \n\t"
        "pop         r4         \n\t"
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys), [INV_SBOX] "" (INV_SBOX));
}

#elif defined ARM
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
}

#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* Add here the cipher decryption implementation */
}

#endif
