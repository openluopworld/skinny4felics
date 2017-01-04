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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    // Round keys and round constants are eor-ed
    // and stored together
    /* r5      : 0x0f                       */
    /* r6,r7,r24,r25 : temp                 */
    /* r8-r23  : master keys                */
    /* r26     : loop control               */
    /* r27     : 0xf0                       */
    /* r26-r27 : X points to master keys    */
    /* r28-r29 : Y points to roundKeys      */
    /* r30-r31 : Z points to RC             */
    /* -------------------------------------*/
    asm volatile(
    	"push         r5         \n\t"
        "push         r6         \n\t"
        "push         r7         \n\t"
        "push         r8         \n\t"
        "push         r9         \n\t"
        "push         r10        \n\t"
        "push         r11        \n\t"
        "push         r12        \n\t"
        "push         r13        \n\t"
        "push         r14        \n\t"
        "push         r15        \n\t"
        "push         r16        \n\t"
        "push         r17        \n\t"
        "push         r28        \n\t"
        "push         r29        \n\t"
        "movw         r26,        r24       \n\t"
        "movw         r28,        r22       \n\t"
        // Load keys
        // Tweak1        Tweak2
        // r8  r9        r16 r17
        // r10 r11       r18 r19
        // r12 r13       r20 r21
        // r14 r15       r22 r23
        // 
        "ld           r8,         x+        \n\t"
        "ld           r9,         x+        \n\t"
        "ld           r10,        x+        \n\t"
        "ld           r11,        x+        \n\t"
        "ld           r12,        x+        \n\t"
        "ld           r13,        x+        \n\t"
        "ld           r14,        x+        \n\t"
        "ld           r15,        x+        \n\t"
        "ld           r16,        x+        \n\t"
        "ld           r17,        x+        \n\t"
        "ld           r18,        x+        \n\t"
        "ld           r19,        x+        \n\t"
        "ld           r20,        x+        \n\t"
        "ld           r21,        x+        \n\t"
        "ld           r22,        x+        \n\t"
        "ld           r23,        x+        \n\t"
        // Init
        "ldi          r26,        36        \n\t"
        "ldi          r27,        0x0f      \n\t"
        "mov          r5,         r27       \n\t"
        "ldi          r27,        0xf0      \n\t"
        "ldi          r30,        lo8(RC)   \n\t"
        "ldi          r31,        hi8(RC)   \n\t"
    "key_schedule_start:                    \n\t"
        // XOR RoundConstant and the TweakKeys together
        "lpm          r24,        z+        \n\t"
        "mov          r25,        r24       \n\t"
        "andi         r25,        0x0f      \n\t" // store k0
        "mov          r6,         r8        \n\t"
        "eor          r6,         r25       \n\t"
        "eor          r6,         r16       \n\t"
        "st           y+,         r6        \n\t"
        "mov          r6,         r9        \n\t" // store k1
        "eor          r6,         r17       \n\t"
        "st           y+,         r6        \n\t"
        "andi         r24,        0x30      \n\t" // store k2
        "swap         r24                   \n\t"
        "mov          r6,         r10       \n\t"
        "eor          r6,         r24       \n\t"
        "eor          r6,         r18       \n\t"
        "st           y+,         r6        \n\t"
        "mov          r6,         r11       \n\t" // store k3
        "eor          r6,         r19       \n\t"
        "st           y+,         r6        \n\t"        
    "dec              r26                   \n\t"
    "brne             again                 \n\t"
    "rjmp             key_schedule_exit     \n\t"
    "again:                                 \n\t"
        // (k1  k0 ) (k3  k2 )        (k15 k9 ) (k13 k8 )
        // (k5  k4 ) (k7  k6 )        (k14 k10) (k11 k12)
        // (k9  k8 ) (k11 k10) -----> (k1  k0 ) (k3  k2 )
        // (k13 k12) (k15 k14)        (k5  k4 ) (k7  k6 )
        // Tweak1
        "movw         r6,         r12       \n\t"
        "movw         r12,        r8        \n\t"
        "movw         r8,         r14       \n\t"
        "movw         r14,        r10       \n\t"
        "mov          r11,        r7        \n\t"
        "and          r11,        r27       \n\t"
        "mov          r10,        r8        \n\t"
        "and          r10,        r5        \n\t"
        "eor          r11,        r10       \n\t"
        "mov          r10,        r7        \n\t"
        "and          r10,        r5        \n\t"
        "mov          r7,         r9        \n\t"
        "and          r7,         r5        \n\t"
        "swap         r7                    \n\t"
        "eor          r10,        r7        \n\t"
        "mov          r7,         r8        \n\t"
        "and          r7,         r27       \n\t"
        "mov          r8,         r6        \n\t"
        "and          r6,         r5        \n\t"
        "eor          r7,         r6        \n\t"
        "swap         r8                    \n\t"
        "and          r8,         r5        \n\t"
        "and          r9,         r27       \n\t"
        "eor          r8,         r9        \n\t"
        "mov          r9,         r7        \n\t"
        // Tweak2
        "movw         r6,         r20       \n\t"
        "movw         r20,        r16       \n\t"
        "movw         r16,        r22       \n\t"
        "movw         r22,        r18       \n\t"
        "mov          r19,        r7        \n\t"
        "and          r19,        r27       \n\t"
        "mov          r18,        r16       \n\t"
        "and          r18,        r5        \n\t"
        "eor          r19,        r18       \n\t"
        "mov          r18,        r7        \n\t"
        "and          r18,        r5        \n\t"
        "mov          r7,         r17       \n\t"
        "and          r7,         r5        \n\t"
        "swap         r7                    \n\t"
        "eor          r18,        r7        \n\t"
        "mov          r7,         r16       \n\t"
        "and          r7,         r27       \n\t"
        "mov          r16,        r6        \n\t"
        "and          r6,         r5        \n\t"
        "eor          r7,         r6        \n\t"
        "swap         r16                   \n\t"
        "and          r16,        r5        \n\t"
        "and          r17,        r27       \n\t"
        "eor          r16,        r17       \n\t"
        "mov          r17,        r7        \n\t"
        // LFSR
        "mov          r24,        r16       \n\t" // half of first row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsr          r16                   \n\t"
        "andi         r16,        0xee      \n\t"
        "eor          r16,        r24       \n\t"
        "mov          r24,        r17       \n\t" // half of first row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsr          r17                   \n\t"
        "andi         r17,        0xee      \n\t"
        "eor          r17,        r24       \n\t"
        "mov          r24,        r18       \n\t" // half of second row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsr          r18                   \n\t"
        "andi         r18,        0xee      \n\t"
        "eor          r18,        r24       \n\t"
        "mov          r24,        r19       \n\t" // half of second row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsr          r19                   \n\t"
        "andi         r19,        0xee      \n\t"
        "eor          r19,        r24       \n\t"
    "rjmp             key_schedule_start    \n\t"
    "key_schedule_exit:                     \n\t"
        "pop          r29         \n\t"
        "pop          r28         \n\t"
        "pop          r17         \n\t"
        "pop          r16         \n\t"
        "pop          r15         \n\t"
        "pop          r14         \n\t"
        "pop          r13         \n\t"
        "pop          r12         \n\t"
        "pop          r11         \n\t"
        "pop          r10         \n\t"
        "pop          r9          \n\t"
        "pop          r8          \n\t"
        "pop          r7          \n\t"
        "pop          r6          \n\t"
        "pop          r5          \n\t"
        :
        : [key] "" (key), [roundKeys] "" (roundKeys), [RC] "" (RC));
}

#elif defined MSP
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
}

#elif defined ARM
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* Add here the cipher encryption key schedule implementation */
}

#endif
