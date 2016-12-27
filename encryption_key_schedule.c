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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    /* r5-r6   : tk0, tk4                   */
    /* r7-r22  : master keys                */
    /* r23     : loop control               */
    /* r24-r25 : temp use                   */
    /* r26-r27 : X points to plain text     */
    /* r30-r31 : Z points to roundKeys      */
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
        "ldi          r23,        40        \n\t"
        // load_keys
        // r7  r8  r9  r10
        // r11 r12 r13 r14
        // r15 r16 r17 r18
        // r19 r20 r21 r22
        "ld           r7,         x+        \n\t"
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
        "movw         r26,        r22       \n\t"
        "ldi          r30,        lo8(RC)   \n\t"
        "ldi          r31,        hi8(Rc)   \n\t"
    "key_schedule_start:                    \n\t"
        // add_round_const
        "lpm          r24,        z+        \n\t"
        "mov          r25,        r24       \n\t"
        "andi         r25,        0x0f      \n\t"
        "mov          r5,         r7        \n\t"
        "eor          r5,         r25       \n\t"
        "andi         r24,        0x30      \n\t"
        "swap         r24                   \n\t"
        "mov          r6,         r11       \n\t"
        "eor          r6,         r24       \n\t"
        // store_round_keys
        "st           x+,         r5        \n\t"
        "st           x+,         r8        \n\t"
        "st           x+,         r9        \n\t"
        "st           x+,         r10       \n\t"
        "st           x+,         r6        \n\t"
        "st           x+,         r12       \n\t"
        "st           x+,         r13       \n\t"
        "st           x+,         r14       \n\t"
        "dec          r23                   \n\t"
    "breq             key_schedule_exit     \n\t"
        // 0  1  2  3         9  15 8  13
        // 4  5  6  7         10 14 12 11
        // 8  9  10 11 -----> 0  1  2  3
        // 12 13 14 15        4  5  6  7
        "mov          r24,        r7        \n\t"
        "mov          r7,         r16       \n\t"
        "mov          r16,        r8        \n\t"
        "mov          r8,         r22       \n\t"
        "mov          r22,        r14       \n\t"
        "mov          r14,        r18       \n\t"
        "mov          r18,        r10       \n\t"
        "mov          r10,        r20       \n\t"
        "mov          r20,        r12       \n\t"
        "mov          r12,        r21       \n\t"
        "mov          r21,        r13       \n\t"
        "mov          r13,        r19       \n\t"
        "mov          r19,        r11       \n\t"
        "mov          r11,        r17       \n\t"
        "mov          r17,        r9        \n\t"
        "mov          r9,         r15       \n\t"
        "mov          r15,        r24       \n\t"
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

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* Add here the cipher encryption key schedule implementation */
}
#endif