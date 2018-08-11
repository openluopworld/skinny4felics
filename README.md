# SKINNY4FELICS
Implementation of Lightweight Block Cipher [SKINNY] based on [FELICS]. 

Only two versions are given here. They are SKINNY-128-128, whose block size is 128-bit with 128-bit key size, and SKINNY-64-128, whose block size is 64-bit with the same key size.

## How To Use
It runs correctly under FELICS on AVR and MSP. For ARM, the code is NOT tested, since there is not a board at hand. Note that, some optimizations have been given, so the code may seem in a mess.

## SKINNY-128-128

### Cipher State
```C
s0  s1  s2  s3
s4  s5  s6  s7
s8  s9  s10 s11
s12 s13 s14 s15
```
where each element is a byte.

## SKINNY-64-128

### Cipher State
```C
s0  s1  s2  s3
s4  s5  s6  s7
s8  s9  s10 s11
s12 s13 s14 s15
```
where each element is a nibble.

Suppose the block is (0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef). The three states are as follows.

* AVR
```C
r1 r2 ---> s0  s1  s2  s3  ---> 0x0 0x1 0x2 0x3
r3 r4 ---> s4  s5  s6  s7  ---> 0x4 0x5 0x6 0x7
r5 r6 ---> s8  s9  s10 s11 ---> 0x8 0x9 0xa 0xb
r7 r8 ---> s12 s13 s14 s15 ---> 0xc 0xd 0xe 0xf
```
* MSP
```C
r1 ---> s2  s3  s0  s1  ---> 0x2 0x3 0x0 0x1
r2 ---> s6  s7  s4  s5  ---> 0x6 0x7 0x4 0x5
r3 ---> s10 s11 s8  s9  ---> 0xa 0xb 0x8 0x9
r4 ---> s14 s15 s12 s13 ---> 0xe 0xf 0xc 0xd
```
* ARM
```C
r1 ---> s6  s7  s4  s5  s2  s3  s0  s1  ---> 0x6 0x7 0x4 0x5 0x2 0x3 0x0 0x1
r2 ---> s14 s15 s12 s13 s10 s11 s8  s9  ---> 0xe 0xf 0xc 0xd 0xa 0xb 0x8 0x9
```

## Implementation
* In key schedule, **the round constants *c0* and *c1* are XOR-ed with *TK1* and *TK2* (only for SKINNY-64-128), the final values are stored as *'RoundKeys'*.  The constant *c2* is XOR-ed with the cipher state in encryption (or decryption)**.
* For SKINNY-64-128, two *SubCells* are done each time. That is to say, *SBOX* and *Inverse SBOX* are from 8-bit to 8-bit. Parts of *SBOX* are as follows:
```C
SBOX_BYTE SBOX[256] = {
    0xcc, 0xc6, 0xc9, 0xc0, 0xc1, 0xca, 0xc2, 0xcb, 0xc3, 0xc8, 0xc5, 0xcd, 0xc4, 0xce, 0xc7, 0xcf,
    0x6c, 0x66, 0x69, 0x60, 0x61, 0x6a, 0x62, 0x6b, 0x63, 0x68, 0x65, 0x6d, 0x64, 0x6e, 0x67, 0x6f,
    0x9c, 0x96, 0x99, 0x90, 0x91, 0x9a, 0x92, 0x9b, 0x93, 0x98, 0x95, 0x9d, 0x94, 0x9e, 0x97, 0x9f,
```

[SKINNY]:<https://sites.google.com/site/skinnycipher/>
[FELICS]:<https://www.cryptolux.org/index.php/FELICS>
