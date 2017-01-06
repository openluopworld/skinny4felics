# SKINNY4FELICS
Implementation of Lightweight Block Cipher [SKINNY] based on [FELICS]. Only the *encryptionKeySchedule.c*, *encrypt.c* and *decrypt.c* are given here. Note that, some optimizations have been given, but this is still NOT the best implementation.

Only two versions are given here, SKINNY-128-128 whose block size is 128-bit with 128-bit key size, and the other is SKINNY-64-128 whose block size is 64-bit with the same key size.

## SKINNY-128-128
### Test Vector
![Test Vector for SKINNY-128-128](./pic/skinny-128-128.png?raw=true)

### Cipher State
```C
s0  s1  s2  s3
s4  s5  s6  s7
s8  s9  s10 s11
s12 s13 s14 s15
```
where each element is a byte.

## SKINNY-64-128
### Test Vector
![Test Vector for SKINNY-64-128](./pic/skinny-64-128.png?raw=true)

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


[SKINNY]:<https://sites.google.com/site/skinnycipher/>
[FELICS]:<https://www.cryptolux.org/index.php/FELICS>