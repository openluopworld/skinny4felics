# skinny4felics
Implementation of lightweight block cipher SKINNY based on FELICS.

NOTE: Some optimization have been given, but this is still NOT the best implementation.

### SKINNY-64-128
* Plaintext
  + 00 01 02 03 fc fd fe ff
* Keys
  + f0 f1 f2 f3 f4 f5 f6 f7 08 09 0a 0b 0c 0d 0e 0f
* RoundKeys:
  + e8 f8 f8 f8 f9 fa ff ff 64 f7 ff f2 40 5f ff fe
  + 37 2f ef f9 07 ff 5f ff 15 df 7f ff ff 2f 5f 0f
  + af bf cf 9f 0f 2f 8d 5f 1f cf 53 bf 3f f7 c3 bf
  + 6f f6 d2 af cf fe c9 52 8f f1 d6 ad 19 fd f0 f4
  + 2a fe e3 f7 41 fb cf f4 0a f0 cf ff 17 1f df fc
  + 6d bf ef f6 d3 df df ff 1b 5f 6f ff df cf 1f 3f
  + 0f 0f cf ff df 1f 6b cf af 4f 3e 9f 4f fa 90 3f
  + 8f fc e6 5f 1f f8 d8 88 3f f8 e8 88 7c ff ca f9
  + e1 f2 c7 f4 6b fe df f0 4c f9 ff f7 2e 6f ff f7 
* Ciphertext
  + 20 0e 15 c8 07 ea 51 dd

### SKINNY-128-128
* Plaintext
  + 00 01 02 03 04 05 06 07 f8 f9 fa fb fc fd fe ff
* Keys
  + f0 f1 f2 f3 f4 f5 f6 f7 08 09 0a 0b 0c 0d 0e 0f
* RoundKeys:
  + f1 f1 f2 f3 f4 f5 f6 f7 0a 0f 08 0d 0a 0e 0c 0b
  + f6 f7 f0 f5 f2 f6 f4 f3 00 0b 09 0e 08 0c 0a 0d
  + f8 f3 f1 f6 f1 f4 f2 f5 05 0d 0f 0c 0a 0a 08 0e
  + fe f5 f7 f4 f2 f2 f0 f6 06 0e 0b 0a 0c 08 09 0c
  + f2 f6 f3 f2 f4 f0 f1 f4 01 0c 0d 08 09 09 0f 0a
  + f8 f4 f5 f0 f2 f1 f7 f2 00 0a 0e 09 0e 0f 0b 08
  + fd f2 f6 f1 f6 f7 f3 f0 09 08 0c 0f 0d 0b 0d 09
  + f5 f0 f4 f7 f4 f3 f5 f1 06 09 0a 0b 0c 0d 0e 0f
  + fd f1 f2 f3 f5 f5 f6 f7 03 0f 08 0d 09 0e 0c 0b
  + f4 f7 f0 f5 f1 f6 f4 f3 04 0b 09 0e 0a 0c 0a 0d
  + f1 f3 f1 f6 f1 f4 f2 f5 07 0d 0f 0c 0b 0a 08 0e
  + fb f5 f7 f4 f0 f2 f0 f6 0d 0e 0b 0a 0c 08 09 0c
  + f4 f6 f3 f2 f5 f0 f1 f4 0c 0c 0d 08 0b 09 0f 0a
  + f3 f4 f5 f0 f3 f1 f7 f2 07 0a 0e 09 0d 0f 0b 08
  + f3 f2 f6 f1 f4 f7 f3 f0 04 08 0c 0f 0c 0b 0d 09
  + fe f0 f4 f7 f7 f3 f5 f1 00 09 0a 0b 0f 0d 0e 0f
  + f1 f1 f2 f3 f7 f5 f6 f7 0a 0f 08 0d 08 0e 0c 0b
  + f7 f7 f0 f5 f2 f6 f4 f3 02 0b 09 0e 08 0c 0a 0d
  + fc f3 f1 f6 f1 f4 f2 f5 0d 0d 0f 0c 0a 0a 08 0e
  + fe f5 f7 f4 f3 f2 f0 f6 07 0e 0b 0a 0e 08 09 0c
* Ciphertext
  + 5f 9f 3f c4 b9 d8 43 61 ba 11 c1 a4 03 bc c0 e4