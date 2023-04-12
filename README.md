### I/O Testing

1) Playing with inputs and without modifying or looking at the code, try to identify different errors that could occur using the reference implementation given in ref_aes.c


### Randomness Testing

1) With a key of your choice (you can use the one hardcoded), statistically test the quality of the ref_aes.c implementation using it as a random number generator with the dieharder cli. You can inspire/use the code in comments as base of your test.

2) (Bonus) Fixing the AES implementation provided, retry the diehard test to make it pass everything (with 1k samples).

Material: 

- https://en.wikipedia.org/wiki/Diehard_tests
- apt-get install dieharder (on MacOS youll need to DL the source and install it manually)
- ref_aes.c
- aes.diehard (pre-formated file)

### Key Recovery

Using only the SBox look-up table given in ref_aes.c, the following state input of the AES algorithm, and the following internal output taken after the first SubBytes in AES (	ARK + SB done by the algorithm), propose an algorithm that recovers the corresponding round key (round key 0) in a efficient manner.

Material:

- Input: 0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710
- Output (after 1 addroundkey and 1 (proper) subbytes): 0x5DDC4AAF, 0x415C0534, 0x1530EF67, 0x9872021C
