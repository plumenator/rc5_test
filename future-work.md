
0. Make the wrapping add and other arithmetic operations look cleaner and less verbose
1. Make it work with u128 (just need to get the P and Q values, the current code should work as is)
2. Make it work with u8 (this would require handling 1-byte blocks, treating each nibble as a word. It might require a substantial change)
   1. [Haskell implementation](https://hackage.haskell.org/package/cipher-rc5-0.1.0.2/docs/src/Crypto-Cipher-RC5.html) that uses bit vectors (essentially serialize to bits, run the algo and deserialize back to words), that works even for 8 bit words
3. Add property based tests
4. Run a fuzzer
