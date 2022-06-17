
1. Make the wrapping add and other arithmetic operations look cleaner and less verbose
2. Use bitvectors to avoid all the generics and traits boilerplate
   1. [Haskell implementation](https://hackage.haskell.org/package/cipher-rc5-0.1.0.2/docs/src/Crypto-Cipher-RC5.html) that uses bit vectors (essentially serialize to bits, run the algo and deserialize back to words), that works even for 8 bit words
3. Add property based tests
4. Run a fuzzer
