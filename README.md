# Bitcoin Block Mining Simulation

simulates the mining process of a real Bitcoin block. The code is written in C and uses the OpenSSL library to perform SHA-256 hashing.

## Algorithms and Code Structure

1. **Double SHA-256 Hashing**  
   Bitcoin mining relies on applying the SHA-256 hash function twice on the block header. First, the input data (block header) is hashed with SHA-256, and then the resulting hash is hashed again to produce the final output.

2. **Block Header Structure**  
   The block header is 80 bytes long and consists of fields such as version, previous block hash (`prev_hash`), Merkle root (`merkle_root`), timestamp, difficulty bits, and nonce. The nonce is a 32-bit counter that is incremented to find a valid hash.

3. **Difficulty Target Calculation**  
   The `bits` field encodes the mining difficulty in a compact form. It is converted into a full 256-bit target value against which the resulting hash is compared. This involves extracting the exponent and coefficient from the bits field and constructing the target as a 32-byte array.

4. **Nonce Searching (Mining)**  
   The miner iterates nonce values from 0 up to 2^32 - 1, updating the block header each time. For each nonce, the double SHA-256 hash of the header is computed and compared to the target. If the hash is less than the target, mining is successful.

5. **Progress Display and Output**  
   The program displays mining progress every million nonce attempts as a progress bar in the terminal. Once a valid nonce is found, the nonce and corresponding hash are printed.

## Mathematical Summary

- **SHA-256** is a cryptographic hash function that maps any input data to a fixed 256-bit output.

- Double hashing is defined as:  
  `H = SHA256(SHA256(header))`

- The difficulty target is calculated from the compact `bits` representation as:  
  `target = coefficient × 2^(8 × (exponent - 3))`

- Mining is successful if:  
  `H < target`

## How to Run

Compile the code using gcc with OpenSSL library:

``` bash
gcc -o bitcoin_miner bitcoin_miner.c -lcrypto # compile
./bitcoin_miner # run
```

The input parameters (version, prev_hash, merkle_root, timestamp, bits) are taken from the real Bitcoin block [#896987](https://blockexplorer.one/bitcoin/mainnet/blockId/896987). This program simulates mining of that specific block.
