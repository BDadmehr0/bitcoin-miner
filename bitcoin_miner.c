#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

/**
 * @brief Convert a 32-byte hash to a null-terminated hexadecimal string.
 * 
 * @param hash  Input 32-byte hash.
 * @param output Output buffer of at least 65 bytes (64 hex chars + null terminator).
 */
void hash_to_hex(unsigned char hash[32], char output[65]) {
    for (int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

/**
 * @brief Convert a hexadecimal string to bytes.
 * 
 * @param hex Input null-terminated hex string (must be even length).
 * @param bytes Output buffer to store bytes.
 * @param reverse If non-zero, bytes are stored in reverse order (for little-endian representation).
 */
void hex_to_bytes(const char* hex, unsigned char* bytes, int reverse) {
    char tmp[3] = {0};
    int len = strlen(hex);
    for (int i = 0; i < len / 2; i++) {
        tmp[0] = hex[i * 2];
        tmp[1] = hex[i * 2 + 1];
        unsigned int val;
        sscanf(tmp, "%x", &val);
        if (reverse)
            bytes[(len / 2 - 1) - i] = (unsigned char)val;
        else
            bytes[i] = (unsigned char)val;
    }
}

/**
 * @brief Compute double SHA-256 hash on the input data.
 * 
 * @param input Pointer to input data.
 * @param len Length of input data in bytes.
 * @param output Output buffer to store 32-byte hash.
 */
void double_sha256(unsigned char* input, int len, unsigned char* output) {
    unsigned char first[32];
    SHA256(input, len, first);
    SHA256(first, 32, output);
}

/**
 * @brief Convert compact "bits" representation to full 256-bit target.
 * 
 * @param bits_hex 8-character hex string representing the 4-byte bits field.
 * @param target Output 32-byte array to store the full target.
 */
void bits_to_target(const char* bits_hex, unsigned char* target) {
    unsigned char bits[4];
    hex_to_bytes(bits_hex, bits, 0);

    int exponent = bits[0];
    int coefficient = (bits[1] << 16) | (bits[2] << 8) | bits[3];

    memset(target, 0, 32);

    int index = 32 - exponent;
    if (index < 0 || index > 29) return; // Safety check

    target[index]     = (coefficient >> 16) & 0xff;
    target[index + 1] = (coefficient >> 8) & 0xff;
    target[index + 2] = (coefficient) & 0xff;
}

/**
 * @brief Print a 32-byte target as a 64-character hexadecimal string.
 * 
 * @param target 32-byte array representing the target.
 */
void print_target_hex(unsigned char* target) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", target[i]);
    }
    printf("\n");
}

/**
 * @brief Simulate Bitcoin mining by iterating nonce values to find a valid hash under the target.
 * 
 * @param version_hex     8-char hex string representing block version.
 * @param prev_hash_hex   64-char hex string of previous block hash (big-endian).
 * @param merkle_root_hex 64-char hex string of Merkle root (big-endian).
 * @param timestamp_hex   8-char hex string representing block timestamp.
 * @param bits_hex        8-char hex string representing difficulty bits.
 */
void mine_real_block(
    const char* version_hex,
    const char* prev_hash_hex,
    const char* merkle_root_hex,
    const char* timestamp_hex,
    const char* bits_hex
) {
    unsigned char header[80];       // Block header bytes
    unsigned char hash[32];         // Resulting hash buffer
    unsigned char target[32];       // Difficulty target
    char hash_hex[65];              // Hash string for output
    uint32_t nonce = 0;

    // Build block header in proper order (little-endian where needed)
    hex_to_bytes(version_hex, header, 0);               // version (4 bytes, LE)
    hex_to_bytes(prev_hash_hex, header + 4, 1);         // prev_hash (32 bytes, LE)
    hex_to_bytes(merkle_root_hex, header + 36, 1);      // merkle_root (32 bytes, LE)
    hex_to_bytes(timestamp_hex, header + 68, 0);        // timestamp (4 bytes, LE)
    hex_to_bytes(bits_hex, header + 72, 0);             // bits (4 bytes, LE)

    // Calculate the full 256-bit target from bits
    bits_to_target(bits_hex, target);

    printf("Target: ");
    print_target_hex(target);
    printf("Mining block...\n");

    while (1) {
        // Set nonce in the last 4 bytes of the header (little-endian)
        header[76] = (nonce) & 0xff;
        header[77] = (nonce >> 8) & 0xff;
        header[78] = (nonce >> 16) & 0xff;
        header[79] = (nonce >> 24) & 0xff;

        // Compute double SHA256 hash of header
        double_sha256(header, 80, hash);

        // Check if hash is less than target (valid block)
        if (memcmp(hash, target, 32) < 0) {
            hash_to_hex(hash, hash_hex);
            printf("\nMined successfully!\nNonce: %u\nHash: %s\n", nonce, hash_hex);
            break;
        }

        nonce++;

        // Show progress every 1 million attempts
        if (nonce % 1000000 == 0) {
            int width = 50; // progress bar width
            float progress = (float)nonce / 0xFFFFFFFF;
            int pos = (int)(progress * width);

            printf("\r[");
            for (int i = 0; i < width; ++i) {
                if (i < pos) printf("=");
                else if (i == pos) printf(">");
                else printf(" ");
            }
            printf("] %.2f%%", progress * 100);
            fflush(stdout);
        }

        // Stop if nonce limit reached
        if (nonce == 0xFFFFFFFF) {
            printf("\nNonce limit reached (2^32 - 1), stopping mining.\n");
            break;
        }
    }
}

int main() {
    // Real Bitcoin block #896987 details from https://blockexplorer.one/bitcoin/mainnet/blockId/896987
    const char* version_hex = "20000000";
    const char* prev_hash_hex = "0000000000000000000a1717d19d2c42681ec43504fbc41970cd9f1c4a124dd";
    const char* merkle_root_hex = "25fa40ddf069812044fe21ad7da1b2339efd2b562b4028a5e2a77a76e9ed27eb";
    const char* timestamp_hex = "6645A414"; // 16 May 2025 16:20:20 UTC
    const char* bits_hex = "170c6c3a";      // Block difficulty bits

    mine_real_block(version_hex, prev_hash_hex, merkle_root_hex, timestamp_hex, bits_hex);

    return 0;
}
