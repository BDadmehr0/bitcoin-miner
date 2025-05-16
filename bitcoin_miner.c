#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

// تبدیل هش به رشته هگز
void hash_to_hex(unsigned char hash[32], char output[65]) {
    for (int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
}

// تبدیل hex string به بایت
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

// هش دوبل SHA256
void double_sha256(unsigned char* input, int len, unsigned char* output) {
    unsigned char first[32];
    SHA256(input, len, first);
    SHA256(first, 32, output);
}

// تبدیل bits به target واقعی 256 بیتی
void bits_to_target(const char* bits_hex, unsigned char* target) {
    unsigned char bits[4];
    hex_to_bytes(bits_hex, bits, 0);

    int exponent = bits[0];
    int coefficient = (bits[1] << 16) | (bits[2] << 8) | bits[3];

    memset(target, 0, 32); // صفر کردن کل target

    int index = 32 - exponent;
    if (index < 0 || index > 29) return; // ایمنی

    target[index]     = (coefficient >> 16) & 0xff;
    target[index + 1] = (coefficient >> 8) & 0xff;
    target[index + 2] = (coefficient) & 0xff;
}

// چاپ target در قالب hex
void print_target_hex(unsigned char* target) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", target[i]);
    }
    printf("\n");
}

// شبیه‌سازی کامل ماینینگ
void mine_real_block(
    const char* version_hex,
    const char* prev_hash_hex,
    const char* merkle_root_hex,
    const char* timestamp_hex,
    const char* bits_hex
) {
    unsigned char header[80];
    unsigned char hash[32];
    unsigned char target[32];
    char hash_hex[65];
    uint32_t nonce = 0;

    // ساختن header
    hex_to_bytes(version_hex, header, 0);               // version
    hex_to_bytes(prev_hash_hex, header + 4, 1);         // prev_hash (little-endian)
    hex_to_bytes(merkle_root_hex, header + 36, 1);      // merkle_root (little-endian)
    hex_to_bytes(timestamp_hex, header + 68, 0);        // timestamp
    hex_to_bytes(bits_hex, header + 72, 0);             // bits

    // محاسبه target از bits
    bits_to_target(bits_hex, target);

    printf("Target: ");
    print_target_hex(target);
    printf("Mining block...\n");

    while (1) {
        // تنظیم nonce
        header[76] = (nonce) & 0xff;
        header[77] = (nonce >> 8) & 0xff;
        header[78] = (nonce >> 16) & 0xff;
        header[79] = (nonce >> 24) & 0xff;

        // هش دوبل
        double_sha256(header, 80, hash);

        // مقایسه هش با target
        if (memcmp(hash, target, 32) < 0) {
            hash_to_hex(hash, hash_hex);
            printf("\n✅ Mined!\nNonce: %u\nHash: %s\n", nonce, hash_hex);
            break;
        }

        nonce++;
        if (nonce % 1000000 == 0) {
          int width = 50; // عرض نوار پیشرفت
          float progress = (float)nonce / 0xFFFFFFFF;
          int pos = progress * width;
    
          printf("\r[");
            for (int i = 0; i < width; ++i) {
              if (i < pos) printf("=");
              else if (i == pos) printf(">");
              else printf(" ");
            }
            printf("] %.2f%%", progress * 100);
          fflush(stdout);
        }


        if (nonce == 0xFFFFFFFF) {
            printf("\n❌ Nonce limit reached (2^32 - 1)\n");
            break;
        }
    }
}

int main() {
    // بلاک واقعی: 896987 (https://blockexplorer.one/bitcoin/mainnet/blockId/896987)
    const char* version_hex = "20000000";
    const char* prev_hash_hex = "0000000000000000000a1717d19d2c42681ec43504fbc41970cd9f1c4a124dd";
    const char* merkle_root_hex = "25fa40ddf069812044fe21ad7da1b2339efd2b562b4028a5e2a77a76e9ed27eb";
    const char* timestamp_hex = "6645A414"; // 16 May 2025 16:20:20 UTC
    const char* bits_hex = "170c6c3a"; // سختی بلاک

    mine_real_block(version_hex, prev_hash_hex, merkle_root_hex, timestamp_hex, bits_hex);

    return 0;
}

