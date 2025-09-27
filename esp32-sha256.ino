#include <Arduino.h>

// ---- SHA-256 constants ----
const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
  0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,
  0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,
  0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,
  0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,
  0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// ---- Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes) ----
uint32_t H[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// ---- Helper functions ----
uint32_t rotR(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
uint32_t shr(uint32_t x, int n) { return x >> n; }
uint32_t SIGMA0(uint32_t x) { return rotR(x, 2) ^ rotR(x, 13) ^ rotR(x, 22); }
uint32_t SIGMA1(uint32_t x) { return rotR(x, 6) ^ rotR(x, 11) ^ rotR(x, 25); }
uint32_t sigma0(uint32_t x) { return rotR(x, 7) ^ rotR(x, 18) ^ shr(x, 3); }
uint32_t sigma1(uint32_t x) { return rotR(x, 17) ^ rotR(x, 19) ^ shr(x, 10); }
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

// ---- Serial input ----
String input = "";

// ---- Functions for padding & printing ----
int messageProcessing(const String& input, uint8_t* padded) {
  int inputLen = input.length();
  // copy input to padded array
  for (int i = 0; i < inputLen; i++) padded[i] = input[i];
  int paddedLen = inputLen;
  
  // append 0x80
  padded[paddedLen++] = 0x80;
  
  // append 0x00 until 64 bits shy of next 512-bit block
  while ((paddedLen + 8) % 64 != 0) padded[paddedLen++] = 0x00;
  
  // append length in bits (64-bit big-endian)
  uint64_t bitLen = (uint64_t)inputLen * 8;
  for (int i = 7; i >= 0; i--) {
    padded[paddedLen++] = (bitLen >> (i*8)) & 0xFF;
  }
  return paddedLen; // total length in bytes
}

String toHexString(const uint8_t* data, int len) {
  String out = "";
  for (int i = 0; i < len; i++) {
    if (data[i] < 16) out += "0";
    out += String(data[i], HEX);
  }
  return out;
}

// Convert 4 bytes to uint32_t (big-endian)
uint32_t bytesToUint32(const uint8_t* bytes, int offset) {
  return ((uint32_t)bytes[offset] << 24) |
         ((uint32_t)bytes[offset + 1] << 16) |
         ((uint32_t)bytes[offset + 2] << 8) |
         ((uint32_t)bytes[offset + 3]);
}

// Convert uint32_t to hex string
String uint32ToHex(uint32_t value) {
  String result = "";
  for (int i = 3; i >= 0; i--) {
    uint8_t byte = (value >> (i * 8)) & 0xFF;
    if (byte < 16) result += "0";
    result += String(byte, HEX);
  }
  return result;
}

// ---- SHA-256 Core Algorithm ----
void sha256(uint8_t* padded, int len) {
  Serial.print("Padded message (hex): ");
  Serial.println(toHexString(padded, len));
  
  // Reset hash values for each new message
  H[0] = 0x6a09e667; H[1] = 0xbb67ae85; H[2] = 0x3c6ef372; H[3] = 0xa54ff53a;
  H[4] = 0x510e527f; H[5] = 0x9b05688c; H[6] = 0x1f83d9ab; H[7] = 0x5be0cd19;
  
  // Process message in 512-bit (64-byte) chunks
  for (int chunkStart = 0; chunkStart < len; chunkStart += 64) {
    Serial.print("Processing chunk starting at byte: ");
    Serial.println(chunkStart);
    
    // Message schedule array W[0..63]
    uint32_t W[64];
    
    // Copy chunk into first 16 words of message schedule
    for (int i = 0; i < 16; i++) {
      W[i] = bytesToUint32(padded, chunkStart + i * 4);
    }
    
    // Extend the first 16 words into the remaining 48 words
    for (int i = 16; i < 64; i++) {
      W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }
    
    // Initialize working variables
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    
    Serial.println("Starting 64 rounds:");
    
    // Main loop - 64 rounds
    for (int i = 0; i < 64; i++) {
      uint32_t temp1 = h + SIGMA1(e) + Ch(e, f, g) + K[i] + W[i];
      uint32_t temp2 = SIGMA0(a) + Maj(a, b, c);
      
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
      
      // Print every 8th round for debugging
      if (i % 8 == 7) {
        Serial.print("Round ");
        Serial.print(i + 1);
        Serial.print(": a=");
        Serial.print(uint32ToHex(a));
        Serial.print(" e=");
        Serial.println(uint32ToHex(e));
      }
    }
    
    // Add compressed chunk to current hash value
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  
  // Produce final hash value
  Serial.print("SHA-256 Hash: ");
  for (int i = 0; i < 8; i++) {
    Serial.print(uint32ToHex(H[i]));
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  Serial.println("Send string to hash with SHA-256:");
}

void loop() {
  if (Serial.available() > 0) {
    input = Serial.readStringUntil('\n');
    input.trim(); // Remove any trailing newlines/spaces
    
    Serial.print("You sent: ");
    Serial.println(input);
    
    uint8_t padded[1024]; // adjust if expecting longer messages
    int paddedLen = messageProcessing(input, padded);
    sha256(padded, paddedLen);
    Serial.println("---");
  }
}