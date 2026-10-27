// ABI smoke test: pure arithmetic roundtrip, no timing dependencies.
// Verifies the upload/execute/return path end to end before any real probe.
typedef unsigned long long u64;

void exp(const u64 *args, u64 *out) {
    out[0] = 0x4558454330303156ull; // "V100EXE" tag
    out[1] = args[0] + args[1];
    out[2] = args[0] ^ args[1];
    out[3] = args[0] * 0x9e3779b97f4a7c15ull;
    u64 fib = 0, a = 0, b = 1;
    for (u64 i = 0; i < args[2] && i < 1000000; i++) {fib = a + b; a = b; b = fib;}
    out[4] = fib;
    out[5] = (u64)(void *)out ^ (u64)(void *)args; // pointers differ per call
    out[6] = args[3];
    out[7] = 0xd0d0d0d0d0d0d0d0ull;
}
