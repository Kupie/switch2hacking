// HIPC2 send via svc 0x22 (SendSyncRequestWithUserBuffer) — the transport
// proven in takeover-launched processes (executor v7+). The frame is built
// in out[0..7] which doubles as the reply buffer (svc 0x22 replies in-place).
//
// args[0] = handle (low 32) | wc (high 32)   [wc = 8 + 2*nargs, the total
//            word count of the frame; send size = wc*4]
// args[1] = "SFCI" (u32 LE 0x49434653) | token (u32) << 32
// args[2] = cmd (u32) | seq (u32) << 32
// args[3..6] = the up-to-four u64 command arguments
// out[0..7] = the 64-byte frame: {6,wc} +0x00, zeros +0x08, SFCI+token
//             +0x10, cmd+seq +0x18, args +0x20 — replaced by the reply on
//             success (SFCO at +0x10 = out[2] low half).
typedef unsigned long long u64;
typedef unsigned int u32;

static inline u32 svc22(u64 buf, u64 size, u32 handle) {
    register u64 x0 __asm__("x0") = buf;
    register u64 x1 __asm__("x1") = size;
    register u64 x2 __asm__("x2") = handle;
    __asm__ __volatile__("svc #0x22" : "+r"(x0) : "r"(x1), "r"(x2) : "memory", "cc");
    return (u32)x0;
}

void exp(const u64 *args, u64 *out) {
    u32 handle = (u32)args[0];
    u32 wc = (u32)(args[0] >> 32);
    out[0] = 6ull | ((u64)wc << 32);   // {6, wc}
    out[1] = 0;                        // +0x08 descriptor area: zero
    out[2] = args[1];                  // SFCI | token
    out[3] = args[2];                  // cmd | seq
    out[4] = args[3];
    out[5] = args[4];
    out[6] = args[5];
    out[7] = args[6];
    u32 r = svc22((u64)(void *)out, (u64)wc * 4, handle);
    (void)r;   // on error the request frame stays in out (no SFCO) — the PC's oracle
}
