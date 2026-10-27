// A small native RO proof server. No runtime, heap, or absolute pointers.
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef struct { u64 result, value; } Reply;
typedef struct { u64 result, handle; } Pair;

extern Reply connect_port(const char *name);
extern u32 send_request(u32 handle);
extern u32 close_handle(u32 handle);
extern void sleep_thread(s64 ns);
extern Reply wait_handles(const u32 *handles, u32 count, s64 timeout);
extern Reply reply_receive(const u32 *handles, u32 count, u32 reply, s64 timeout);
extern Reply accept_session(u32 port);
extern Reply process_id(u32 handle);
extern Reply thread_id(u32 handle);
extern u64 system_tick(void);
extern u32 process_request(u32 command, const u64 *input, u32 bytes,
    u32 handle, u64 *output, u32 *output_bytes, void *receive, u64 receive_size);
extern u32 process_permission(u32 handle, u64 address, u64 size, u32 permission);
extern Pair debug_active_process(u64 pid);   // svc 0x60: x0=result, x1=debug handle
extern u32 debug_read(u64 buffer, u32 debug_handle, u64 address, u64 size);
extern u32 debug_write(u32 debug_handle, u64 buffer, u64 address, u64 size);
extern u32 get_process_list(u64 *out_count, u64 *pids, u32 max);  // pass-through: x0/x1/x2 already ABI
extern u32 terminate_process(u32 handle);
extern u64 free_address(u32 handle, u64 size);
extern u32 map_code(u32 handle, u64 destination, u64 source, u64 size);
extern u32 unmap_code(u32 handle, u64 destination, u64 source, u64 size);
extern void publish_code(u64 address, u64 size);
extern void rig_call(u64 entry, const u64 *args, u64 *out, u64 stack_top);

static u32 *message(void) {
    u32 *p;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(p));
    return p;
}

static void clear(u32 *p) {
    for (u32 i = 0; i < 64; i++) p[i] = 0;
}

// HIPC2 send (rig sub 21): the type-6 frame in THIS worker thread's TLS,
// sent via the proven send_request wrapper (svc 0x21, handle in x0 — the
// fw23 old-ABI transport). in[0]=handle | wc<<32 (wc = 8+2n, send words),
// in[1]=cmd | seq<<32, in[2..4]=up to 3 u64 args. Reply lands in the TLS
// in-place; out = {transport|SFCO, token|result, then the raw 8-word frame}.
// The frame buffer (the executor's exact transport: send_buffer = svc 0x22,
// x0=buffer x1=size x2=handle — the PROVEN path; the reply lands in-place).
static u64 hipc2Frame[512] __attribute__((aligned(4096))); // the executor's user-buffer shape
// Sub 21: the fs-sender-faithful TLS client — the frame in THIS thread's
// TLS (message()), the REAL per-thread sequence (the fs sender's exact
// ldar [TLS+0x1f8 + 0x100] pattern), svc 0x21, the reply read from the TLS.
// Sub 23: the buffer variant (svc 0x22, frame+reply in hipc2Frame).
// in[0]=handle|wc<<32, in[1]=cmd|seq<<32 (seq 0 = use the real counter),
// in[2..4]=args, in[5]=tag (6 HIPC2, 4 cmif, 0x11 old-sm).
static u32 hipc2SendTls(u64 *out, const u64 *in) {
    u32 handle = (u32)in[0];
    u32 wc = (u32)(in[0] >> 32);
    u32 *p = message();
    u8 *tls = (u8 *)p; // tpidrro_el0 = the TLS block base (the fs sender reads [base+0x1f8])
    clear(p);
    p[0] = (u32)in[5]; p[1] = wc;
    p[4] = 0x49434653; // "SFCI" at +0x10
    p[5] = 1;          // token
    p[6] = (u32)in[1]; // cmd
    // The real per-thread sequence: [TLS_base + 0x1f8] -> +0x100 -> ldar
    // (the fs sender's exact pattern, text+0x1f416c..74).
    u32 seq = (u32)(in[1] >> 32);
    if (!seq) {
        u64 *ctxp = (u64 *)(tls + 0x1f8);
        u64 ctx = *ctxp;
        u32 *counter = (u32 *)(ctx + 0x100);
        __asm__ volatile("ldar %w0, [%1]" : "=r"(seq) : "r"(counter) : "memory");
    }
    p[7] = seq;
    u64 *args = (u64 *)(p + 8);
    args[0] = in[2]; args[1] = in[3]; args[2] = in[4];
    u32 transport = send_request(handle);
    out[0] = ((u64)transport << 32) | seq;
    // The reply from the TLS: the fw23 reply = SFCO@+0x20, result@+0x28
    // (the respond() epilogue's own shape). Copy TLS words 0..0x60.
    for (u32 i = 0; i < 12; i++) out[2 + i] = ((u64 *)p)[i];
    for (u32 i = 0; i < 12; i++) out[14 + i] = ((u64 *)p)[12 + i];
    return 26 * 8;
}
// The .data.cave anchor: layout.ld KEEP()s this section first in .data (the
// exec rig's blob page once lived here; the anchor preserves the layout).
__attribute__((used, section(".data.cave"), aligned(0x1000))) static u8 dataAnchor[0x1000];
static volatile u32 bootSmHandle;
// Deferred-op queue: the rig can only QUEUE ops (it runs mid-request inside
// respond()); main's clean-state loop (between receives — where
// register_service provably works) executes them and stores the results.
// deferOp[0] = kind (1 = GSH, 2 = HIPC2 send); [1..7] = params.
// deferState: 0 idle, 1 queued, 2 done.
static volatile u64 deferOp[8];
static volatile u32 deferState;
static volatile u64 deferResult[8];
// The debug-relay (restored 2026-10-27): the executor polls with RELAY_TAG,
// the PC queues ops via rig sub 17 and reads reports via sub 18.
#define RELAY_TAG 0x524f0100u
#define RELAY_MAGIC 0x32594c5232455845ULL // "EXE2RLY2"
static volatile u64 relayCmd[4];   // op, a0, a1, a2 (op 0 = sleep)
static volatile u64 relayCmdReady;
static u64 relayReport[16];       // seq, status, op, result, value, data[12]
static volatile u64 relaySeq;
static volatile u64 payloadStamp = 0x20261027ULL; // the .data keeper + a version stamp // the boot sm port (register_service's proven transport)
// Sub 25: queue a GSH on the boot sm port (executed by main's clean loop).
// in[0] = the 8-char name, in[1] = space (0 legacy shape / 1 / 2).
// Sub 27: queue an HIPC2/cmif send (in[1]=handle|wc, in[2]=cmd|seq,
// in[3..5]=args, in[6]=tag). Sub 28: poll {state, result[0..7]}.
static u32 rigDeferQueue(u64 *out, const u64 *in, u64 kind) {
    if (deferState == 1) {out[0] = 0xdead0001; return 8;} // busy: poll first
    deferOp[0] = kind;
    for (u32 i = 0; i < 7; i++) deferOp[1 + i] = in[i];
    deferState = 1;
    out[0] = deferState; out[1] = deferResult[0];
    return 16;
}
static u32 rigDeferPoll(u64 *out) {
    out[0] = deferState;
    for (u32 i = 0; i < 8; i++) out[1 + i] = deferResult[i];
    return 9 * 8;
}

// Sub 24: THE TLS-armed-thread combo — the request from the buffer (svc 0x22,
// the executor's transport) + the reply read from the TLS (the SDK-armed
// thread's receive area). The one-two that matches BOTH proven clients.
static u32 hipc2SendCombo(u64 *out, const u64 *in) {
    u32 handle = (u32)in[0];
    u32 wc = (u32)(in[0] >> 32);
    u32 *p = (u32 *)hipc2Frame;
    for (u32 i = 0; i < 512; i++) hipc2Frame[i] = 0;
    p[0] = (u32)in[5]; p[1] = wc;
    p[4] = 0x49434653;
    p[5] = 1;
    p[6] = (u32)in[1];
    p[7] = (u32)(in[1] >> 32);
    hipc2Frame[4] = in[2]; hipc2Frame[5] = in[3]; hipc2Frame[6] = in[4];
    register u64 x0 __asm__("x0") = (u64)hipc2Frame;
    register u64 x1 __asm__("x1") = 4096;
    register u64 x2 __asm__("x2") = handle;
    __asm__ volatile("svc #0x22" : "+r"(x0) : "r"(x1), "r"(x2) : "memory");
    u32 transport = (u32)x0;
    out[0] = ((u64)transport << 32) | p[7];
    // The reply: the TLS words first (the TLS-armed thread's receive area),
    // then the buffer words — whichever holds the reply becomes obvious.
    u32 *t = message();
    for (u32 i = 0; i < 12; i++) out[2 + i] = ((u64 *)t)[i];
    for (u32 i = 0; i < 10; i++) out[14 + i] = hipc2Frame[i];
    return 24 * 8;
}

// Sub 23: the buffer variant — the request AND reply via hipc2Frame/svc 0x22.
static u32 rigHipc2Send(u64 *out, const u64 *in) {
    u32 handle = (u32)in[0];
    u32 wc = (u32)(in[0] >> 32);
    u32 *p = (u32 *)hipc2Frame;
    for (u32 i = 0; i < 512; i++) hipc2Frame[i] = 0;
    p[0] = (u32)in[5]; p[1] = wc;
    p[4] = 0x49434653;
    p[5] = 1;
    p[6] = (u32)in[1];
    p[7] = (u32)(in[1] >> 32);
    hipc2Frame[4] = in[2]; hipc2Frame[5] = in[3]; hipc2Frame[6] = in[4];
    register u64 x0 __asm__("x0") = (u64)hipc2Frame;
    register u64 x1 __asm__("x1") = 4096;
    register u64 x2 __asm__("x2") = handle;
    __asm__ volatile("svc #0x22" : "+r"(x0) : "r"(x1), "r"(x2) : "memory");
    u32 transport = (u32)x0;
    out[0] = ((u64)transport << 32) | p[7];
    for (u32 i = 0; i < 19; i++) out[2 + i] = hipc2Frame[i];
    return 21 * 8;
}

static u32 register_service(u32 sm, u32 space, const char *name, u32 *last_result) {
    u32 *p = message();
    clear(p);
    p[0] = 0x12;
    p[1] = 5;
    p[2] = space;
    for (u32 i = 0; name[i] && i < 8; i++) ((u8 *)p)[12 + i] = name[i];
    p[5] = 4; // max sessions; the following bool is false (normal IPC).
    u32 transport = send_request(sm);
    if (transport) { *last_result = transport; return 0; }
    if (p[0] != 0x12 || p[1] != 0x80000001 || p[2] != 0x20) {
        *last_result = 0xffffffff;
        return 0;
    }
    *last_result = p[4];
    return p[4] ? 0 : p[3];
}

static Reply respond(u32 session, u64 registration_result) {
    u32 *p = message();
    u32 at = 2, handle = 0, valid = p[0] == 4 || p[0] == 0x01000004;
    u64 receive_address = 0, receive_size = 0;
    if (valid && p[1] >> 31) {
        u32 special = p[at++];
        // Process probes accept one copied handle and an optional kernel PID.
        valid = (special & ~1u) == 2;
        if (special & 1) at += 2;
        if (valid) handle = p[at++];
    }
    if (valid && p[0] == 0x01000004) {
        // One kernel-validated receive map-alias buffer, used only for bulk reads.
        u32 flags = p[at + 2];
        receive_size = p[at] | ((u64)((flags >> 24) & 15) << 32);
        receive_address = p[at + 1] | ((u64)(flags >> 28) << 32) |
            ((u64)((flags >> 2) & 7) << 36);
        at += 3;
    }
    u32 raw_words = p[1] & 0x3ff;
    u32 end = at + raw_words;
    at = (at + 3) & ~3u;
    valid = valid && end <= 64 && end >= at + 4 && p[at] == 0x49434653;
    u32 command = valid ? p[at + 2] : 0;
    if (valid) {
    }
    u64 output[24] = {0};
    u32 output_bytes = 48, result = 0xf601;
    Reply pid = process_id(0xffff8001), tid = thread_id(0xffff8000);
    u64 tick = system_tick();
    if (valid && command == 0x524f0001 && !handle && end >= at + 6) {
        output[0] = 0x4558454f5232534eULL;
        output[1] = ((u64 *)(p + at + 4))[0] ^ 0x9d7c3a51e6b2048fULL;
        output[2] = pid.value; output[3] = tid.value;
        output[4] = tick; output[5] = registration_result;
        result = 0;
    } else if (valid && command == 0x524f0002 && !handle && end >= at + 5) {
        // Side-channel rig: input[0]=sub-command, input[1]=argument.
        u64 sub = ((u64 *)(p + at + 4))[0];
        u64 arg = ((u64 *)(p + at + 4))[1];
        output[0] = 0x47495232464f524eULL; // "NR2FR2IG" little-endian tag
        output[1] = sub; output[2] = arg;
        u64 *out = &output[3];
        u32 bytes = 0;
        if (sub == 21) {
            // Buffer send (svc 0x22): in[1]=handle|wc, in[2]=cmd|seq, in[3..5]=args+tag.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = rigHipc2Send(out, in + 1);
        } else if (sub == 23) {
            // TLS send (svc 0x21, the real sequence): same input shape.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = hipc2SendTls(out, in + 1);
        } else if (sub == 24) {
            // The combo: buffer request (svc 0x22) + TLS reply read.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = hipc2SendCombo(out, in + 1);
        } else if (sub == 25) {
            // Queue a GSH on the boot sm port: in[1] = the 8-char name.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = rigDeferQueue(out, in + 1, 1);
        } else if (sub == 29) {
            // Queue the EXECUTOR-RECIPE GSH: in[1] = the 8-char name.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = rigDeferQueue(out, in + 1, 3);
        } else if (sub == 27) {
            // Queue a send: in[1]=handle|wc, in[2]=cmd|seq, in[3..5]=args, in[6]=tag.
            const u64 *in = (const u64 *)(p + at + 4);
            bytes = rigDeferQueue(out, in + 1, 2);
        } else if (sub == 28) {
            bytes = rigDeferPoll(out);
        } else if (sub == 17 && end >= at + 9) {
            // Relay put: queue {op, a0, a1, a2} for the executor's next poll.
            const u64 *in = (const u64 *)(p + at + 4);
            relayCmd[0] = in[1]; relayCmd[1] = in[2];
            relayCmd[2] = in[3]; relayCmd[3] = in[4];
            relayCmdReady = 1;
            out[0] = relaySeq; out[1] = relayCmdReady;
            bytes = 16;
        } else if (sub == 18) {
            // Relay get: the latest executor report block.
            out[0] = relaySeq;
            for (u32 i = 0; i < 16; i++) out[1 + i] = relayReport[i];
            bytes = 17 * 8;
        }
        output_bytes = 24 + bytes;
        result = 0;
    } else if (valid && command == RELAY_TAG && !handle && end >= at + 21) {
        // Debug-relay executor poll: input = {magic, status, op, result,
        // value, data[12]}. Store the report, then answer with the queued
        // command or an all-zero SLEEP reply. The executor re-polls in 10 ms.
        const u64 *in = (const u64 *)(p + at + 4);
        if (in[0] == RELAY_MAGIC) {
            relayReport[0] = ++relaySeq;
            for (u32 i = 0; i < 15; i++) relayReport[1 + i] = in[1 + i];
            if (relayCmdReady) {
                for (u32 i = 0; i < 4; i++) output[i] = relayCmd[i];
                relayCmdReady = 0;
            }
            output_bytes = 32;
            result = 0;
        }
    } else if (valid && handle) {
        result = process_request(command, (u64 *)(p + at + 4),
            (end - at - 4) * 4, handle, output, &output_bytes,
            (void *)receive_address, receive_size);
    }
    if (handle) close_handle(handle);
    clear(p);
    p[1] = 0x80000000 | ((32 + output_bytes + 3) / 4);
    p[2] = 1; // The kernel inserts our PID into the reply descriptor.
    p[8] = 0x4f434653; // SFCO, after the special-header alignment.
    p[10] = result;
    u64 *out = (u64 *)(p + 12);
    for (u32 i = 0; i < (output_bytes + 7) / 8; i++) out[i] = output[i];
    return reply_receive((const u32 *)0, 0, session, 0);
}

__attribute__((noreturn)) void main(void) {
    Reply connected;
    do {
        connected = connect_port("sm:");
        if (connected.result) sleep_thread(50000000);
    } while (connected.result);
    u32 sm = connected.value;
    bootSmHandle = sm; // the rig's sub 25 does the GSH on THIS proven port
    u32 *p = message();
    clear(p);
    p[0] = 0x10;
    p[1] = 0x80000000;
    p[2] = 1;
    // The real ro's verification (its FUN_0001cc60): the reply echo must read
    // 0x8000000100000010 (masked == 0x100000010) and the result word be zero.
    // A silently-dropped send leaves the REQUEST bytes in the TLS and fails
    // the echo check — unlike the bare p[2] check, which a drop also passes.
    {
        u64 *q = (u64 *)p;
        if (send_request(sm) || p[2] || (q[0] & 0x800003ffffffffffULL) != 0x100000010ULL)
            for (;;) sleep_thread(1000000000);
    }

    u32 ports[2] = {0, 0}, sessions[4] = {0, 0, 0, 0};
    u32 registration[2] = {0, 0};
    for (;;) {
        // Native RO registers ro:1 only in space 1. Space 2 is optional here.
        if (!ports[0]) ports[0] = register_service(sm, 2, "ro:1", &registration[0]);
        // If stock RO owns this name, retain it until the controller frees it.
        if (!ports[1]) ports[1] = register_service(sm, 1, "ro:dmnt", &registration[1]);
        // The deferred op: executed HERE (the clean state — between receives,
        // exactly where register_service's sends provably work).
        if (deferState == 1) {
            deferState = 0;
            u32 *p = message();
            clear(p);
            u64 *params = (u64 *)deferOp;
            if (params[0] == 3) {
                // THE EXECUTOR-RECIPE GSH (the only GSH recipe ever proven on
                // fw23 — the v10 executor's probes resolved both names):
                // a FRESH sm: session + InitializeClient, then the LEGACY-shape
                // GSH sent via svc 0x22 from the 4096-aligned buffer, the
                // reply read back from the buffer. The monitor never tested
                // fresh-session + buffer transport together. params[1] = name.
                Reply c = connect_port("sm:");
                if (c.result) {
                    deferResult[0] = 0xdead0002;
                    deferResult[1] = (u64)c.result;
                } else {
                    u32 *b = (u32 *)hipc2Frame;
                    for (u32 i = 0; i < 512; i++) hipc2Frame[i] = 0;
                    b[0] = 0x10; b[1] = 0x80000000; b[2] = 1;
                    register u64 x0 __asm__("x0") = (u64)hipc2Frame;
                    register u64 x1 __asm__("x1") = 4096;
                    register u64 x2 __asm__("x2") = (u32)c.value;
                    __asm__ volatile("svc #0x22" : "+r"(x0) : "r"(x1), "r"(x2) : "memory");
                    u32 init_t = (u32)x0;
                    u64 *q = (u64 *)b;
                    u64 init_echo = (init_t == 0 && b[2] == 0)
                        ? (q[0] & 0x800003ffffffffffULL) : 0xdead0003;
                    for (u32 i = 0; i < 512; i++) hipc2Frame[i] = 0;
                    b[0] = 0x11; b[1] = 2;
                    for (u32 i = 0; i < 8; i++) ((u8 *)b)[8 + i] = (u8)(params[1] >> (8 * i));
                    x0 = (u64)hipc2Frame; x1 = 4096; x2 = (u32)c.value;
                    __asm__ volatile("svc #0x22" : "+r"(x0) : "r"(x1), "r"(x2) : "memory");
                    u32 gsh_t = (u32)x0;
                    deferResult[0] = ((u64)init_t << 32) | gsh_t;
                    deferResult[1] = init_echo;
                    for (u32 i = 0; i < 6; i++) deferResult[2 + i] = q[i];
                    close_handle((u32)c.value);
                }
            } else if (params[0] == 1) {
                // GSH on the boot sm port. The real ro's RegisterService proves
                // the evolved TIPC arg layout: space (u32) at TLS+8, the name
                // string at TLS+0xc. params[2] selects: 0 = the legacy HOS1
                // shape (name u64 at +8, no space word), 1/2 = the evolved
                // shape with that space word.
                p[0] = 0x11; p[1] = 2;
                if (params[2] == 0) {
                    for (u32 i = 0; i < 8; i++) ((u8 *)p)[8 + i] = (u8)(params[1] >> (8 * i));
                } else {
                    p[2] = (u32)params[2];
                    for (u32 i = 0; i < 8; i++) ((u8 *)p)[12 + i] = (u8)(params[1] >> (8 * i));
                }
                u32 transport = send_request(bootSmHandle);
                deferResult[0] = ((u64)transport << 32) | p[2];
                deferResult[1] = ((u64)p[4] << 32) | p[3];
                for (u32 i = 0; i < 8; i++) deferResult[2 + i] = ((u64 *)p)[i];
            } else {
                // The HIPC2/cmif send via the TLS (svc 0x21).
                u32 handle = (u32)params[1];
                u32 wc = (u32)(params[1] >> 32);
                p[0] = (u32)params[7]; p[1] = wc;
                p[4] = 0x49434653; p[5] = 1;
                p[6] = (u32)params[2]; p[7] = (u32)(params[2] >> 32);
                u64 *args = (u64 *)(p + 8);
                args[0] = params[3]; args[1] = params[4]; args[2] = params[5];
                u32 transport = send_request(handle);
                deferResult[0] = ((u64)transport << 32) | p[7];
                for (u32 i = 0; i < 12; i++) deferResult[1 + i] = ((u64 *)p)[i];
            }
            deferState = 2;
        }
        u32 handles[6], kinds[6], count = 0;
        for (u32 i = 0; i < 2; i++) if (ports[i]) {
            handles[count] = ports[i]; kinds[count++] = i;
        }
        for (u32 i = 0; i < 4; i++) if (sessions[i]) {
            handles[count] = sessions[i]; kinds[count++] = 2 + i;
        }
        if (!count) { sleep_thread(50000000); continue; }
        // A receive without a reply target needs a blank receive header.
        // This call waits for either a port connection or a session request.
        clear(message());
        Reply ready = reply_receive(handles, count, 0, 50000000);
        if (ready.value >= count) continue;
        u32 kind = kinds[ready.value];
        if (ready.result) {
            if (ready.result == 0xf601 && kind >= 2) {
                close_handle(sessions[kind - 2]); sessions[kind - 2] = 0;
            }
            continue;
        }
        if (kind < 2) {
            Reply accepted = accept_session(ports[kind]);
            if (accepted.result) continue;
            u32 slot = 0;
            while (slot < 4 && sessions[slot]) slot++;
            if (slot < 4) sessions[slot] = accepted.value;
            else close_handle(accepted.value);
        } else {
            u32 slot = kind - 2;
            if (message()[0] == 2) {
                close_handle(sessions[slot]); sessions[slot] = 0;
            } else {
                Reply sent = respond(sessions[slot], ((u64)registration[1] << 32) | registration[0]);
                if (sent.result == 0xf601) { close_handle(sessions[slot]); sessions[slot] = 0; }
            }
        }
    }
}
