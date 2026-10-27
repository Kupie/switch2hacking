// creport-policy debug executor. Launched as a SECOND process under a
// sysmodule title whose NPDM carries the debug suite (creport
// 0x0400000000000036: DebugActiveProcess(0x60), ReadDebugProcessMemory(0x6A),
// QueryDebugProcessMemory(0x69), GetDebugEvent(0x63),
// GetDebugThreadContext(0x67), GetDebugThreadParam(0x6D)) - but no
// server-side session SVCs (0x40-0x45) and no process-memory suite.
// So this payload is a PURE IPC CLIENT: it connects to the RO monitor's
// ro:dmnt service and polls for work. Every poll reports the previous op's
// result; the monitor answers with the next queued op or SLEEP. The PC
// drives the queue through the monitor's rig subs 17/18 over the
// app-worker ro:dmnt path.
//
// v7: ALL IPC goes through svc 0x22 (SendSyncRequestWithUserBuffer) with a
// page-aligned static 4096-byte message buffer - NO TLS dependency.
// v4-v6 used svc 0x21 (TLS message at tpidrro_el0): alive but silent under
// 0039, zero requests ever reaching the monitor's ring, and v6's
// 40-attempt crash cap fired => connect/init/GSH persistently failing.
// The OS loader sets up tpidrro for its own processes (monitor, fs worker);
// the TAKEOVER loader does not. svc 0x22 takes the message buffer in
// registers, so it cannot depend on a missing TLS. v1-v3 also used 0x22 but
// died - under the 0036 title, which kills takeover processes (the monitor
// binary dies there too in 45s); 0039/sdb is the proven-safe title.
//
// Ops (reply words from the monitor): {op, a0, a1, a2}
//   0 SLEEP                       - sleep 10 ms, poll again
//   1 ATTACH(pid=a0)              - DebugActiveProcess -> {result, handle}
//   2 READ(handle=a0, addr=a1, size=a2<=96) -> {result, words[12]}
//   3 CLOSE(handle=a0)           - CloseHandle(debug handle) = detach
//   4 PING                        - {magic, own pid}
//   5 EVENT(handle=a0)            - GetDebugEvent -> 96 bytes
//   6 QUERY(handle=a0, addr=a1)  - QueryDebugProcessMemory -> info+pageinfo
//   7 CTX(handle=a0, tid=a1)     - GetDebugThreadContext -> regs
//
// Report layout (every poll request input): {magic, status, op, result,
// value, data[12]}; status bits: 0x1 sm connected, 0x2 ro:dmnt session,
// 0x4 last transport error, 0x8 last reply error, 0x10 sm connect failed,
// 0x20 sm client initialized.
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef struct { u64 result, value; } Reply;
typedef struct { u64 result, handle; } Pair;

extern Reply connect_port(const char *name);   // svc 0x1f: value = handle
extern u32 send_request(u32 handle);           // svc 0x21: TLS message (UNUSED in v7)
extern u32 send_buffer(u64 buffer, u64 size, u32 handle); // svc 0x22: user-buffer message
extern u32 close_handle(u32 handle);           // svc 0x16
extern void sleep_thread(s64 ns);               // svc 0x0b
extern Reply process_id(u32 handle);            // svc 0x24: value = pid
extern Pair debug_active(u64 pid);              // svc 0x60: {result, handle}
extern u32 debug_read(u64 buffer, u32 handle, u64 address, u64 size); // 0x6a
extern u32 debug_event(u64 buffer, u32 handle); // svc 0x63
extern u32 debug_query(u64 info, u64 page_info, u32 handle, u64 address); // 0x69
extern u32 debug_thread_ctx(u64 context, u32 handle, u64 thread_id);     // 0x67

// v7: the message area is a static page-aligned buffer (svc 0x22), NOT the
// TLS at tpidrro_el0 (never set up in takeover-launched processes).
static u64 ipcArea[512] __attribute__((aligned(4096)));
static u32 *message(void) {return (u32 *)ipcArea;}

#define RELAY_TAG 0x524f0100u
#define RELAY_MAGIC 0x32594c5232455845ULL // "EXE2RLY2"
#define SELF 0xffff8001u
// Referenced initialized writable global: keeps a non-empty .data section
// in the NSO layout (the linker drops unreferenced data sections).
static volatile u64 execMarker = 0x32474e5050415045ULL; // "EPAPPNG2"

#define OP_SLEEP 0
#define OP_ATTACH 1
#define OP_READ 2
#define OP_CLOSE 3
#define OP_PING 4
#define OP_EVENT 5
#define OP_QUERY 6
#define OP_CTX 7
#define OP_GSH 8   // a0 = the 8-char name u64: the full fresh-session GSH recipe
#define OP_CMIF 9  // a0 = handle, a1 = {cmd | token<<32}, a2 = one u64 arg

static u64 statusWord;
static u64 lastOp, lastResult, lastValue;
static u64 lastData[12];

static void crash(void) {*(volatile u64 *)0 = 0x4447494458595845ULL;}

static void clear_message(void) {
    u32 *p = message();
    for (u32 i = 0; i < 64; i++) p[i] = 0;
}

static void build_poll(void) {
    clear_message();
    u32 *p = message();
    p[0] = 4;                        // cmif word0: no buffer descriptors
    p[1] = (32 + 136 + 3) / 4;       // payload words, no special section
    p[4] = 0x49434653;               // "SFCI" at byte 16
    p[6] = RELAY_TAG;                // command at byte 24
    u64 *in = (u64 *)(p + 8);        // input at byte 32
    in[0] = RELAY_MAGIC;
    in[1] = statusWord;
    in[2] = lastOp;
    in[3] = lastResult;
    in[4] = lastValue;
    for (u32 i = 0; i < 12; i++) in[5 + i] = lastData[i];
}


// v8 DEATH-CLOCK bisector: each phase sleeps 30s on success, crashes on the
// first failure. Death time (pm:dmnt 0x20f) decodes the failing phase:
//   <10s  connect_port("sm:") failed            (svc 0x1f rejected)
//   ~30s  sm InitializeClient failed           (send_buffer reply bad)
//   ~60s  sm GetServiceHandle("ro:dmnt") failed (name not granted)
//   ~90s  the relay poll transport failed       (session send rejected)
//   ~120s the poll reply is not our monitor's    (GSH went to the REAL ro)
//   alive  FULL CHAIN WORKS -> v8 continues as the real relay loop.
// One attempt per phase (no retry confound). crash() = contained null write.

// v10 ERROR-ECHO death clock. Base phases 1-2 are proven OK (30s sleeps).
// Death time decodes the GSH result for BOTH a SAC-known name (fatal:u) and
// the patched-SAC name (ro:dmnt):
//   ~80s   GSH(fatal:u) transport error      ~100s  GSH(fatal:u) reply shape wrong
//   120-183 GSH(fatal:u) refused: err&0x3f = t-120
//   ~260s  GSH handle zero (granted but empty)
//   after fatal:u OK (+30s), GSH(ro:dmnt) refused: same encoding +200 => 320-383
//   ~280s  poll transport error (GSH WORKED)  ~300s poll reply not ours
//   ~340s  ro:dmnt transport error
//   ALIVE  FULL CHAIN WORKS -> real relay loop
__attribute__((noreturn)) void main(void) {
    // phase 1: connect to sm
    Reply c = connect_port("sm:");
    if (c.result) crash();
    u32 sm = (u32)c.value;
    statusWord |= 0x1;
    sleep_thread(30000000000LL);
    // phase 2: InitializeClient
    clear_message();
    u32 *p = message();
    p[0] = 0x10; p[1] = 0x80000000; p[2] = 1;
    u32 init = send_buffer((u64)ipcArea, 4096, sm);
    if (init || p[2]) crash();
    statusWord |= 0x20;
    sleep_thread(30000000000LL);
    // probe A: GSH("fatal:u") - in creport SAC for sure
    clear_message();
    p = message();
    p[0] = 0x11; p[1] = 2;
    ((u8 *)message())[8] = 'f'; ((u8 *)message())[9] = 'a';
    ((u8 *)message())[10] = 't'; ((u8 *)message())[11] = 'a';
    ((u8 *)message())[12] = 'l'; ((u8 *)message())[13] = ':';
    ((u8 *)message())[14] = 'u';
    u32 gt = send_buffer((u64)ipcArea, 4096, sm);
    if (gt) {sleep_thread(20000000000LL); crash();}                    // death ~80s
    if (p[0] != 0x11 || p[1] != 0x80000001 || p[2] != 0x20) {sleep_thread(40000000000LL); crash();} // ~100s
    if (p[4]) {sleep_thread(60000000000LL + (u64)(p[4] & 0x3f) * 1000000000LL); crash();} // 120-183s: err=t-120
    if (!p[3]) {sleep_thread(200000000000LL); crash();}                // ~260s
    close_handle(p[3]);   // fatal:u resolves! SAC mechanism confirmed live.
    sleep_thread(30000000000LL);
    // probe B: GSH("ro:dmnt") - the patched-SAC name
    clear_message();
    p = message();
    p[0] = 0x11; p[1] = 2;
    ((u8 *)message())[8] = 'r'; ((u8 *)message())[9] = 'o';
    ((u8 *)message())[10] = ':'; ((u8 *)message())[11] = 'd';
    ((u8 *)message())[12] = 'm'; ((u8 *)message())[13] = 'n';
    ((u8 *)message())[14] = 't';
    gt = send_buffer((u64)ipcArea, 4096, sm);
    u32 session = 0;
    if (gt) {sleep_thread(340000000000LL); crash();}                    // ~340s ro transport
    if (p[0] != 0x11 || p[1] != 0x80000001 || p[2] != 0x20) {sleep_thread(320000000000LL); crash();} // ~320s
    if (p[4]) {sleep_thread(320000000000000LL + (u64)(p[4] & 0x3f) * 1000000000LL); crash();} // 320-383s
    if (!p[3]) {sleep_thread(360000000000LL); crash();}                // ~360s
    session = p[3];
    statusWord |= 0x2;
    close_handle(sm);
    sleep_thread(30000000000LL);
    // probe C: ONE relay poll
    build_poll();
    u32 transport = send_buffer((u64)ipcArea, 4096, session);
    if (transport) {statusWord |= 0x4; sleep_thread(280000000000LL); crash();}   // ~280s... (t=120 base)
    p = message();
    if (p[8] != 0x4f434653 || p[10] != 0) {statusWord |= 0x8; sleep_thread(240000000000LL); crash();} // ~300s
    statusWord |= 0x1;
    // FULL CHAIN WORKS: serve as the real relay.
    for (;;) {
        build_poll();
        u32 transport = send_buffer((u64)ipcArea, 4096, session);
        if (transport) {statusWord |= 0x4; sleep_thread(1000000000LL); continue;}
        u32 *p = message();
        if (p[8] != 0x4f434653) {statusWord |= 0x8; sleep_thread(1000000000LL); continue;}
        u32 result = p[10];
        u64 *out = (u64 *)(p + 12);
        if (result) {statusWord |= 0x8; sleep_thread(1000000000LL); continue;}
        u64 op = out[0], a0 = out[1], a1 = out[2], a2 = out[3];
        lastOp = op; lastResult = 0; lastValue = 0;
        for (u32 i = 0; i < 12; i++) lastData[i] = 0;
        if (op == OP_ATTACH) {
            Pair r = debug_active(a0);
            lastResult = r.result; lastValue = r.handle;
        } else if (op == OP_READ) {
            u64 size = a2 > 96 ? 96 : a2;
            lastResult = debug_read((u64)lastData, (u32)a0, a1, size);
            lastValue = size;
        } else if (op == OP_CLOSE) {
            lastResult = close_handle((u32)a0);
        } else if (op == OP_PING) {
            Reply pid = process_id(SELF);
            lastResult = pid.result; lastValue = pid.value; lastData[0] = execMarker;
        } else if (op == OP_EVENT) {
            lastResult = debug_event((u64)lastData, (u32)a0);
        } else if (op == OP_QUERY) {
            lastResult = debug_query((u64)lastData, (u64)(lastData + 8), (u32)a0, a1);
        } else if (op == OP_CTX) {
            lastResult = debug_thread_ctx((u64)lastData, (u32)a0, a1);
        } else if (op == OP_GSH) {
            // The proven executor recipe, parameterized: fresh sm: connect,
            // echo-verified init, legacy-shape GSH via THIS buffer, close.
            // Report: result = init_t<<32 | gsh_t, value = the session
            // handle, data[0..5] = the buffer reply words.
            Reply c = connect_port("sm:");
            if (c.result) { lastResult = 0xdead0002; lastValue = c.result; }
            else {
                u32 esm = (u32)c.value;
                clear_message();
                u32 *b = (u32 *)ipcArea;
                b[0] = 0x10; b[1] = 0x80000000; b[2] = 1;
                u32 init_t = send_buffer((u64)ipcArea, 4096, esm);
                u64 *q = (u64 *)b;
                u64 echo = (init_t == 0 && b[2] == 0)
                    ? (q[0] & 0x800003ffffffffffULL) : 0xdead0003;
                clear_message();
                b[0] = 0x11; b[1] = 2;
                for (u32 i = 0; i < 8; i++) ((u8 *)b)[8 + i] = (u8)(a0 >> (8 * i));
                u32 gsh_t = send_buffer((u64)ipcArea, 4096, esm);
                lastResult = ((u64)init_t << 32) | gsh_t;
                lastValue = ((u64)echo << 32) | b[3];   // echo high, handle low
                for (u32 i = 0; i < 6; i++) lastData[i] = q[i];
                close_handle(esm);
            }
        } else if (op == OP_CMIF) {
            // Arbitrary TIPC send on a handle this process holds: the frame
            // {cmd, token}@+0, a2@+8, the rest zeroed; the reply in data.
            clear_message();
            u32 *b = (u32 *)ipcArea;
            b[0] = (u32)a1; b[1] = (u32)(a1 >> 32);
            ((u64 *)b)[1] = a2;
            u32 t = send_buffer((u64)ipcArea, 4096, (u32)a0);
            lastResult = t;
            lastValue = 0;
            for (u32 i = 0; i < 12; i++) lastData[i] = ((u64 *)b)[i];
        } else {
            lastOp = OP_SLEEP;
            sleep_thread(10000000);
        }
    }
}
