.section .text.start,"ax",%progbits
.global _start
_start:
    b main
    .word module_header - _start
    .word 0

.text
.global connect_port
connect_port:
    mov x1, x0
    svc #0x1f
    mov w0, w0
    mov w1, w1
    ret
.global send_request
send_request:
    svc #0x21
    ret
.global close_handle
close_handle:
    svc #0x16
    ret
.global sleep_thread
sleep_thread:
    svc #0x0b
    ret
.global wait_handles
wait_handles:
    mov x3, x2
    mov x2, x1
    mov x1, x0
    svc #0x18
    mov w0, w0
    mov w1, w1
    ret
.global reply_receive
reply_receive:
    mov x4, x3
    mov x3, x2
    mov x2, x1
    mov x1, x0
    svc #0x43
    mov w0, w0
    mov w1, w1
    ret
.global accept_session
accept_session:
    mov w1, w0
    svc #0x41
    mov w0, w0
    mov w1, w1
    ret
.global process_id
process_id:
    mov w1, w0
    svc #0x24
    mov w0, w0
    ret
.global thread_id
thread_id:
    mov w1, w0
    svc #0x25
    mov w0, w0
    ret
.global system_tick
system_tick:
    svc #0x1e
    ret

.global get_info
get_info:
    mov x3, x2
    mov w2, w1
    mov w1, w0
    svc #0x29
    mov w0, w0
    ret
.global query_process
query_process:
    mov x3, x2
    mov w2, w1
    svc #0x76
    mov w0, w0
    mov w1, w1
    ret
.global query_memory
query_memory:
    mov x2, x1
    svc #0x6
    mov w0, w0
    mov w1, w1
    ret
.global map_process
map_process:
    svc #0x74
    ret
.global unmap_process
unmap_process:
    svc #0x75
    ret
.global map_code
map_code:
    svc #0x77
    ret
.global unmap_code
unmap_code:
    svc #0x78
    ret
.global process_permission
process_permission:
    svc #0x73
    ret

// Debug-suite SVCs (HOS 23 numbering, switchbrew SVC). These trap unless
// the monitor's NPDM SVC mask includes them (kernel per-process gate): only
// call after launching under a surveyed debug-class policy (creport et al).
// fw23 lesson (JKd5i0, pid-209 monitor death 2026-10-25): the out-pointer
// MUST be a real writable slot - svc 0x60 with x0=pid VALUE (the old wrapper)
// killed the monitor. Pair returns ride x0/x1 (AAPCS64 two-INTEGER struct).
.global debug_active_process
debug_active_process:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    mov x1, x0            // x1 = pid (svc 0x60: x0=Handle* out, x1=process_id)
    add x0, sp, #16       // x0 = &out_handle (stack slot)
    svc #0x60
    mov w0, w0            // zero-extend the result into x0
    ldr w1, [sp, #16]     // x1 = handle (zero-extended)
    ldp x29, x30, [sp], #32
    ret                   // x0 = result, x1 = handle -> Pair{result, handle}
.global debug_read
debug_read:
    svc #0x6a             // buffer, debug_handle, address, size
    mov w0, w0
    ret
.global debug_query
debug_query:
    svc #0x69             // info, page_info, debug_handle, address
    mov w0, w0
    ret
.global debug_write
debug_write:
    svc #0x6b             // debug_handle, buffer, address, size
    mov w0, w0
    ret
// Pass-through GetProcessList (main.c rigDebugProbe bit3): the caller's
// x0/x1/x2 are already the svc ABI. EMPIRICAL WARNING (pASgAv, 2026-10-25):
// svc 0x65 with sane args KILLED the monitor - fw23 numbering is unverified
// and 0x65 is NOT in creport's toolkit. Bit3 = a known monitor-killer phase.
.global get_process_list
get_process_list:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    svc #0x65             // x0=u32* out_count, x1=u64* pids, x2=max (caller ABI)
    mov w0, w0            // zero-extend the result
    ldp x29, x30, [sp], #16
    ret
.global terminate_process
terminate_process:
    mov w1, w0
    svc #0x7b
    mov w0, w0
    ret

.global rig_call
rig_call:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x4, sp
    and x3, x3, #-16
    mov sp, x3
    blr x0
    mov sp, x4
    ldp x29, x30, [sp], #16
    ret

.global memset
memset:
    mov x3, x0
    cbz x2, 2f
1:
    strb w1, [x3], #1
    subs x2, x2, #1
    b.ne 1b
2:
    ret

.section .rodata.module,"a",%progbits
.global module_header
module_header:
    .ascii "MOD0"
    .word dynamic - module_header
    .word __bss_start - module_header
    .word __bss_end - module_header
    .word 0, 0, 0
dynamic:
    .quad 0, 0

.section .data,"aw",%progbits
    .quad 0x4558454f5232534e, 1
