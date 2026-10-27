.section .text.start,"ax",%progbits
.global _start
_start:
    b main
    .word module_header - _start
    .word 0

.text
// Pure-client SVC wrappers (creport policy: all of these are inside the
// 49-SVC mask). No server-side primitives are emitted anywhere.
.global connect_port
connect_port:                       // svc 0x1f: x1=name -> w0 result, x1 handle
    mov x1, x0
    svc #0x1f
    mov w0, w0
    ret
.global send_request
send_request:                       // svc 0x21: x0=handle, message at TLS
    svc #0x21
    mov w0, w0
    ret
.global send_buffer
send_buffer:                        // svc 0x22: x0=buffer x1=size x2=handle
    svc #0x22
    mov w0, w0
    ret
.global close_handle
close_handle:                       // svc 0x16: w0=handle
    svc #0x16
    mov w0, w0
    ret
.global sleep_thread
sleep_thread:                       // svc 0x0b
    svc #0x0b
    ret
.global process_id
process_id:                         // svc 0x24: x1=handle -> w0, x1 pid
    mov x1, x0
    svc #0x24
    mov w0, w0
    ret
.global debug_active
debug_active:                       // svc 0x60: x1=pid -> w0 result, x1 handle
    mov x1, x0
    svc #0x60
    ret
.global debug_read
debug_read:                         // svc 0x6a: x0=buf w1=handle x2=addr x3=size
    svc #0x6a
    mov w0, w0
    ret
.global debug_event
debug_event:                        // svc 0x63: x0=buf w1=handle
    svc #0x63
    mov w0, w0
    ret
.global debug_query
debug_query:                        // svc 0x69: x0=info x1=pageinfo w2=handle x3=addr
    svc #0x69
    mov w0, w0
    ret
.global debug_thread_ctx
debug_thread_ctx:                   // svc 0x67: x0=ctx w1=handle x2=tid
    svc #0x67
    mov w0, w0
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

