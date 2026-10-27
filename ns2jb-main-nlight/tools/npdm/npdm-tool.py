#!/usr/bin/env python3
"""NPDM decoder — HOS 23 (Switch 2) layout, empirically verified against
ro's policy on live fw 23.0.1 (FINDINGS/escalation track).

Layout notes (vs the pre-20 wiki layout):
- META: aci_off@0x70, aci_size@0x74, acid_off@0x78, acid_size@0x7C
  (file-relative).
- ACID: sig(0x100) + key(0x100) + [0x100 extra on fw23] + magic 'ACID' —
  magic found by SEARCH, fields at magic+0x30/0x34 are kc_off/kc_size,
  and the offset VALUES are relative to the acid SECTION start (sig),
  i.e. file[acid_off + kc_off].
- ACI0: unchanged — kc_off@aci+0x30, kc_size@aci+0x34 (ACI0-relative).
- KAC descriptors: u32, type = count of trailing 1-bits (hactool kac_print):
  3 ThreadInfo, 4 EnableSystemCalls (SVC mask: bits24 = (d>>5)&0xFFFFFF,
  index = (d>>29)&7 -> svc = index*24 + bit), 6 MemoryMap, 7 IoMemoryMap,
  10 MemoryRegionMap, 11 Interrupts, 13 MiscParams, 14 KernelVersion,
  15 HandleTableSize, 16 MiscFlags (0xFFFFFFFF invalid).
"""
import sys, struct, json

SVC_NAMES = {
    0x01:'SetHeapSize',0x02:'SetMemoryPermission',0x03:'SetMemoryAttribute',0x04:'MapMemory',
    0x05:'UnmapMemory',0x06:'QueryMemory',0x07:'ExitProcess',0x08:'CreateThread',0x09:'StartThread',
    0x0A:'ExitThread',0x0B:'SleepThread',0x0C:'GetThreadPriority',0x0D:'SetThreadPriority',
    0x0E:'GetThreadCoreMask',0x0F:'SetThreadCoreMask',0x10:'GetCurrentProcessorNumber',
    0x11:'SignalEvent',0x12:'ClearEvent',0x13:'MapSharedMemory',0x14:'UnmapSharedMemory',
    0x15:'CreateTransferMemory',0x16:'CloseHandle',0x17:'ResetSignal',0x18:'WaitSynchronization',
    0x19:'CancelSynchronization',0x1A:'ArbitrateLock',0x1B:'ArbitrateUnlock',
    0x1C:'WaitProcessWideKeyAtomic',0x1D:'SignalProcessWideKey',0x1E:'GetSystemTick',
    0x1F:'ConnectToNamedPort',0x20:'SendSyncRequestLight',0x21:'SendSyncRequest',
    0x22:'SendSyncRequestWithUserBuffer',0x23:'SendAsyncRequestWithUserBuffer',
    0x24:'GetProcessId',0x25:'GetThreadId',0x26:'Break',0x27:'OutputDebugString',
    0x28:'ReturnFromException',0x29:'GetInfo',0x2A:'FlushEntireDataCache',0x2B:'FlushDataCache',
    0x2C:'MapPhysicalMemory',0x2D:'UnmapPhysicalMemory',0x2E:'GetDebugFutureThreadInfo',
    0x2F:'GetLastThreadInfo',0x30:'GetResourceLimitLimitValue',0x31:'GetResourceLimitCurrentValue',
    0x32:'SetThreadActivity',0x33:'GetThreadContext3',0x34:'WaitForAddress',0x35:'SignalToAddress',
    0x36:'SynchronizePreemptionState',0x37:'GetResourceLimitPeakValue',
    0x39:'CreateIoPool',0x3A:'CreateIoRegion',
    0x3C:'KernelDebug',0x3D:'ChangeKernelTraceState',
    0x40:'CreateSession',0x41:'AcceptSession',0x42:'ReplyAndReceiveLight',0x43:'ReplyAndReceive',
    0x44:'ReplyAndReceiveWithUserBuffer',0x45:'CreateEvent',
    0x46:'MapIoRegion',0x47:'UnmapIoRegion',
    0x48:'MapPhysicalMemoryUnsafe',0x49:'UnmapPhysicalMemoryUnsafe',0x4A:'SetUnsafeLimit',
    0x4B:'CreateCodeMemory',0x4C:'ControlCodeMemory',
    0x4D:'SleepSystem',0x4E:'ReadWriteRegister',0x4F:'SetProcessActivity',
    0x50:'CreateSharedMemory',0x51:'MapTransferMemory',0x52:'UnmapTransferMemory',
    0x53:'CreateInterruptEvent',0x54:'QueryPhysicalAddress',0x55:'QueryMemoryMapping',
    0x56:'CreateDeviceAddressSpace',0x57:'AttachDeviceAddressSpace',0x58:'DetachDeviceAddressSpace',
    0x59:'MapDeviceAddressSpaceByForce',0x5A:'MapDeviceAddressSpaceAligned',
    0x5B:'MapDeviceAddressSpace',0x5C:'UnmapDeviceAddressSpace',
    0x5D:'InvalidateProcessDataCache',0x5E:'StoreProcessDataCache',0x5F:'FlushProcessDataCache',
    0x60:'DebugActiveProcess',0x61:'BreakDebugProcess',0x62:'TerminateDebugProcess',
    0x63:'GetDebugEvent',0x64:'ContinueDebugEvent',0x65:'GetProcessList',0x66:'GetThreadList',
    0x67:'GetDebugThreadContext',0x68:'SetDebugThreadContext',0x69:'QueryDebugProcessMemory',
    0x6A:'ReadDebugProcessMemory',0x6B:'WriteDebugProcessMemory',0x6C:'SetHardwareBreakPoint',
    0x6D:'GetDebugThreadParam',
    0x6F:'GetSystemInfo',0x70:'CreatePort',0x71:'ManageNamedPort',0x72:'ConnectToPort',
    0x73:'SetProcessMemoryPermission',0x74:'MapProcessMemory',0x75:'UnmapProcessMemory',
    0x76:'QueryProcessMemory',0x77:'MapProcessCodeMemory',0x78:'UnmapProcessCodeMemory',
    0x79:'CreateProcess',0x7A:'StartProcess',0x7B:'TerminateProcess',0x7C:'GetProcessInfo',
    0x7D:'CreateResourceLimit',0x7E:'SetResourceLimitLimitValue',
    0x7F:'CallSecureMonitor',
    0x80:'SetGpuMemoryAttribute',0x81:'LockGpuSharableMemory',0x82:'UnlockGpuSharableMemory',
    0x90:'MapInsecurePhysicalMemory',0x91:'UnmapInsecurePhysicalMemory',
}
INTERESTING = ['0x60','0x61','0x62','0x63','0x64','0x65','0x66','0x67','0x68','0x69',
               '0x6A','0x6B','0x6C','0x6D','0x79','0x7A','0x7B','0x7C','0x7D','0x7E',
               '0x7F','0x4E','0x54','0x55','0x56','0x57','0x58','0x59','0x5A','0x5B','0x5C',
               '0x3C','0x4D','0x48','0x4A','0x82','0x81']

def trailing_ones(d):
    t = 0
    while d & 1: d >>= 1; t += 1
    return t

def decode_kac(data):
    mask = [False]*128
    other = []
    for i in range(0, len(data), 4):
        d = struct.unpack_from('<I', data, i)[0]
        t = trailing_ones(d)
        if t == 4:
            idx = (d >> 29) & 7
            bits = (d >> 5) & 0xFFFFFF
            for b in range(24):
                s = idx*24 + b
                if s < 128: mask[s] = mask[s] or bool((bits >> b) & 1)
        else:
            other.append((t, d >> (t+1)))
    return mask, other

def parse(path):
    b = open(path, 'rb').read()
    u32 = lambda o: struct.unpack_from('<I', b, o)[0]
    out = {'file': path, 'size': len(b)}
    assert b[:4] == b'META', 'no META'
    out['title'] = b[0x20:0x30].split(b'\0')[0].decode(errors='replace')
    aci_off, aci_size = u32(0x70), u32(0x74)
    acid_off, acid_size = u32(0x78), u32(0x7C)
    out['aci'] = {'off': aci_off, 'size': aci_size}
    out['acid'] = {'off': acid_off, 'size': acid_size, 'magic_at': b.find(b'ACID')}
    assert b[aci_off:aci_off+4] == b'ACI0', 'no ACI0'
    kac_off, kac_size = u32(aci_off+0x30), u32(aci_off+0x34)
    mask, other = decode_kac(b[aci_off+kac_off:aci_off+kac_off+kac_size])
    out['aci0'] = {'svc': [i for i,v in enumerate(mask) if v], 'other': other}
    # ACID: fields at magic+0x30/0x34, offset VALUES relative to acid section start
    magic_at = out['acid']['magic_at']
    acid_kac_off, acid_kac_size = u32(magic_at+0x30), u32(magic_at+0x34)
    mask2, other2 = decode_kac(b[acid_off+acid_kac_off:acid_off+acid_kac_off+acid_kac_size])
    out['acid_kac'] = {'svc': [i for i,v in enumerate(mask2) if v], 'other': other2}
    # intersection (final process permissions, userspace)
    out['final_svc'] = [i for i in range(128) if mask[i] and mask2[i]]
    return out

if __name__ == '__main__':
    rows = [parse(p) for p in sys.argv[1:]]
    for r in rows:
        svc = r['final_svc']
        named = {('%02x' % s): SVC_NAMES.get(s, '?') for s in svc}
        interesting = [n for n in INTERESTING if int(n, 16) in svc]
        print('%s  title=%-8r %d svc final | interesting: %s' % (
            r['file'].split('/')[-2].replace('-code-','->'), r['title'], len(svc),
            ', '.join('%s(%s)' % (SVC_NAMES.get(int(n,16),'?'), n) for n in interesting) or '(none)'))
    if len(rows) > 1:
        print()
        print(json.dumps({r['file'].split('/')[-2].split('-code-')[-1]:
            {'title': r['title'], 'n_svc': len(r['final_svc']),
             'interesting': [SVC_NAMES.get(int(n,16),'?') for n in INTERESTING if int(n,16) in r['final_svc']]}
            for r in rows}, indent=1))