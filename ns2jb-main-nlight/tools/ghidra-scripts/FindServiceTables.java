// FindServiceTables: locate fsp-srv/fsp-pr/fsp-ldr/fsp-ldr dispatch tables by
// the name-reference sites, decompile the registration + dispatch functions.
//@category fw23
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class FindServiceTables extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = System.getProperty("user.home") + "/dev/ns2jb/fw-re/out/fs-live.elf.services.c";
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        // name string addresses (from strings dump)
        Map<String, Long> names = new HashMap<>();
        names.put("fsp-srv", 0x5992242fa4L);
        names.put("fsp-pr", 0x5992242facL);
        names.put("fsp-ldr", 0x5992242fb3L);
        ReferenceManager rm = currentProgram.getReferenceManager();
        Set<Function> targets = new LinkedHashSet<>();
        try (PrintWriter f = new PrintWriter(out)) {
            for (Map.Entry<String, Long> e : names.entrySet()) {
                Address sa = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(e.getValue());
                f.println("// ===== refs to \"" + e.getKey() + "\" =====");
                for (Reference r : rm.getReferencesTo(sa)) {
                    Address from = r.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    f.println("// ref at " + from + (fn != null ? " in " + fn.getName() + " @ " + fn.getEntryPoint() : " (no fn)"));
                    if (fn != null) targets.add(fn);
                }
            }
            // also decompile every function in a window around the fsp-pr ref site
            long[] windows = {0x599201154cL, 0x5992011500L, 0x5992011f70L};
            for (long w : windows) {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(w);
                Address start = a.subtract(0x200);
                for (Address cur = start; cur.compareTo(a.add(0x200)) < 0; ) {
                    Function fn = getFunctionContaining(cur);
                    if (fn != null) {
                        if (targets.add(fn)) {}
                        cur = fn.getBody().getMaxAddress().add(4);
                    } else {
                        if (createFunction(cur, null) != null) { continue; }
                        cur = cur.add(4);
                    }
                }
            }
            f.println("// total functions: " + targets.size());
            for (Function fn : targets) {
                f.println("// ===== " + fn.getName() + " @ " + fn.getEntryPoint() + " =====");
                DecompileResults res = dec.decompileFunction(fn, 120, monitor);
                if (res.getDecompiledFunction() != null)
                    f.println(res.getDecompiledFunction().getC());
                else
                    f.println("// decompile failed: " + res.getErrorMessage());
            }
        }
        dec.dispose();
        println("FindServiceTables done -> " + out);
    }
}