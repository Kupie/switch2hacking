// XrefDecompile: find functions referencing strings matching a regex (via
// script args: PATTERN or use default) and decompile them.
//@category fw23
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class XrefDecompile extends GhidraScript {
    private String pattern() {
        String[] args = getScriptArgs();
        return args.length > 0 ? args[0] : "ticket|titlekey|ndrm";
    }

    @Override
    public void run() throws Exception {
        String pat = pattern();
        String out = System.getProperty("user.home") + "/dev/ns2jb/fw-re/out/"
            + currentProgram.getName() + ".decomp-" + pat.replaceAll("[^A-Za-z0-9]", "_") + ".c";
        Set<Function> targets = new LinkedHashSet<>();

        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.hasNext() ? di.next() : null;
            if (d == null) break;
            Object val = d.getValue();
            if (val instanceof String && ((String) val).matches(".*(?i:" + pat + ").*")) {
                for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d.getAddress())) {
                    Function fn = getFunctionContaining(r.getFromAddress());
                    if (fn != null) targets.add(fn);
                }
            }
        }

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        try (PrintWriter f = new PrintWriter(out)) {
            f.println("// " + targets.size() + " functions referencing /" + pat + "/");
            for (Function fn : targets) {
                f.println("// ===== " + fn.getName() + " @ " + fn.getEntryPoint() + " =====");
                DecompileResults res = dec.decompileFunction(fn, 60, monitor);
                if (res.getDecompiledFunction() != null)
                    f.println(res.getDecompiledFunction().getC());
                else
                    f.println("// decompile failed: " + res.getErrorMessage());
            }
        }
        dec.dispose();
        println("XrefDecompile done -> " + out);
    }
}
