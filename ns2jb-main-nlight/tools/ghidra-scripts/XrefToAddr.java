// XrefToAddr: for each address argument, find all references to it,
// print the referencing instruction + enclosing function, and decompile
// each such function into out/<program>.xref-<ts>.c
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class XrefToAddr extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("need addresses"); return; }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> done = new HashSet<>();
        StringBuilder sb = new StringBuilder();
        for (String a : args) {
            Address t = currentProgram.getAddressFactory().getAddress(a);
            println("xrefs to " + t);
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(t);
            while (it.hasNext()) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Instruction ins = getInstructionAt(from);
                println("  " + from + " " + (ins == null ? "?" : ins.toString()));
                Function f = getFunctionContaining(from);
                if (f != null && !f.isExternal() && done.add(f)) {
                    sb.append("// ==== ").append(f.getName()).append(" @ ")
                      .append(f.getEntryPoint()).append(" (refs ").append(t).append(")\n");
                    DecompileResults res = di.decompileFunction(f, 120, monitor);
                    if (res.getDecompiledFunction() != null)
                        sb.append(res.getDecompiledFunction().getC()).append("\n");
                }
            }
        }
        String root = System.getProperty("user.dir"); // fw-re cwd
        File out = new File(root + "/out/" + currentProgram.getName()
            + ".xref-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}
