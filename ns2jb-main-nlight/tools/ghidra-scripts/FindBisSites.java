// FindBisSites: scan analyzed instructions for cmp/sub-with-immediate where
// the immediate is a BIS partition id (0,10,27,30,31,35), cluster them, and
// decompile the enclosing functions of tight clusters (the partition switch).
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class FindBisSites extends GhidraScript {
    static final long[] IDS = {0, 10, 27, 30, 31, 35};
    @Override
    public void run() throws Exception {
        Map<Integer, List<Instruction>> at = new TreeMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString();
            if (!(m.startsWith("cmp") || m.startsWith("sub") || m.startsWith("subs"))) continue;
            Object[] ops = ins.getOpObjects(1);
            for (Object o : ops) {
                if (o instanceof ghidra.program.model.scalar.Scalar) {
                    long v = ((ghidra.program.model.scalar.Scalar) o).getValue();
                    for (long id : IDS) {
                        if (v == id) {
                            at.computeIfAbsent((int) id, k -> new ArrayList<>()).add(ins);
                            break;
                        }
                    }
                }
            }
        }
        for (Map.Entry<Integer, List<Instruction>> e : at.entrySet()) {
            println("id " + e.getKey() + ": " + e.getValue().size() + " sites");
            Set<Function> fns = new LinkedHashSet<>();
            for (Instruction ins : e.getValue()) {
                Function f = getFunctionContaining(ins.getAddress());
                if (f != null) fns.add(f);
            }
            int n = 0;
            for (Function f : fns) { println("   fn " + f.getName() + " @ " + f.getEntryPoint()); if (++n > 8) break; }
        }
    }
}
