// FindErrPair: find movz #low followed within 3 instructions by movk #high
// (lsl 16) — the u32 error-constant construction — and decompile the
// enclosing functions.
//@category fw23
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class FindErrPair extends GhidraScript {
    static boolean hasScalar(Instruction ins, long v) {
        for (int opi = 0; opi < ins.getNumOperands(); opi++)
            for (Object o : ins.getOpObjects(opi))
                if (o instanceof Scalar && ((Scalar) o).getValue() == v) return true;
        return false;
    }
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long lo = Long.decode(args[0]), hi = Long.decode(args[1]);
        Set<Function> fns = new LinkedHashSet<>();
        List<String> sites = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getMnemonicString().equals("movz") || !hasScalar(ins, lo)) continue;
            Instruction p = ins.getNext();
            for (int i = 0; i < 3 && p != null; i++, p = p.getNext()) {
                if (p.getMnemonicString().equals("movk") && hasScalar(p, hi)) {
                    sites.add(ins.getAddress() + " -> " + p.getAddress());
                    Function f = getFunctionContaining(ins.getAddress());
                    if (f != null) fns.add(f);
                    break;
                }
            }
        }
        for (String s : sites) println("pair " + s);
        println("pairs: " + sites.size() + ", functions: " + fns.size());
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        StringBuilder sb = new StringBuilder();
        for (Function f : fns) {
            sb.append("// ==== ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res.getDecompiledFunction() != null)
                sb.append(res.getDecompiledFunction().getC()).append("\n");
        }
        File out = new File(System.getProperty("user.dir") + "/out/" + currentProgram.getName()
            + ".pair-" + System.currentTimeMillis() + ".c");
        out.getParentFile().mkdirs();
        try (Writer w = new FileWriter(out)) { w.write(sb.toString()); }
        println("wrote " + out);
    }
}
