// GHIRUST objective export script for Ghidra headless analysis.
//
// This script is a prototype. It has NOT been executed in the GHIRUST
// development environment because no Java runtime/JDK is installed. No Ghidra
// output or compatibility claim exists until it runs successfully and its
// output is stored next to the GHIRUST analysis.
//
// Usage from analyzeHeadless:
//   -postScript ExportFunctions.java <output.ndjson>
//
// The script writes one JSON object per function:
//   {"name":..., "address":"0x...", "size":N, "decompiled":"..."}
// JSON is escaped manually to avoid assuming a particular Gson classpath.
//
// @category GHIRUST

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: ExportFunctions.java <output.ndjson>");
            return;
        }
        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler could not open the program");
        }

        int written = 0;
        try (PrintWriter writer = new PrintWriter(
                new BufferedWriter(new FileWriter(output)))) {
            FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function function = functions.next();
                DecompileResults results =
                    decompiler.decompileFunction(function, 60, monitor);
                String text = "";
                if (results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                    text = results.getDecompiledFunction().getC();
                }
                writer.print("{\"name\":\"" + escape(function.getName()) + "\"");
                writer.print(",\"address\":\"0x"
                        + Long.toHexString(function.getEntryPoint().getOffset()) + "\"");
                writer.print(",\"size\":" + function.getBody().getNumAddresses());
                writer.print(",\"decompiled\":\"" + escape(text) + "\"}");
                writer.print("\n");
                written++;
            }
        } finally {
            decompiler.dispose();
        }
        println("GHIRUST: exported " + written + " function(s) to " + output);
    }

    private static String escape(String value) {
        StringBuilder builder = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '\\': builder.append("\\\\"); break;
                case '"': builder.append("\\\""); break;
                case '\n': builder.append("\\n"); break;
                case '\r': builder.append("\\r"); break;
                case '\t': builder.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
            }
        }
        return builder.toString();
    }
}
