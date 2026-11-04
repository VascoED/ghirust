// GHIRUST objective exporter for Ghidra headless analysis.
//
// Writes newline-delimited JSON (NDJSON). Each line is one record:
//   program, memory, import, function, string.
//
// Function records embed basic blocks, instructions, CFG edges and the
// decompiled C text. The GHIRUST comparison tool normalizes addresses to
// relative virtual addresses (RVA) before comparing.
//
// This script is original code that links against the Ghidra API. No Ghidra
// source file is copied into GHIRUST. Ghidra remains under its own license.
//
// Usage from analyzeHeadless:
//   -postScript ExportProgram.java <output.ndjson> [max-decompiled-functions]
//
// @category GHIRUST

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Locale;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExportProgram extends GhidraScript {
    private static final int MAX_STRINGS = 5000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: ExportProgram.java <output.ndjson> [max-decompiled-functions]");
            return;
        }
        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("could not create " + parent);
        }
        int maxDecompiled = 100000;
        if (args.length > 1) {
            maxDecompiled = Integer.parseInt(args[1]);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler could not open the program");
        }

        try (PrintWriter writer = new PrintWriter(
                new BufferedWriter(new FileWriter(output)))) {
            writeProgram(writer);
            writeMemory(writer);
            writeImports(writer);
            writeFunctions(writer, decompiler, maxDecompiled);
            writeStrings(writer);
        } finally {
            decompiler.dispose();
        }
        println("GHIRUST: exported program to " + output);
    }

    private void writeProgram(PrintWriter writer) {
        StringBuilder line = new StringBuilder();
        line.append("{\"type\":\"program\"");
        field(line, "name", currentProgram.getName());
        field(line, "format", currentProgram.getExecutableFormat());
        field(line, "language", currentProgram.getLanguageID().toString());
        field(line, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        field(line, "image_base", hex(currentProgram.getImageBase()));
        Address entry = null;
        StringBuilder entries = new StringBuilder();
        boolean firstEntry = true;
        AddressIterator entryIterator =
                currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (entryIterator.hasNext()) {
            Address address = entryIterator.next();
            if (entry == null) {
                entry = address;
            }
            if (!firstEntry) {
                entries.append(",");
            }
            firstEntry = false;
            entries.append(quote(hex(address)));
        }
        field(line, "entry", entry == null ? null : hex(entry));
        line.append(",\"entries\":[").append(entries).append("]");
        field(line, "function_count",
                currentProgram.getFunctionManager().getFunctionCount());
        line.append("}");
        writer.println(line);
    }

    private void writeMemory(PrintWriter writer) {
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            StringBuilder line = new StringBuilder();
            line.append("{\"type\":\"memory\"");
            field(line, "name", block.getName());
            field(line, "start", hex(block.getStart()));
            field(line, "end", hex(block.getEnd()));
            field(line, "size", block.getSize());
            field(line, "read", block.isRead());
            field(line, "write", block.isWrite());
            field(line, "execute", block.isExecute());
            field(line, "initialized", block.isInitialized());
            line.append("}");
            writer.println(line);
        }
    }

    private void writeImports(PrintWriter writer) {
        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator symbols = table.getExternalSymbols();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            StringBuilder line = new StringBuilder();
            line.append("{\"type\":\"import\"");
            field(line, "name", symbol.getName());
            String namespace = symbol.getParentNamespace() == null
                    ? "" : symbol.getParentNamespace().getName(true);
            field(line, "namespace", namespace);
            field(line, "address", hex(symbol.getAddress()));
            line.append("}");
            writer.println(line);
        }
    }

    private void writeFunctions(PrintWriter writer, DecompInterface decompiler,
            int maxDecompiled) throws Exception {
        BasicBlockModel model = new BasicBlockModel(currentProgram, true);
        FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);
        int decompiled = 0;
        while (functions.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Function function = functions.next();
            StringBuilder line = new StringBuilder();
            line.append("{\"type\":\"function\"");
            field(line, "name", function.getName());
            field(line, "address", hex(function.getEntryPoint()));
            field(line, "size", function.getBody().getNumAddresses());
            field(line, "external", function.isExternal());
            field(line, "thunk", function.isThunk());
            field(line, "external_entry", hasExternalEntryPoint(function));
            field(line, "calling_convention", function.getCallingConventionName());
            String decompiledText = "";
            if (!function.isExternal() && decompiled < maxDecompiled) {
                DecompileResults results =
                        decompiler.decompileFunction(function, 60, monitor);
                if (results.decompileCompleted()
                        && results.getDecompiledFunction() != null) {
                    decompiledText = results.getDecompiledFunction().getC();
                }
            }
            decompiled++;
            field(line, "decompiled", decompiledText);

            line.append(",\"blocks\":[");
            boolean firstBlock = true;
            CodeBlockIterator blocks =
                    model.getCodeBlocksContaining(function.getBody(), monitor);
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                if (!firstBlock) {
                    line.append(",");
                }
                firstBlock = false;
                appendBlock(line, block, function, model);
            }
            line.append("]}");
            writer.println(line);
        }
    }

    private void appendBlock(StringBuilder line, CodeBlock block, Function function,
            BasicBlockModel model) throws Exception {
        line.append("{\"start\":").append(quote(hex(block.getFirstStartAddress())));
        line.append(",\"end\":").append(quote(hex(block.getMaxAddress())));
        line.append(",\"instructions\":[");
        boolean firstInstruction = true;
        Address address = block.getFirstStartAddress();
        Address maximum = block.getMaxAddress();
        while (address != null && address.compareTo(maximum) <= 0) {
            Instruction instruction =
                    currentProgram.getListing().getInstructionAt(address);
            if (instruction == null) {
                address = address.next();
                continue;
            }
            if (!firstInstruction) {
                line.append(",");
            }
            firstInstruction = false;
            line.append("{\"address\":").append(quote(hex(instruction.getAddress())));
            line.append(",\"mnemonic\":").append(quote(instruction.getMnemonicString()));
            line.append(",\"operands\":").append(quote(operands(instruction)));
            line.append(",\"bytes\":").append(quote(bytes(instruction)));
            line.append(",\"flow\":").append(quote(instruction.getFlowType().toString()));
            line.append("}");
            address = instruction.getMaxAddress().next();
        }
        line.append("],\"edges\":[");
        boolean firstEdge = true;
        CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
        while (destinations.hasNext()) {
            CodeBlockReference reference = destinations.next();
            CodeBlock destination = reference.getDestinationBlock();
            if (destination == null) {
                continue;
            }
            Address destinationStart = destination.getFirstStartAddress();
            if (!function.getBody().contains(destinationStart)) {
                continue;
            }
            if (!firstEdge) {
                line.append(",");
            }
            firstEdge = false;
            line.append(quote(hex(destinationStart)));
        }
        line.append("]}");
    }

    private boolean hasExternalEntryPoint(Function function) {
        for (Symbol symbol :
                currentProgram.getSymbolTable().getSymbols(function.getEntryPoint())) {
            if (symbol.isExternalEntryPoint()) {
                return true;
            }
        }
        return false;
    }

    private void writeStrings(PrintWriter writer) {
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        int written = 0;
        while (data.hasNext() && written < MAX_STRINGS) {
            Data item = data.next();
            Object value = item.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            StringBuilder line = new StringBuilder();
            line.append("{\"type\":\"string\"");
            field(line, "address", hex(item.getAddress()));
            field(line, "value", (String) value);
            field(line, "data_type", item.getDataType().getName());
            line.append("}");
            writer.println(line);
            written++;
        }
    }

    private static String operands(Instruction instruction) {
        StringBuilder operands = new StringBuilder();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index > 0) {
                operands.append(", ");
            }
            operands.append(instruction.getDefaultOperandRepresentation(index));
        }
        return operands.toString();
    }

    private static String bytes(Instruction instruction) throws Exception {
        byte[] raw = instruction.getBytes();
        if (raw == null) {
            return "";
        }
        StringBuilder encoded = new StringBuilder(raw.length * 2);
        for (byte value : raw) {
            encoded.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return encoded.toString();
    }

    private static String hex(Address address) {
        return address == null ? null : "0x" + Long.toHexString(address.getOffset());
    }

    private static void field(StringBuilder line, String name, String value) {
        line.append(",\"").append(name).append("\":");
        if (value == null) {
            line.append("null");
        } else {
            line.append(quote(value));
        }
    }

    private static void field(StringBuilder line, String name, boolean value) {
        line.append(",\"").append(name).append("\":").append(value);
    }

    private static void field(StringBuilder line, String name, long value) {
        line.append(",\"").append(name).append("\":").append(value);
    }

    private static String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder quoted = new StringBuilder(value.length() + 16);
        quoted.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': quoted.append("\\\\"); break;
                case '"': quoted.append("\\\""); break;
                case '\n': quoted.append("\\n"); break;
                case '\r': quoted.append("\\r"); break;
                case '\t': quoted.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        quoted.append(String.format(Locale.ROOT, "\\u%04x",
                                (int) character));
                    } else {
                        quoted.append(character);
                    }
            }
        }
        quoted.append('"');
        return quoted.toString();
    }
}
