package dev.krillin.bifrost.core.acl.opa;

import com.dylibso.chicory.runtime.ByteArrayMemory;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.ImportMemory;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import com.dylibso.chicory.wasm.types.ExternalType;
import com.dylibso.chicory.wasm.types.FunctionImport;
import com.dylibso.chicory.wasm.types.FunctionType;
import com.dylibso.chicory.wasm.types.Import;
import com.dylibso.chicory.wasm.types.MemoryImport;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates an OPA-compiled-to-WebAssembly policy in-process, on the pure-JVM Chicory WASM
 * runtime — no OPA sidecar process.
 *
 * <p>This wraps the OPA WASM one-shot ABI (opa 0.70.0, {@code opa build -t wasm}):
 * the host supplies {@code env.memory} (an imported {@link Memory}) plus stub host functions
 * {@code env.opa_abort} and {@code env.opa_builtin0..4}; the module exports {@code opa_malloc},
 * {@code opa_heap_ptr_get}/{@code opa_heap_ptr_set}, and {@code opa_eval}. See the OPA WASM SDK
 * docs (there is no {@code opa_println} import in this ABI — that is a different OPA WASM
 * mode). This class implements only the one-shot {@code opa_eval} path (format=0, JSON in,
 * JSON result-set out) — no {@code opa_json_parse}/{@code opa_json_dump}/eval-ctx path needed.
 */
public final class OpaPolicy {

    private final Instance instance;
    private final Memory memory;
    private final ExportFunction opaMalloc;
    private final ExportFunction opaHeapPtrGet;
    private final ExportFunction opaHeapPtrSet;
    private final ExportFunction opaEval;
    private final int baseHeap;

    private OpaPolicy(Instance instance) {
        this.instance = instance;
        this.memory = instance.memory();
        this.opaMalloc = instance.export("opa_malloc");
        this.opaHeapPtrGet = instance.export("opa_heap_ptr_get");
        this.opaHeapPtrSet = instance.export("opa_heap_ptr_set");
        this.opaEval = instance.export("opa_eval");
        this.baseHeap = (int) opaHeapPtrGet.apply()[0];
    }

    /**
     * Parses + instantiates the OPA WASM module found at the given classpath resource path
     * (e.g. {@code "/opa/spike.wasm"}). Do this once and reuse the returned {@link OpaPolicy} —
     * parsing/instantiation is the expensive part; {@link #eval(String)} is cheap and resets
     * the module's heap between calls.
     */
    public static OpaPolicy fromResource(String classpathPath) {
        try (InputStream in = OpaPolicy.class.getResourceAsStream(classpathPath)) {
            if (in == null) {
                throw new IllegalStateException("OPA wasm resource not found: " + classpathPath);
            }
            WasmModule module = Parser.parse(in);
            ImportValues importValues = buildImports(module);
            Instance instance = Instance.builder(module).withImportValues(importValues).build();
            return new OpaPolicy(instance);
        } catch (IOException e) {
            throw new IllegalStateException("failed to read OPA wasm resource: " + classpathPath, e);
        } catch (RuntimeException e) {
            throw new IllegalStateException("failed to parse/instantiate OPA wasm module: " + classpathPath, e);
        }
    }

    /**
     * Evaluates the policy's single entrypoint (id 0) against the given JSON input.
     *
     * @return the raw OPA result-set JSON, e.g. {@code [{"result":{"ok":true}}]}
     *
     * <p><b>Thread-safety:</b> a single instance holds one shared wasm linear memory and mutates the
     * heap pointer per call, so {@code eval} is {@code synchronized} — concurrent callers are serialized
     * (a race could otherwise read another thread's result region and return a wrong ALLOW). For high
     * throughput, use one instance per thread rather than sharing one.
     */
    public synchronized String eval(String inputJson) {
        try {
            // Reset the module heap to the post-instantiation baseline before every call —
            // the one-shot opa_eval ABI is stateless across calls as long as we do this.
            opaHeapPtrSet.apply(baseHeap);

            byte[] inputBytes = inputJson.getBytes(StandardCharsets.UTF_8);
            int inputAddr = (int) opaMalloc.apply(inputBytes.length)[0];
            memory.write(inputAddr, inputBytes);

            int heapPtr = (int) opaHeapPtrGet.apply()[0];
            long[] evalResult = opaEval.apply(
                    0,                   // reserved
                    0,                   // entrypoint id (single-entrypoint build)
                    0,                   // data_addr (none)
                    inputAddr,
                    inputBytes.length,
                    heapPtr,
                    0                    // format = 0 (JSON)
            );
            int resultAddr = (int) evalResult[0];
            if (resultAddr == 0) {
                throw new IllegalStateException("opa_eval returned a null result address");
            }
            return memory.readCString(resultAddr);
        } catch (RuntimeException e) {
            throw new IllegalStateException("OPA WASM evaluation failed", e);
        }
    }

    // ---- host-side ABI wiring -------------------------------------------------------------

    private static ImportValues buildImports(WasmModule module) {
        MemoryImport memoryImport = findMemoryImport(module);
        Memory hostMemory = new ByteArrayMemory(memoryImport.limits());

        List<HostFunction> hostFunctions = new ArrayList<>();
        for (int i = 0; i < module.importSection().importCount(); i++) {
            Import imp = module.importSection().getImport(i);
            if (imp.importType() != ExternalType.FUNCTION || !"env".equals(imp.module())) {
                continue;
            }
            FunctionImport fnImport = (FunctionImport) imp;
            FunctionType type = module.typeSection().getType(fnImport.typeIndex());
            switch (imp.name()) {
                case "opa_abort":
                    hostFunctions.add(new HostFunction("env", "opa_abort", type, OpaPolicy::hostOpaAbort));
                    break;
                case "opa_builtin0":
                case "opa_builtin1":
                case "opa_builtin2":
                case "opa_builtin3":
                case "opa_builtin4":
                    hostFunctions.add(new HostFunction("env", imp.name(), type, OpaPolicy::hostUnsupportedBuiltin));
                    break;
                default:
                    throw new IllegalStateException(
                            "unexpected OPA wasm host import env." + imp.name()
                                    + " - spike ground truth said the import set was fixed;"
                                    + " re-verify the ABI for this opa version");
            }
        }

        return ImportValues.builder()
                .addMemory(new ImportMemory("env", "memory", hostMemory))
                .addFunction(hostFunctions.toArray(new HostFunction[0]))
                .build();
    }

    private static long[] hostOpaAbort(Instance instance, long... args) {
        int addr = (int) args[0];
        String message = instance.memory().readCString(addr);
        throw new IllegalStateException("OPA policy aborted: " + message);
    }

    private static long[] hostUnsupportedBuiltin(Instance instance, long... args) {
        throw new IllegalStateException(
                "OPA builtin function call is not supported by this fail-closed host stub"
                        + " (spike policy uses only comparisons; a real policy that needs"
                        + " builtins must implement opa_builtin0..4)");
    }

    private static MemoryImport findMemoryImport(WasmModule module) {
        for (int i = 0; i < module.importSection().importCount(); i++) {
            Import imp = module.importSection().getImport(i);
            if (imp.importType() == ExternalType.MEMORY) {
                return (MemoryImport) imp;
            }
        }
        throw new IllegalStateException(
                "OPA wasm module does not import env.memory - ABI assumption violated");
    }
}
