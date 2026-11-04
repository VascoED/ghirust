# GHIRUST
### Next-Generation Hybrid Decompilation & Reverse Engineering Platform

**Project Type:** Full-Stack / Low-Level Systems Engineering  
**Architecture:** Rust + C++ + GPU Compute  
**Primary Objective:** High-Performance Multi-Language Decompilation  
**Localization:** PT-PT, PT-BR, EN-US, RU-RU  
**Compute Architecture:** CPU + GPU Hybrid Processing

---

# 1. PROJECT VISION

GHIRUST is a next-generation reverse engineering and decompilation platform designed around a high-performance native architecture.

The objective is to rebuild and significantly expand the existing GHIRA system, creating a modular, parallel, hardware-aware decompilation engine.

The platform must combine:

- Native Rust core.
- Specialized C++ low-level components.
- GPU-accelerated computation.
- Intelligent CPU/GPU workload distribution.
- Multi-language decompilation.
- Unified Intermediate Representation.
- Parallel binary analysis.
- Advanced type and control-flow reconstruction.
- Persistent intelligent caching.
- Real-time system monitoring.
- Advanced debugging and execution tracing.
- Complete multilingual interface.

The system must prioritize performance, correctness, scalability, modularity and maintainability.

**Important:** Do not blindly rewrite existing components. First audit the original GHIRA architecture, identify reusable components, benchmark existing functionality and establish compatibility requirements.

---

# 2. CORE TECHNOLOGY STACK

## Primary Languages

### Rust
Responsible for:
- Main application engine.
- Core architecture.
- Memory management.
- Task scheduling.
- Parallel processing.
- Binary parsing.
- Intermediate representation.
- Analysis orchestration.
- Cache management.
- Monitoring infrastructure.
- Localization engine.

### C++
Responsible for:
- Specialized low-level analysis.
- Performance-critical algorithms.
- Optimized disassembly components.
- Native binary processing.
- Specialized compiler and ABI analysis.
- SIMD implementations.
- GPU kernel integration where appropriate.

Rust and C++ must communicate through stable, explicitly defined interfaces.

Prefer C-compatible FFI boundaries and avoid unnecessary cross-language memory ownership complexity.

## GPU Technologies

- CUDA: NVIDIA acceleration.
- HIP: AMD acceleration.
- Vulkan Compute: Cross-vendor compute alternative.

Use a hardware abstraction layer to prevent GPU-specific implementations from contaminating the core architecture.

## Additional Technologies

| Technology | Purpose |
|---|---|
| LLVM | Compiler infrastructure and IR interoperability |
| Rayon | CPU parallelism |
| Tokio | Asynchronous orchestration |
| egui | Native monitoring interface |
| sysinfo | System information |
| NVML | NVIDIA GPU monitoring |
| tracing | Instrumentation |
| OpenTelemetry | Metrics and tracing export |
| SIMD | CPU acceleration |

---

# 3. GHIRUST CORE ENGINE

Develop a central engine:

`GHIRUST Unified Decompilation Engine (GUDE)`

This engine coordinates all decompilation operations.

Architecture:

```text
                 GHIRUST
                    |
               CORE ENGINE
                    |
              FILE ANALYZER
                    |
             FORMAT DETECTION
                    |
            LANGUAGE RECOGNITION
                    |
               DISASSEMBLER
                    |
             UNIFIED IR ENGINE
                    |
             ANALYSIS PIPELINE
                    |
            HYBRID TASK SCHEDULER
                    |
              CPU / GPU COMPUTE
                    |
             IR OPTIMIZATION
                    |
             LANGUAGE BACKENDS
                    |
            SOURCE RECONSTRUCTION
```

The core must support:

- Modular execution.
- Incremental analysis.
- Parallel processing.
- Multiple binary formats.
- Multiple architectures.
- Plugin-compatible backends.
- Persistent analysis sessions.
- Cancellation and recovery.
- Structured diagnostics.

---

# 4. UNIFIED INTERMEDIATE REPRESENTATION

Create:

`GHIRUST Unified Intermediate Representation (GUIR)`

This is one of the most important components.

All supported languages and binary formats should converge into a shared analysis infrastructure.

GUIR must represent:

- Instructions.
- Functions.
- Basic blocks.
- Control-flow graphs.
- Variables.
- Types.
- Expressions.
- Memory operations.
- Function calls.
- Dependencies.
- Exceptions.
- References.
- Control structures.
- Concurrency primitives.
- Language-specific metadata.

Preserve source-language information whenever possible.

Do not discard information merely to force every language into a generic representation.

Support:
- IR validation.
- IR optimization.
- IR serialization.
- IR versioning.
- Incremental updates.
- Cross-module references.

---

# 5. ADAPTIVE HYBRID COMPUTE ENGINE

Develop:

`Adaptive Hybrid Compute Engine (AHCE)`

Its responsibility is to distribute computational workloads intelligently between CPU and GPU.

## 5.1 GPU Workloads

Prioritize GPU execution for operations with substantial data parallelism:

- Large-scale binary pattern matching.
- Signature scanning.
- Instruction sequence comparison.
- Large-scale hashing.
- Parallel reference analysis.
- Candidate function classification.
- Batch processing of independent analysis blocks.
- Suitable data-flow operations.
- Repetitive mathematical operations.

GPU execution must only be selected when transfer costs and synchronization overhead do not outweigh its computational benefits.

## 5.2 CPU Workloads

Prioritize CPU execution for:

- CFG reconstruction.
- Complex control-flow analysis.
- Function reconstruction.
- Dependency resolution.
- Semantic analysis.
- Type inference orchestration.
- Pseudocode reconstruction.
- Recursive analysis.
- Task coordination.
- Memory management.

## 5.3 Hybrid Task Scheduler

Create:

`HybridTaskScheduler`

The scheduler must evaluate:

- Task complexity.
- Parallelization potential.
- CPU availability.
- GPU availability.
- RAM availability.
- VRAM availability.
- Data transfer overhead.
- Queue depth.
- Task dependencies.
- Historical execution performance.

Support three execution modes:

1. Automatic.
2. CPU Priority.
3. GPU Priority.

The automatic mode should predict the most efficient execution target.

Use measured execution history to improve scheduling decisions.

## 5.4 Simultaneous Execution

CPU and GPU must execute independent tasks simultaneously.

Example:

```text
GPU:
  Pattern Matching
  Instruction Batch Analysis
  Signature Detection

CPU:
  CFG Reconstruction
  Function Analysis
  Type Resolution

SHARED:
  IR Updates
  Result Synchronization
  Dependency Management
```

Avoid unnecessary GPU synchronization.

Use asynchronous transfers, batching and memory reuse.

Implement backpressure to prevent excessive task submission.

---

# 6. PARALLEL ANALYSIS FRAMEWORK

Create:

`GHIRUST Parallel Analysis Framework`

Support independent workers for:

- Function detection.
- Symbol recovery.
- Type analysis.
- CFG analysis.
- Data-flow analysis.
- Signature recognition.
- Reference resolution.
- Language recognition.

Requirements:

- Work stealing.
- Priority queues.
- Dependency tracking.
- Task deduplication.
- Cancellation.
- Worker health monitoring.
- Result synchronization.
- Incremental analysis.
- Failure recovery.

Use Rayon for CPU parallelism where appropriate.

Tokio should coordinate asynchronous infrastructure rather than replace CPU-bound parallel execution.

---

# 7. MULTI-LANGUAGE DECOMPILATION

Implement five specialized language backends.

Each backend must share the central engine while maintaining language-specific reconstruction logic.

## 7.1 GO DECOMPILER

Support reconstruction of:

- Functions.
- Methods.
- Structs.
- Interfaces.
- Goroutines.
- Channels.
- Closures.
- Runtime-related structures.
- Type metadata.
- Function references.

Analyze:

- Go runtime.
- Goroutine scheduling.
- Garbage collection.
- Interface dispatch.
- Runtime type information.

Recognize compiler and runtime variations.

## 7.2 RUST DECOMPILER

Support reconstruction of:

- Functions.
- Structs.
- Enums.
- Traits where inferable.
- Generic-related metadata.
- Closures.
- Iterators.
- Async/await state machines.
- References.
- Pointer structures.
- Ownership-related patterns where recoverable.

Analyze:

- Rust symbol mangling.
- Monomorphization.
- Trait dispatch.
- Panic handling.
- Drop glue.
- Async state machines.
- Compiler-generated abstractions.

Do not claim to recover original ownership, lifetimes or generic declarations when the binary does not preserve enough information.

## 7.3 PYTHON DECOMPILER

Support:

### Python Bytecode

- Functions.
- Classes.
- Imports.
- Loops.
- Comprehensions.
- Decorators.
- Closures.
- Exceptions.
- Generators.
- Async functions.

### Native Python Extensions

- CPython extensions.
- C/C++ bindings.
- Python C API interactions.
- Native module exports.
- Cross-language calls.

Support multiple Python bytecode versions through version-specific instruction models.

## 7.4 C++ DECOMPILER

Support:

- Classes.
- Methods.
- Inheritance.
- Virtual tables.
- RTTI.
- Namespaces.
- Templates where recoverable.
- Exceptions.
- Smart pointers.
- STL pattern recognition.
- Operator overloading patterns.
- Constructors and destructors.

Compiler compatibility:

- GCC.
- Clang.
- MSVC.

ABI compatibility:

- Itanium C++ ABI.
- Microsoft C++ ABI.

Binary formats:

- ELF.
- PE.
- Mach-O.

Implement compiler-specific pattern recognition.

## 7.5 JAVA DECOMPILER

Support:

- JVM bytecode.
- Classes.
- Interfaces.
- Inheritance.
- Generics metadata.
- Lambdas.
- Annotations.
- Exceptions.
- Streams.
- Inner classes.
- Records.
- Synthetic methods.

Input formats:

- CLASS.
- JAR.
- WAR.
- EAR.

Support multiple Java bytecode versions.

---

# 8. AUTOMATIC LANGUAGE AND FORMAT RECOGNITION

Create:

`GHIRUST Language Recognition Engine`

Automatically identify:

- Binary format.
- Architecture.
- Operating system target.
- Compiler.
- Compiler version where inferable.
- Programming language.
- Runtime.
- ABI.
- Relevant framework signatures.

Supported formats:

- ELF.
- PE.
- Mach-O.
- JVM CLASS.
- JAR.
- Python bytecode.
- Relevant native executable formats.

Use multiple evidence sources.

Provide confidence scores and distinguish confirmed metadata from heuristic guesses.

---

# 9. ADVANCED ANALYSIS SYSTEMS

Implement specialized analysis modules.

```text
analysis/
├── cfg/
├── dataflow/
├── functions/
├── symbols/
├── types/
├── signatures/
├── references/
├── strings/
├── compiler_patterns/
├── runtime_detection/
└── semantic_analysis/
```

Required capabilities:

- Automatic function detection.
- Cross-reference mapping.
- Symbol recovery.
- Type inference.
- Function fingerprinting.
- Signature databases.
- Compiler identification.
- Runtime identification.
- String analysis.
- Dependency analysis.
- Control-flow reconstruction.
- Data-flow reconstruction.

Implement confidence tracking for inferred results.

---

# 10. INTELLIGENT PERSISTENT CACHE

Create:

`GHIRUST Smart Analysis Cache`

Cache:

- Binary metadata.
- Function boundaries.
- Signatures.
- Symbol information.
- Type information.
- CFG results.
- Analysis results.
- Intermediate representations.

Requirements:

- Persistent storage.
- Content-addressable keys.
- Incremental invalidation.
- Version compatibility.
- Concurrent access.
- Memory-aware eviction.
- Session recovery.

Use binary content hashes and analysis configuration as part of cache identity.

Avoid reprocessing unchanged regions.

---

# 11. LOCALIZATION ENGINE

Rebuild the localization system from the ground up.

Supported locales:

| Language | Locale |
|---|---|
| Portuguese Portugal | pt-PT |
| Portuguese Brazil | pt-BR |
| English United States | en-US |
| Russian | ru-RU |

Create:

```text
localization/
├── engine/
│   ├── language_manager.rs
│   ├── translation_loader.rs
│   ├── locale_detector.rs
│   └── fallback.rs
│
└── languages/
    ├── pt-PT/
    ├── pt-BR/
    ├── en-US/
    └── ru-RU/
```

Each locale must include:

- Interface translations.
- Menus.
- Notifications.
- Errors.
- Debug messages.
- Monitoring labels.
- Settings.
- Reports.
- Tooltips.

Requirements:

- Runtime language switching.
- Automatic locale detection.
- Manual language selection.
- Translation fallback.
- Translation completeness validation.
- Unicode support.
- Russian text support.
- Proper regional formatting.

Never translate internal API identifiers, structured event codes or machine-readable log fields.

PT-PT and PT-BR must be treated as distinct localization targets, not interchangeable translations.

---

# 12. GHIRUST COMMAND CENTER

Create an independent monitoring interface:

`GHIRUST COMMAND CENTER`

Purpose:

Provide complete visibility into the execution of the decompilation engine.

The Command Center must display real-time system metrics, active tasks, scheduler decisions, execution logs and resource consumption.

Use a native interface built with egui.

## 12.1 SYSTEM DASHBOARD

Display:

- Total CPU utilization.
- Per-core CPU utilization.
- Process RAM consumption.
- Available system RAM.
- GPU utilization.
- VRAM consumption.
- Available VRAM.
- Active threads.
- Active workers.
- Pending tasks.
- Completed tasks.
- GPU temperature where available.
- GPU power consumption where available.

Support historical graphs.

## 12.2 TASK MONITOR

Display all task states:

- QUEUED.
- RUNNING.
- WAITING.
- COMPLETED.
- FAILED.
- CANCELLED.

Each task must expose:

- Task ID.
- Module.
- Assigned device.
- Execution time.
- Memory consumption.
- Priority.
- Progress.
- Dependencies.
- Execution status.

Allow inspection of individual tasks.

## 12.3 SCHEDULER DECISION MONITOR

Show why each task was assigned to CPU or GPU.

Example:

```text
TASK: Pattern Matching

PARALLELISM: 94%
DATA SIZE: 1.2 GB
CPU AVAILABILITY: 38%
GPU AVAILABILITY: 72%

DECISION: GPU

REASON:
High parallelism.
Sufficient VRAM.
Low expected transfer overhead.

ESTIMATED TIME: 1.8s
ACTUAL TIME: 1.5s
```

Track prediction accuracy.

Record scheduling decisions for later performance analysis.

## 12.4 CPU MONITOR

Display:

- CPU usage.
- Per-core usage.
- Thread count.
- Worker count.
- CPU frequency where available.
- Module-level execution time.
- RAM usage.
- CPU task queue.

## 12.5 GPU MONITOR

Display:

- GPU utilization.
- VRAM usage.
- Compute utilization.
- Active GPU workloads.
- Kernel execution times.
- CPU-to-GPU transfer volume.
- GPU-to-CPU transfer volume.
- GPU temperature.
- GPU power consumption.

Hardware-specific metrics must be reported as unavailable when the driver does not expose them.

## 12.6 MEMORY MONITOR

Track separately:

- Process RAM.
- System RAM.
- GPU VRAM.
- Cache memory.
- Task memory.
- Temporary allocations.

Track allocation peaks and memory leaks where detectable.

## 12.7 LIVE EXECUTION LOGS

Implement a real-time event console.

Event categories:

- INFO.
- DEBUG.
- WARNING.
- ERROR.
- CRITICAL.
- SCHEDULER.
- CPU.
- GPU.
- MEMORY.
- DECOMPILER.
- ANALYSIS.

Support:

- Filtering.
- Search.
- Export.
- Timestamping.
- Event correlation.
- Execution tracing.

## 12.8 MANUAL EXECUTION CONTROLS

Allow:

- CPU Priority.
- GPU Priority.
- Automatic Scheduling.
- Thread limits.
- Worker limits.
- RAM limits.
- VRAM budgets.
- Task priorities.
- Pause.
- Resume.
- Cancel.

Resource limits should be enforced through memory budgeting and backpressure wherever possible.

---

# 13. PERFORMANCE INTELLIGENCE ENGINE

Create:

`GHIRUST Performance Intelligence Engine`

Its purpose is to identify performance bottlenecks automatically.

Analyze:

- CPU saturation.
- GPU underutilization.
- Memory pressure.
- VRAM pressure.
- Excessive transfers.
- Task synchronization.
- Queue congestion.
- Cache inefficiency.
- Slow analysis modules.

Example:

```text
PERFORMANCE BOTTLENECK DETECTED

MODULE:
CFG Reconstruction

CPU USAGE:
92%

GPU USAGE:
18%

FINDING:
CPU graph traversal is limiting throughput.

RECOMMENDATION:
Optimize graph traversal.
Parallelize independent function analysis.

STATUS:
AWAITING OPTIMIZATION
```

Recommendations must be based on measured evidence.

Do not automatically modify critical settings or source code without user authorization.

---

# 14. PROJECT STRUCTURE

Proposed repository:

```text
GHIRUST/
│
├── Cargo.toml
├── README.md
├── LICENSE
│
├── core/
│   ├── engine/
│   ├── memory/
│   ├── scheduler/
│   ├── pipeline/
│   └── configuration/
│
├── native/
│   ├── cpp/
│   │   ├── disassembly/
│   │   ├── algorithms/
│   │   ├── simd/
│   │   └── bindings/
│   │
│   └── ffi/
│
├── compute/
│   ├── cpu/
│   ├── gpu/
│   │   ├── cuda/
│   │   ├── hip/
│   │   └── vulkan/
│   └── hybrid/
│
├── ir/
│   ├── gui_ir/
│   ├── optimizer/
│   ├── types/
│   └── serialization/
│
├── decompilers/
│   ├── go/
│   ├── rust/
│   ├── python/
│   ├── cpp/
│   └── java/
│
├── analysis/
│   ├── cfg/
│   ├── dataflow/
│   ├── functions/
│   ├── symbols/
│   ├── types/
│   ├── signatures/
│   └── references/
│
├── formats/
│   ├── elf/
│   ├── pe/
│   ├── macho/
│   ├── jvm/
│   └── python_bytecode/
│
├── cache/
│   ├── persistent/
│   └── memory/
│
├── localization/
│   ├── engine/
│   └── languages/
│       ├── pt-PT/
│       ├── pt-BR/
│       ├── en-US/
│       └── ru-RU/
│
├── monitoring/
│   ├── system/
│   ├── cpu/
│   ├── gpu/
│   ├── memory/
│   └── tasks/
│
├── debugging/
│   ├── logger/
│   ├── scheduler/
│   ├── tracing/
│   └── diagnostics/
│
├── ui/
│   ├── dashboard/
│   ├── command_center/
│   ├── settings/
│   └── language_selector/
│
├── benchmarks/
│   ├── cpu/
│   ├── gpu/
│   ├── scheduler/
│   └── end_to_end/
│
└── tests/
    ├── unit/
    ├── integration/
    ├── regression/
    ├── languages/
    └── performance/
```

---

# 15. DEVELOPMENT ROADMAP

Development must be incremental and benchmark-driven.

## PHASE 1 — ORIGINAL GHIRA AUDIT

- Inspect existing architecture.
- Identify reusable modules.
- Map dependencies.
- Benchmark current performance.
- Document existing functionality.
- Define migration strategy.

## PHASE 2 — RUST CORE

- Establish Rust workspace.
- Implement core engine.
- Implement memory management.
- Establish native interfaces.
- Implement structured logging.

## PHASE 3 — UNIFIED IR

- Design GUIR.
- Implement instruction representation.
- Implement type representation.
- Implement CFG representation.
- Add validation and serialization.

## PHASE 4 — PARALLEL PROCESSING

- Implement worker infrastructure.
- Implement task queues.
- Add work stealing.
- Implement dependency tracking.
- Add cancellation and recovery.

## PHASE 5 — HYBRID COMPUTE

- Implement CPU backend.
- Implement GPU abstraction.
- Add CUDA.
- Add HIP.
- Evaluate Vulkan Compute.
- Implement automatic scheduling.
- Add simultaneous CPU/GPU execution.

## PHASE 6 — ANALYSIS ENGINE

- Function detection.
- CFG reconstruction.
- Data-flow analysis.
- Type inference.
- Symbol recovery.
- Signature recognition.

## PHASE 7 — LANGUAGE BACKENDS

Implement:

1. C++.
2. Go.
3. Rust.
4. Java.
5. Python.

Each backend must have independent regression tests and language-specific fixtures.

## PHASE 8 — CACHE ENGINE

- Persistent cache.
- Incremental invalidation.
- Memory-aware eviction.
- Session persistence.

## PHASE 9 — LOCALIZATION

- PT-PT.
- PT-BR.
- EN-US.
- RU-RU.
- Runtime language switching.
- Translation validation.

## PHASE 10 — COMMAND CENTER

- System dashboard.
- CPU monitor.
- GPU monitor.
- RAM/VRAM monitor.
- Task monitor.
- Scheduler decision monitor.
- Live logs.
- Execution tracing.

## PHASE 11 — PERFORMANCE INTELLIGENCE

- Bottleneck detection.
- Scheduler prediction accuracy.
- Resource optimization.
- Cache optimization.
- Performance recommendations.

## PHASE 12 — FINAL VALIDATION

- Regression testing.
- Multi-language testing.
- CPU-only benchmarks.
- GPU-only benchmarks.
- Hybrid benchmarks.
- Memory stress testing.
- Large binary testing.
- Stability testing.
- Performance comparison against original GHIRA.

---

# 16. BENCHMARKING AND QUALITY REQUIREMENTS

Every major component must have measurable performance targets.

Track:

- Total decompilation time.
- Instructions processed per second.
- Functions analyzed per second.
- Average analysis time per function.
- CPU utilization.
- GPU utilization.
- RAM consumption.
- VRAM consumption.
- Transfer overhead.
- Cache hit rate.
- Scheduler prediction accuracy.
- Reconstruction correctness.

Compare:

```text
CPU ONLY
GPU ONLY
HYBRID AUTOMATIC
```

Do not assume GPU execution is always faster.

Establish reproducible benchmarks using identical binaries, configurations and hardware.

Measure both cold-cache and warm-cache execution.

Correctness must never be sacrificed for benchmark performance.

---

# 17. ENGINEERING PRINCIPLES

The implementation must follow these rules:

1. Do not build fake functionality or placeholder implementations presented as complete.
2. Do not replace working functionality without regression testing.
3. Do not rewrite everything before auditing the original project.
4. Keep modules independent and testable.
5. Avoid unnecessary dependencies.
6. Use safe Rust by default.
7. Isolate unsafe Rust and C++ boundaries.
8. Use explicit memory ownership.
9. Avoid unnecessary CPU/GPU transfers.
10. Preserve language-specific metadata.
11. Make every major operation observable.
12. Instrument performance from the beginning.
13. Keep localization independent of business logic.
14. Never silently discard analysis information.
15. Distinguish inferred information from confirmed metadata.
16. Maintain backward compatibility where feasible.
17. Document architectural decisions.
18. Benchmark before and after optimizations.

---

# 18. FINAL PROJECT OBJECTIVE

GHIRUST must become a modular, high-performance reverse engineering and decompilation platform.

The final system must combine:

**CORE ENGINE**
- Rust.
- C++.
- Unified IR.
- Advanced binary analysis.

**HYBRID COMPUTING**
- CPU parallelism.
- GPU acceleration.
- Automatic task scheduling.
- Simultaneous CPU/GPU execution.

**MULTI-LANGUAGE DECOMPILATION**
- Go.
- Rust.
- Python.
- C++.
- Java.

**ADVANCED ANALYSIS**
- CFG.
- Data flow.
- Type inference.
- Function reconstruction.
- Symbol recovery.
- Compiler and runtime recognition.

**INTELLIGENT INFRASTRUCTURE**
- Persistent cache.
- Incremental analysis.
- Performance intelligence.
- Automatic bottleneck detection.

**USER EXPERIENCE**
- PT-PT.
- PT-BR.
- EN-US.
- RU-RU.
- Native Command Center.
- Live task monitoring.
- CPU/GPU/RAM/VRAM monitoring.
- Scheduler decision visualization.
- Advanced debugging.

The ultimate goal is to build GHIRUST as a unified decompilation ecosystem where analysis, computation, hardware management, language reconstruction and performance diagnostics operate together through one coherent architecture.

**Development priority: Correctness → Architecture → Observability → Performance → Optimization.**

Do not optimize unmeasured bottlenecks. Do not sacrifice reconstruction accuracy for raw execution speed.

# 19. REAL-WORLD TESTING AND BENCHMARK VALIDATION

## Objective

The development process must include real-world comparative testing between:

- Original GHIRA (unmodified baseline).
- GHIRUST (new implementation).

The purpose is to objectively measure whether GHIRUST improves decompilation performance, reconstruction quality, resource efficiency and overall stability.

Do not rely exclusively on synthetic benchmarks.

## 19.1 TEST ENVIRONMENT

Create a dedicated directory:

```text
tests/
└── objectives/
    ├── binaries/
    ├── source/
    ├── expected/
    ├── ghira_results/
    ├── ghirust_results/
    ├── reports/
    └── benchmarks/
```

## 19.2 TEST DLL GENERATION

Create a real test DLL specifically for comparative decompilation.

The DLL must be generated from documented source code.

Recommended initial implementation: C++.

The test DLL must contain:

- Multiple functions.
- Classes and inheritance.
- Virtual methods.
- Structs.
- Enums.
- Loops.
- Conditional branches.
- Nested functions where supported.
- Function calls.
- String references.
- Arrays.
- Pointer operations.
- Mathematical operations.
- Exception handling.
- Multiple compilation units.

Include both simple and complex functions.

Compile the DLL using documented compiler settings.

Preserve:
- Original source code.
- Compiler version.
- Compiler flags.
- Build configuration.
- Binary hash.
- Debug symbol information for separate test configurations.

Create two test configurations:

1. Debug/unoptimized DLL.
2. Release/optimized DLL with symbols stripped.

This allows testing both straightforward reconstruction and more difficult real-world analysis.

## 19.3 IDENTICAL INPUT REQUIREMENT

The exact same DLL must be supplied to both applications.

```text
                  TEST DLL
                     |
              +------+------+
              |             |
          ORIGINAL        GHIRUST
           GHIRA
              |             |
         DECOMPILATION  DECOMPILATION
              |             |
         RESULTS A       RESULTS B
              |             |
              +------+------+
                     |
               COMPARATOR
                     |
              FINAL REPORT
```

Never use different input binaries when comparing performance.

Verify the DLL hash before each execution.

## 19.4 ORIGINAL GHIRA BASELINE

Execute the original GHIRA without modifications.

Record:

- Total execution time.
- Binary loading time.
- Analysis time.
- Decompilation time.
- Number of functions identified.
- Number of functions successfully decompiled.
- RAM consumption.
- CPU utilization.
- GPU utilization, if supported.
- Errors and warnings.

Save all outputs in:

`tests/objectives/ghira_results/`

## 19.5 GHIRUST TEST EXECUTION

Execute the same DLL using GHIRUST.

Test three execution modes:

- CPU Only.
- GPU Only, where supported.
- Hybrid Automatic.

Record the same metrics collected from the original GHIRA.

Additionally record:

- GPU kernel execution time.
- CPU/GPU transfer overhead.
- Scheduler decisions.
- Task execution history.
- VRAM consumption.
- Cache hit rate.

Save all outputs in:

`tests/objectives/ghirust_results/`

## 19.6 DECOMPILATION QUALITY COMPARISON

Compare both outputs against the original source code.

Evaluate:

- Function identification accuracy.
- Function reconstruction.
- Control-flow reconstruction.
- Type recovery.
- Class reconstruction.
- Variable recovery where possible.
- String recovery.
- Call graph accuracy.
- Exception reconstruction.
- Semantic equivalence.

Do not evaluate only textual similarity.

Use structural and semantic comparison whenever possible.

The original source is the reference for validating correctness.

Account for transformations introduced by compiler optimizations.

## 19.7 AUTOMATIC BENCHMARK REPORT

Generate a report:

`tests/objectives/reports/comparison_report.html`

Include:

| Metric | Original GHIRA | GHIRUST CPU | GHIRUST GPU | GHIRUST Hybrid |
|---|---|---|---|---|
| Total Time | | | | |
| Analysis Time | | | | |
| Functions Found | | | | |
| Functions Decompiled | | | | |
| RAM Peak | | | | |
| VRAM Peak | N/A | N/A | | |
| CPU Usage | | | | |
| GPU Usage | | | | |
| Reconstruction Accuracy | | | | |

Also generate:

- JSON results.
- CSV results.
- Execution logs.
- Resource usage graphs.
- Performance comparison charts.

## 19.8 TEST VALIDITY

To guarantee reliable results:

1. Use identical hardware.
2. Use identical input binaries.
3. Record compiler settings.
4. Record application versions.
5. Run multiple repetitions.
6. Separate cold-cache and warm-cache tests.
7. Avoid unrelated background workloads.
8. Record failed and incomplete executions.
9. Compare equivalent functionality only.
10. Never fabricate missing metrics.

Use medians and dispersion statistics rather than relying on a single execution.

If a feature is unsupported by one implementation, report it as unsupported rather than assigning an artificial score.

## 19.9 ACCEPTANCE CRITERIA

GHIRUST must demonstrate:

- Successful DLL loading.
- Successful binary analysis.
- Successful function detection.
- Successful decompilation.
- Reproducible execution.
- Accurate resource monitoring.
- Valid benchmark results.
- No silent analysis failures.
- No corrupted output.
- Correctness validated against reference source.

GPU acceleration must only be considered successful when actual measurements demonstrate an improvement over CPU execution for the tested workload.

## 19.10 TEST AUTOMATION

Create a repeatable benchmark runner.

The runner must:

1. Validate test files.
2. Calculate input hashes.
3. Detect available hardware.
4. Execute original GHIRA.
5. Execute GHIRUST in supported modes.
6. Collect performance metrics.
7. Validate outputs.
8. Compare results.
9. Generate reports.
10. Preserve execution logs.

The complete benchmark must be reproducible without manually editing the results.

---

# FINAL TESTING REQUIREMENT

Do not consider GHIRUST production-ready merely because it compiles or successfully opens a DLL.

It must demonstrate measurable improvements or clearly documented feature improvements against the original GHIRA.

Performance, correctness, reconstruction quality and resource efficiency must be evaluated independently.