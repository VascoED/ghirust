# GPU Scheduler

Status: **not implemented**. Honest summary:

- GHIRUST has exactly one execution backend: CPU.
- No GPU API is linked (no wgpu/Vulkan/CUDA/NVML/DXGI).
- No GPU metrics are measured; `Telemetry::gpu()` returns
  `GpuMetrics::unavailable()` with an explicit reason.
- The GUI renders `GPU: Unavailable` and `VRAM: Unavailable` — never a
  fabricated number.
- There is no simulated GPU budget and no "hybrid CPU/GPU" claim.

## Planned shape (not implemented)

When a real GPU backend exists, it must:

1. Detect the device and supported API.
2. Check VRAM availability before every operation.
3. Reserve VRAM before execution and release it on drop, including on error.
4. Bound buffer sizes and simultaneous transfers.
5. Support cancellation and automatic CPU fallback.
6. Reduce batch sizes and defer work under VRAM pressure.
7. Back every operation with a benchmark that shows a measurable advantage
   over the CPU backend.

Until those properties are implemented and tested, no GPU-related row in the
compatibility matrix will be promoted beyond `NOT_IMPLEMENTED`.
