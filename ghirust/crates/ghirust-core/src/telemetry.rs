//! Real system and process telemetry.
//!
//! Uses the `sysinfo` crate (MIT) for CPU, memory and process measurements.
//! GPU/VRAM metrics are **not** provided: there is no GPU backend and no
//! vendor telemetry API (NVML/DXGI) is linked. Callers must present GPU
//! metrics as unavailable, never as estimates.
//!
//! Measurements are always distinguished:
//!
//! * global system values (CPU percent, physical memory);
//! * the GHIRUST process value (committed RAM);
//! * unavailable metrics ([`GpuMetrics::unavailable`]).

use std::time::Duration;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// Snapshot of measured values, ready for the resource manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSnapshot {
    /// Total system CPU usage in percent (0..=100).
    pub cpu_percent: f32,
    /// Total physical memory, bytes.
    pub total_ram_bytes: u64,
    /// Available physical memory, bytes.
    pub available_ram_bytes: u64,
    /// Committed memory of this process, bytes.
    pub process_ram_bytes: u64,
    /// Logical CPU count of the machine.
    pub logical_cpus: usize,
}

/// GPU state. Always unavailable until a real GPU backend with a vendor
/// telemetry API exists.
#[derive(Debug, Clone)]
pub struct GpuMetrics {
    /// Always `None` for now; never fabricated.
    pub model: Option<String>,
    /// Always `false` for now.
    pub available: bool,
    /// Human-readable reason the metrics are unavailable.
    pub reason: String,
}

impl Default for GpuMetrics {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl GpuMetrics {
    pub fn unavailable() -> Self {
        Self {
            model: None,
            available: false,
            reason: "no GPU backend or vendor telemetry API (NVML/DXGI) is linked".to_owned(),
        }
    }
}

/// Periodic sampler. Refresh is cheap; call it about twice per second.
#[derive(Debug)]
pub struct Telemetry {
    system: System,
    pid: Pid,
    last_refresh: std::time::Instant,
    cpu_accumulator: f32,
    cpu_samples: u32,
    /// First CPU reading is invalid in sysinfo (needs two samples); report
    /// the previous valid value until one exists.
    last_cpu: f32,
    last_process_ram: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl Telemetry {
    pub fn new() -> Self {
        let pid = Pid::from_u32(std::process::id());
        let mut system = System::new().expect("sysinfo failed to initialize the system handle");
        // Warm the CPU measurement so the first user-visible reading is real.
        system.refresh_cpu_usage();
        system.refresh_memory();
        Self {
            system,
            pid,
            last_refresh: std::time::Instant::now(),
            cpu_accumulator: 0.0,
            cpu_samples: 0,
            last_cpu: 0.0,
            last_process_ram: 0,
        }
    }

    /// Sample current values. CPU is averaged between calls at least
    /// `MIN_REFRESH` apart (sysinfo needs two samples for a real reading).
    pub fn snapshot(&mut self) -> SystemSnapshot {
        const MIN_REFRESH: Duration = Duration::from_millis(400);
        if self.last_refresh.elapsed() >= MIN_REFRESH {
            self.system.refresh_cpu_usage();
            let reading = self.system.global_cpu_usage();
            self.last_refresh = std::time::Instant::now();
            self.cpu_accumulator += reading;
            self.cpu_samples += 1;
            self.last_cpu = self.cpu_accumulator / self.cpu_samples as f32;
            if self.cpu_samples > 20 {
                // Keep a moving average without unbounded accumulation.
                self.cpu_accumulator = self.last_cpu;
                self.cpu_samples = 1;
            }
        }
        self.system.refresh_memory();
        let total = self.system.total_memory();
        let available = self.system.available_memory();
        self.refresh_process_ram();
        let logical_cpus = self.system.cpus().len().max(1);
        SystemSnapshot {
            cpu_percent: self.last_cpu,
            total_ram_bytes: total,
            available_ram_bytes: available,
            process_ram_bytes: self.last_process_ram,
            logical_cpus,
        }
    }

    fn refresh_process_ram(&mut self) {
        self.system
            .refresh_processes(ProcessesToUpdate::Some(&[self.pid]), true);
        if let Some(process) = self.system.process(self.pid) {
            self.last_process_ram = process.memory();
        }
    }

    /// GPU metrics: always unavailable today. Kept as an explicit API so the
    /// GUI renders "Unavailable" instead of a fabricated number.
    pub fn gpu(&self) -> GpuMetrics {
        GpuMetrics::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_real_system_values() {
        let mut telemetry = Telemetry::new();
        std::thread::sleep(Duration::from_millis(450));
        let snapshot = telemetry.snapshot();
        assert!(snapshot.total_ram_bytes > 0, "total RAM must be non-zero");
        assert!(snapshot.logical_cpus >= 1, "at least one logical CPU");
        assert!(
            snapshot.process_ram_bytes > 0,
            "process RAM must be non-zero"
        );
        assert!((0.0..=100.0).contains(&snapshot.cpu_percent));
    }

    #[test]
    fn gpu_metrics_are_never_fabricated() {
        let telemetry = Telemetry::new();
        let gpu = telemetry.gpu();
        assert!(!gpu.available);
        assert!(gpu.model.is_none());
        assert!(!gpu.reason.is_empty());
    }
}
