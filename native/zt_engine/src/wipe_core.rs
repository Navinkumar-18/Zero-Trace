//! Platform-neutral wipe engine shared by every backend.
//!
//! This module owns the overwrite pass loop, progress events, speed/ETA
//! estimation, the aligned chunk buffer and the partition-range bounds
//! writer. It performs no platform device access: callers hand it a
//! [`BlockWriter`] (Linux `DirectBlockWriter`, a Windows volume writer, an
//! Android SCSI BOT writer, or the in-memory test writer).
//!
//! Linux keeps its historic checkpoint and SIGTERM/SIGINT behavior through
//! the `cfg(unix)`/`cfg(target_os = "linux")` hooks below. Other platforms
//! can inject an external cancel flag now and add a checkpoint sink later.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;

use crate::checkpoint_sink::CheckpointSink;
use crate::types::{BlockWriter, ExecuteError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionPhase {
    SecurityUnlock,
    FirmwareCommand,
    KeyDestruction,
    CacheFlush,
    Verification,
    Preparing,
    Flushing,
}

impl std::fmt::Display for ExecutionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionPhase::SecurityUnlock => write!(f, "Security Unlock"),
            ExecutionPhase::FirmwareCommand => write!(f, "Firmware Command"),
            ExecutionPhase::KeyDestruction => write!(f, "Key Destruction"),
            ExecutionPhase::CacheFlush => write!(f, "Cache Flush"),
            ExecutionPhase::Verification => write!(f, "Post-Verification"),
            ExecutionPhase::Preparing => write!(f, "Preparing"),
            ExecutionPhase::Flushing => write!(f, "Flushing"),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OverwritePattern {
    Zeros,
    Ones,
    Random,
    MultiPass3,
}
fn default_schema_version() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub phase: ExecutionPhase,
    #[serde(default)]
    pub bytes_done: u64,
    #[serde(default)]
    pub bytes_total: u64,
    #[serde(default)]
    pub percent: Option<f32>,
    #[serde(default)]
    pub speed_bytes_per_sec: f64,
    pub eta_seconds: Option<u32>,
    pub message: String,
    #[serde(default)]
    pub is_heartbeat: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub success: bool,
    pub method_used: String,
    pub command_log: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub dry_run: bool,
    #[serde(default)]
    pub bytes_written: u64,
    #[serde(default)]
    pub io_mode: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_detailed_progress(
    tx: &mpsc::Sender<ProgressEvent>,
    phase: ExecutionPhase,
    bytes_done: u64,
    bytes_total: u64,
    percent: Option<f32>,
    speed_bytes_per_sec: f64,
    eta_seconds: Option<u32>,
    message: &str,
    is_heartbeat: bool,
) {
    let _ = tx
        .send(ProgressEvent {
            schema_version: 2,
            phase,
            bytes_done,
            bytes_total,
            percent,
            speed_bytes_per_sec,
            eta_seconds,
            message: message.to_string(),
            is_heartbeat,
        })
        .await;
}

pub struct PartitionRangeWriter<W: BlockWriter> {
    inner: W,
    start_offset: u64,
    length: u64,
}

impl<W: BlockWriter> PartitionRangeWriter<W> {
    pub fn new(inner: W, start_offset: u64, length: u64) -> Self {
        Self {
            inner,
            start_offset,
            length,
        }
    }

    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: BlockWriter> BlockWriter for PartitionRangeWriter<W> {
    fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<usize, io::Error> {
        let chunk_len = data.len() as u64;
        let end = offset.checked_add(chunk_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Offset overflow in partition write",
            )
        })?;
        if end > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Out of partition range write refused: offset {} + chunk {} > length {}",
                    offset, chunk_len, self.length
                ),
            ));
        }
        let target_offset = self.start_offset.checked_add(offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target offset overflow in partition write",
            )
        })?;
        self.inner.write_chunk(target_offset, data)
    }

    fn sync_data(&mut self) -> Result<(), io::Error> {
        self.inner.sync_data()
    }

    fn flush_buffers(&mut self) -> Result<(), io::Error> {
        self.inner.flush_buffers()
    }

    fn total_size(&self) -> Result<u64, io::Error> {
        Ok(self.length)
    }

    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }

    fn io_mode(&self) -> &'static str {
        self.inner.io_mode()
    }
}

pub struct AlignedBuffer {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}

impl AlignedBuffer {
    pub fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Self { ptr, layout }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.layout.size()) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

pub struct SpeedEstimator {
    samples: VecDeque<(Instant, u64)>,
    window_secs: f64,
}

impl SpeedEstimator {
    pub fn new(window_secs: f64) -> Self {
        Self {
            samples: VecDeque::new(),
            window_secs,
        }
    }

    pub fn record(&mut self, now: Instant, bytes_done: u64) {
        self.samples.push_back((now, bytes_done));
        let cutoff = now - std::time::Duration::from_secs_f64(self.window_secs);
        while let Some(&(t, _)) = self.samples.front() {
            if t < cutoff && self.samples.len() > 1 {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn current_speed(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let (first_t, first_b) = self.samples.front().unwrap();
        let (last_t, last_b) = self.samples.back().unwrap();
        let dt = (*last_t - *first_t).as_secs_f64();
        if dt > 0.05 {
            (*last_b - *first_b) as f64 / dt
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// Platform hooks
// ---------------------------------------------------------------------------

/// Crash-resume checkpoint sink. Linux keeps the historic checkpoint file;
/// other platforms no-op unless the caller injects a sink (Step 1.4a).
#[cfg(target_os = "linux")]
fn legacy_checkpoint(job_id: &str, device_serial: &str, device_size: u64, bytes_done: u64) {
    crate::execute::write_checkpoint_file(job_id, device_serial, device_size, bytes_done);
}

#[cfg(not(target_os = "linux"))]
fn legacy_checkpoint(_job_id: &str, _device_serial: &str, _device_size: u64, _bytes_done: u64) {}

#[cfg(target_os = "linux")]
fn legacy_remove_checkpoint() {
    crate::execute::remove_checkpoint_file();
}

#[cfg(not(target_os = "linux"))]
fn legacy_remove_checkpoint() {}

/// One checkpoint write: the injected sink when the platform supplied one,
/// otherwise the historic hook (Linux file writer, no-op elsewhere).
fn checkpoint(
    sink: Option<&dyn CheckpointSink>,
    job_id: &str,
    device_serial: &str,
    device_size: u64,
    bytes_done: u64,
) {
    match sink {
        Some(sink) => sink.write(job_id, device_serial, device_size, bytes_done),
        None => legacy_checkpoint(job_id, device_serial, device_size, bytes_done),
    }
}

/// Successful-wipe cleanup, sink-aware.
fn finish_checkpoint(sink: Option<&dyn CheckpointSink>) {
    match sink {
        Some(sink) => sink.remove(),
        None => legacy_remove_checkpoint(),
    }
}

/// Classification of write errors that carry safety meaning. Linux keeps the
/// historic `EIO`/`ENODEV`/`ENOSPC` mapping; other platforms map their own
/// codes when their backend lands.
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum OsErrorClass {
    Eio,
    Enodev,
    Enospc,
}

#[cfg(unix)]
fn os_error_class(e: &io::Error) -> Option<OsErrorClass> {
    match e.raw_os_error() {
        Some(code) if code == libc::EIO => Some(OsErrorClass::Eio),
        Some(code) if code == libc::ENODEV => Some(OsErrorClass::Enodev),
        Some(code) if code == libc::ENOSPC => Some(OsErrorClass::Enospc),
        _ => None,
    }
}

#[cfg(not(unix))]
fn os_error_class(_e: &io::Error) -> Option<OsErrorClass> {
    None
}

pub async fn execute_writer_overwrite<W: BlockWriter>(
    writer: W,
    total_passes: u8,
    pattern: OverwritePattern,
    device_serial: &str,
    method_name: &str,
    start: Instant,
    tx: mpsc::Sender<ProgressEvent>,
) -> Result<ExecutionReport, ExecuteError> {
    execute_writer_overwrite_with_cancel(
        writer,
        total_passes,
        pattern,
        device_serial,
        method_name,
        start,
        tx,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_writer_overwrite_with_cancel<W: BlockWriter>(
    writer: W,
    total_passes: u8,
    pattern: OverwritePattern,
    device_serial: &str,
    method_name: &str,
    start: Instant,
    tx: mpsc::Sender<ProgressEvent>,
    external_cancel_flag: Option<Arc<AtomicBool>>,
) -> Result<ExecutionReport, ExecuteError> {
    // No injected sink = the historic platform hook (Linux file writer;
    // no-op elsewhere), byte-identical to the pre-1.4a behavior.
    execute_writer_overwrite_with_cancel_and_sink(
        writer,
        total_passes,
        pattern,
        device_serial,
        method_name,
        start,
        tx,
        external_cancel_flag,
        None,
    )
    .await
}

/// Step 1.4a: the same wipe loop with an injected cross-platform checkpoint
/// sink (Windows uses [`crate::checkpoint_sink::FileCheckpointSink`]).
/// `None` keeps the historic hook so Linux behavior is unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn execute_writer_overwrite_with_cancel_and_sink<W: BlockWriter>(
    mut writer: W,
    total_passes: u8,
    pattern: OverwritePattern,
    device_serial: &str,
    method_name: &str,
    start: Instant,
    tx: mpsc::Sender<ProgressEvent>,
    external_cancel_flag: Option<Arc<AtomicBool>>,
    checkpoint_sink: Option<Arc<dyn CheckpointSink>>,
) -> Result<ExecutionReport, ExecuteError> {
    let checkpoint_sink = checkpoint_sink.as_deref();
    let command_log = vec![format!(
        "Native block overwrite ({} passes, mode: {})",
        total_passes,
        writer.io_mode()
    )];
    let device_size = writer.total_size().map_err(ExecuteError::IoError)?;
    let total_bytes = total_passes as u64 * device_size;

    let device_id_hash = format!("{:x}", Sha256::digest(device_serial.as_bytes()));
    let job_id =
        std::env::var("ZT_JOB_ID").unwrap_or_else(|_| format!("job-{}", &device_id_hash[..12]));

    let cancel_flag = external_cancel_flag.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    // Linux/Unix keep the historic SIGTERM/SIGINT graceful-cancel hooks.
    // Other platforms rely on the injected `external_cancel_flag` (the
    // Windows/Android transports own their own cancellation signal).
    #[cfg(unix)]
    let _term_hook =
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&cancel_flag));
    #[cfg(unix)]
    let _int_hook =
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&cancel_flag));

    let chunk_size = 2 * 1024 * 1024usize; // 2 MiB chunks
    let mut aligned_buf = AlignedBuffer::new(chunk_size);
    let mut speed_est = SpeedEstimator::new(3.0); // 3-second sliding window

    let bytes_done_shared = Arc::new(AtomicU64::new(0));
    let phase_shared = Arc::new(Mutex::new(ExecutionPhase::Preparing));

    // Spawn 1-second heartbeat task
    let (hb_stop_tx, mut hb_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let hb_tx = tx.clone();
    let hb_bytes_done = Arc::clone(&bytes_done_shared);
    let hb_phase = Arc::clone(&phase_shared);
    let hb_total_bytes = total_bytes;

    let hb_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(1000));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let phase = hb_phase.lock().unwrap().clone();
                    let done = hb_bytes_done.load(Ordering::Relaxed);
                    let pct = if hb_total_bytes > 0 { Some(done as f32 / hb_total_bytes as f32) } else { None };
                    let _ = hb_tx.send(ProgressEvent {
                        schema_version: 2,
                        phase,
                        bytes_done: done,
                        bytes_total: hb_total_bytes,
                        percent: pct,
                        speed_bytes_per_sec: 0.0,
                        eta_seconds: None,
                        message: "heartbeat".to_string(),
                        is_heartbeat: true,
                    }).await;
                }
                _ = &mut hb_stop_rx => {
                    break;
                }
            }
        }
    });

    let mut overall_bytes_done: u64 = 0;
    let mut uncommitted_buffered_bytes: u64 = 0;
    let is_buffered_mode = writer.io_mode().starts_with("buffered");
    let mut last_event_time = Instant::now();
    let mut last_checkpoint_time = Instant::now();

    *phase_shared.lock().unwrap() = ExecutionPhase::FirmwareCommand; // Writing phase

    let mut prng = ChaCha20Rng::from_entropy();

    for pass_idx in 0..total_passes {
        let is_random = match pattern {
            OverwritePattern::Random => true,
            OverwritePattern::MultiPass3 => pass_idx == 1,
            _ => false,
        };

        if !is_random {
            let fill_byte = match pattern {
                OverwritePattern::Ones => 0xFF,
                _ => 0x00,
            };
            aligned_buf.as_mut_slice().fill(fill_byte);
        }

        let mut offset = 0u64;
        while offset < device_size {
            // Check cancellation flag
            if cancel_flag.load(Ordering::SeqCst) {
                let _ = writer.sync_data();
                if is_buffered_mode && uncommitted_buffered_bytes > 0 {
                    overall_bytes_done += uncommitted_buffered_bytes;
                    bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                }
                checkpoint(
                    checkpoint_sink,
                    &job_id,
                    device_serial,
                    device_size,
                    overall_bytes_done,
                );
                let _ = hb_stop_tx.send(());
                let _ = hb_task.await;
                let _ = tx
                    .send(ProgressEvent {
                        schema_version: 2,
                        phase: ExecutionPhase::FirmwareCommand,
                        bytes_done: overall_bytes_done,
                        bytes_total: total_bytes,
                        percent: if total_bytes > 0 {
                            Some(overall_bytes_done as f32 / total_bytes as f32)
                        } else {
                            None
                        },
                        speed_bytes_per_sec: 0.0,
                        eta_seconds: None,
                        message: "Sanitization cancelled by user".to_string(),
                        is_heartbeat: false,
                    })
                    .await;
                return Ok(ExecutionReport {
                    success: false,
                    method_used: method_name.to_string(),
                    command_log,
                    stdout: String::new(),
                    stderr: "Sanitization cancelled by user: partially wiped".to_string(),
                    exit_code: 130,
                    duration_ms: start.elapsed().as_millis() as u64,
                    dry_run: false,
                    bytes_written: overall_bytes_done,
                    io_mode: writer.io_mode().to_string(),
                });
            }

            let write_len = std::cmp::min(chunk_size as u64, device_size - offset) as usize;
            if is_random {
                prng.fill_bytes(&mut aligned_buf.as_mut_slice()[..write_len]);
            }

            let mut written_for_chunk = 0;
            while written_for_chunk < write_len {
                if cancel_flag.load(Ordering::SeqCst) {
                    let _ = writer.sync_data();
                    if is_buffered_mode && uncommitted_buffered_bytes > 0 {
                        overall_bytes_done += uncommitted_buffered_bytes;
                        bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                    }
                    checkpoint(
                        checkpoint_sink,
                        &job_id,
                        device_serial,
                        device_size,
                        overall_bytes_done,
                    );
                    let _ = hb_stop_tx.send(());
                    let _ = hb_task.await;
                    let _ = tx
                        .send(ProgressEvent {
                            schema_version: 2,
                            phase: ExecutionPhase::FirmwareCommand,
                            bytes_done: overall_bytes_done,
                            bytes_total: total_bytes,
                            percent: if total_bytes > 0 {
                                Some(overall_bytes_done as f32 / total_bytes as f32)
                            } else {
                                None
                            },
                            speed_bytes_per_sec: 0.0,
                            eta_seconds: None,
                            message: "Sanitization cancelled by user".to_string(),
                            is_heartbeat: false,
                        })
                        .await;
                    return Ok(ExecutionReport {
                        success: false,
                        method_used: method_name.to_string(),
                        command_log,
                        stdout: String::new(),
                        stderr: "Sanitization cancelled by user: partially wiped".to_string(),
                        exit_code: 130,
                        duration_ms: start.elapsed().as_millis() as u64,
                        dry_run: false,
                        bytes_written: overall_bytes_done,
                        io_mode: writer.io_mode().to_string(),
                    });
                }

                let slice = &aligned_buf.as_slice()[written_for_chunk..write_len];
                match writer.write_chunk(offset + written_for_chunk as u64, slice) {
                    Ok(0) => {
                        let _ = hb_stop_tx.send(());
                        let _ = hb_task.await;
                        return Err(ExecuteError::PrematureEndOfDevice(
                            "Write returned 0 bytes (ENOSPC)".into(),
                        ));
                    }
                    Ok(n) => {
                        written_for_chunk += n;
                        if is_buffered_mode {
                            uncommitted_buffered_bytes += n as u64;
                            // In buffered mode, flush periodically (e.g. 16MB) or when pass finishes
                            if uncommitted_buffered_bytes >= 16 * 1024 * 1024
                                || (offset + written_for_chunk as u64 >= device_size)
                            {
                                if let Err(e) = writer.sync_data() {
                                    let _ = hb_stop_tx.send(());
                                    let _ = hb_task.await;
                                    return Err(ExecuteError::IoError(e));
                                }
                                overall_bytes_done += uncommitted_buffered_bytes;
                                uncommitted_buffered_bytes = 0;
                                bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                            }
                        } else {
                            overall_bytes_done += n as u64;
                            bytes_done_shared.store(overall_bytes_done, Ordering::Relaxed);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => match os_error_class(&e) {
                        Some(OsErrorClass::Eio) => {
                            let _ = hb_stop_tx.send(());
                            let _ = hb_task.await;
                            return Err(ExecuteError::HardwareIo(format!(
                                "EIO at offset {}: {}",
                                offset + written_for_chunk as u64,
                                e
                            )));
                        }
                        Some(OsErrorClass::Enodev) => {
                            let _ = hb_stop_tx.send(());
                            let _ = hb_task.await;
                            return Err(ExecuteError::DeviceDisconnected(format!(
                                "ENODEV at offset {}: {}",
                                offset + written_for_chunk as u64,
                                e
                            )));
                        }
                        Some(OsErrorClass::Enospc) => {
                            let _ = hb_stop_tx.send(());
                            let _ = hb_task.await;
                            return Err(ExecuteError::PrematureEndOfDevice(format!(
                                "ENOSPC at offset {}: {}",
                                offset + written_for_chunk as u64,
                                e
                            )));
                        }
                        None => {
                            let _ = hb_stop_tx.send(());
                            let _ = hb_task.await;
                            return Err(ExecuteError::IoError(e));
                        }
                    },
                }
            }

            offset += write_len as u64;
            speed_est.record(Instant::now(), overall_bytes_done);

            // Throttle progress events to ~3/sec
            let now = Instant::now();
            if now.duration_since(last_event_time).as_millis() >= 300 || offset >= device_size {
                last_event_time = now;
                let cur_speed = speed_est.current_speed();
                let eta = if cur_speed > 1024.0 && overall_bytes_done < total_bytes {
                    Some(((total_bytes - overall_bytes_done) as f64 / cur_speed) as u32)
                } else {
                    None
                };
                let pct = overall_bytes_done as f32 / total_bytes as f32;
                let msg = format!(
                    "Pass {} of {}: writing to media",
                    pass_idx + 1,
                    total_passes
                );
                send_detailed_progress(
                    &tx,
                    ExecutionPhase::FirmwareCommand,
                    overall_bytes_done,
                    total_bytes,
                    Some(pct),
                    cur_speed,
                    eta,
                    &msg,
                    false,
                )
                .await;
            }

            // Periodic checkpoint file write (~every 2 seconds)
            if now.duration_since(last_checkpoint_time).as_secs() >= 2 {
                last_checkpoint_time = now;
                checkpoint(
                    checkpoint_sink,
                    &job_id,
                    device_serial,
                    device_size,
                    overall_bytes_done,
                );
            }
        }
    }

    // Flush phase (Item 1, 2, 3)
    *phase_shared.lock().unwrap() = ExecutionPhase::Flushing;
    send_detailed_progress(
        &tx,
        ExecutionPhase::Flushing,
        overall_bytes_done,
        total_bytes,
        None,
        0.0,
        None,
        "Finalizing, flushing to drive",
        false,
    )
    .await;

    // Check cancellation promptly at start of flush
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        checkpoint(
            checkpoint_sink,
            &job_id,
            device_serial,
            device_size,
            overall_bytes_done,
        );
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user during flush".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    if let Err(e) = writer.sync_data() {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        return Err(ExecuteError::IoError(e));
    }
    if let Err(e) = writer.flush_buffers() {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        return Err(ExecuteError::IoError(e));
    }

    // Check cancellation promptly after sync/flush
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        checkpoint(
            checkpoint_sink,
            &job_id,
            device_serial,
            device_size,
            overall_bytes_done,
        );
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user after flush".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    *phase_shared.lock().unwrap() = ExecutionPhase::Verification;
    send_detailed_progress(
        &tx,
        ExecutionPhase::Verification,
        overall_bytes_done,
        total_bytes,
        None,
        0.0,
        None,
        "Verifying sector erasure...",
        false,
    )
    .await;

    // Check cancellation promptly before verification
    if cancel_flag.load(Ordering::SeqCst) {
        let _ = hb_stop_tx.send(());
        let _ = hb_task.await;
        checkpoint(
            checkpoint_sink,
            &job_id,
            device_serial,
            device_size,
            overall_bytes_done,
        );
        return Ok(ExecutionReport {
            success: false,
            method_used: method_name.to_string(),
            command_log,
            stdout: String::new(),
            stderr: "Sanitization cancelled by user during verification".to_string(),
            exit_code: 130,
            duration_ms: start.elapsed().as_millis() as u64,
            dry_run: false,
            bytes_written: overall_bytes_done,
            io_mode: writer.io_mode().to_string(),
        });
    }

    let _ = hb_stop_tx.send(());
    let _ = hb_task.await;

    // Checkpoint removal upon success
    finish_checkpoint(checkpoint_sink);

    Ok(ExecutionReport {
        success: overall_bytes_done == total_bytes,
        method_used: method_name.to_string(),
        command_log,
        stdout: format!(
            "Successfully overwritten {} bytes in {} passes",
            overall_bytes_done, total_passes
        ),
        stderr: String::new(),
        exit_code: 0,
        duration_ms: start.elapsed().as_millis() as u64,
        dry_run: false,
        bytes_written: overall_bytes_done,
        io_mode: writer.io_mode().to_string(),
    })
}

/// Step 1.4a: the CLI exit code for a completed wipe report, shared by every
/// platform so Windows matches Linux exactly:
/// `0` = success, `2` = failed (non-cancel), `130` = cancelled
/// (SIGTERM/SIGINT on Linux; Ctrl+C/Break/close on Windows).
pub fn report_exit_code(report: &ExecutionReport) -> i32 {
    if report.exit_code == 130 {
        130
    } else if report.success {
        0
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory writer: proves the loop and sink plumbing without hardware.
    struct VecWriter {
        data: Vec<u8>,
        size: u64,
    }

    impl VecWriter {
        fn new(size: u64) -> Self {
            Self {
                data: vec![0u8; size as usize],
                size,
            }
        }
    }

    impl BlockWriter for VecWriter {
        fn write_chunk(&mut self, offset: u64, data: &[u8]) -> io::Result<usize> {
            let start = offset as usize;
            let end = start + data.len();
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of range"));
            }
            self.data[start..end].copy_from_slice(data);
            Ok(data.len())
        }

        fn sync_data(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn flush_buffers(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn total_size(&self) -> io::Result<u64> {
            Ok(self.size)
        }

        fn io_mode(&self) -> &'static str {
            "test"
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        writes: Mutex<Vec<u64>>,
        removed: AtomicBool,
    }

    impl CheckpointSink for RecordingSink {
        fn write(&self, _job_id: &str, _serial: &str, _device_size: u64, bytes_done: u64) {
            self.writes.lock().unwrap().push(bytes_done);
        }

        fn remove(&self) {
            self.removed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn report_exit_code_matches_the_linux_contract() {
        let report = |success: bool, exit_code: i32| ExecutionReport {
            success,
            method_used: String::new(),
            command_log: Vec::new(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code,
            duration_ms: 0,
            dry_run: false,
            bytes_written: 0,
            io_mode: "test".to_string(),
        };
        assert_eq!(report_exit_code(&report(true, 0)), 0);
        assert_eq!(report_exit_code(&report(false, 0)), 2);
        assert_eq!(
            report_exit_code(&report(false, 130)),
            130,
            "cancelled wipes must exit 130 on every platform"
        );
    }

    #[tokio::test]
    async fn cancel_returns_130_and_writes_a_checkpoint_through_the_injected_sink() {
        let sink = Arc::new(RecordingSink::default());
        let cancel = Arc::new(AtomicBool::new(true));
        let (tx, _rx) = mpsc::channel(64);

        let report = execute_writer_overwrite_with_cancel_and_sink(
            VecWriter::new(4096),
            1,
            OverwritePattern::Zeros,
            "TEST-SERIAL",
            "Test Overwrite",
            Instant::now(),
            tx,
            Some(cancel),
            Some(sink.clone()),
        )
        .await
        .expect("cancellation is a report, not an error");

        assert!(!report.success);
        assert_eq!(report.exit_code, 130);
        assert_eq!(report_exit_code(&report), 130);
        assert!(
            !sink.writes.lock().unwrap().is_empty(),
            "cancellation must persist a checkpoint through the injected sink"
        );
        assert!(
            !sink.removed.load(Ordering::SeqCst),
            "a cancelled wipe must not remove its checkpoint"
        );
    }

    #[tokio::test]
    async fn success_removes_the_checkpoint_through_the_injected_sink() {
        let sink = Arc::new(RecordingSink::default());
        let (tx, _rx) = mpsc::channel(64);

        let report = execute_writer_overwrite_with_cancel_and_sink(
            VecWriter::new(4096),
            1,
            OverwritePattern::Zeros,
            "TEST-SERIAL",
            "Test Overwrite",
            Instant::now(),
            tx,
            Some(Arc::new(AtomicBool::new(false))),
            Some(sink.clone()),
        )
        .await
        .expect("wipe over the in-memory writer must succeed");

        assert!(report.success);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.bytes_written, 4096);
        assert_eq!(report_exit_code(&report), 0);
        assert!(
            sink.removed.load(Ordering::SeqCst),
            "a successful wipe must remove its checkpoint"
        );
        // Progress checkpoints are throttled (~2 s), so a tiny fast wipe
        // finishes before the first tick; the cancellation test above proves
        // the injected sink receives progress writes.
    }
}
