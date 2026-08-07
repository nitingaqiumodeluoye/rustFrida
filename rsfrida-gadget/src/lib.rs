#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use agent::{
    hello_entry, rustfrida_set_initial_script_ready_callback, AgentArgs, StringTable,
};
use serde::Deserialize;
use std::ffi::{c_void, CStr};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Once};

const DEFAULT_ADDRESS: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 15819;
const FRAME_KIND_BOOTSTRAP_SCRIPT: u8 = 3;
const MAX_BOOTSTRAP_LINE: usize = 8192;
const MAX_SCRIPT_SIZE: usize = 16 * 1024 * 1024;

static START: Once = Once::new();

#[used]
#[link_section = ".init_array"]
static INIT_ARRAY: extern "C" fn() = gadget_constructor;

#[no_mangle]
pub unsafe extern "C" fn __clear_cache(start: *mut c_void, end: *mut c_void) {
    use std::arch::asm;

    let start = start as usize;
    let end = end as usize;
    if start >= end {
        return;
    }

    let ctr: usize;
    asm!("mrs {}, ctr_el0", out(reg) ctr, options(nostack, nomem, preserves_flags));

    if ctr & (1 << 28) == 0 {
        let line_size = 4usize << ((ctr >> 16) & 0xf);
        let mut address = start & !(line_size - 1);
        while address < end {
            asm!("dc cvau, {}", in(reg) address, options(nostack, preserves_flags));
            address += line_size;
        }
        asm!("dsb ish", options(nostack, preserves_flags));
    }

    if ctr & (1 << 29) == 0 {
        let line_size = 4usize << (ctr & 0xf);
        let mut address = start & !(line_size - 1);
        while address < end {
            asm!("ic ivau, {}", in(reg) address, options(nostack, preserves_flags));
            address += line_size;
        }
        asm!("dsb ish", options(nostack, preserves_flags));
    }

    asm!("isb", options(nostack, preserves_flags));
}

extern "C" fn gadget_constructor() {
    rsfrida_gadget_load();
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct GadgetConfig {
    interaction: ListenInteraction,
}

impl Default for GadgetConfig {
    fn default() -> Self {
        Self {
            interaction: ListenInteraction::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct ListenInteraction {
    #[serde(rename = "type")]
    kind: String,
    address: String,
    port: u16,
    on_load: LoadBehavior,
}

impl Default for ListenInteraction {
    fn default() -> Self {
        Self {
            kind: "listen".to_string(),
            address: DEFAULT_ADDRESS.to_string(),
            port: DEFAULT_PORT,
            // xfinject stages the library under a randomized filename, so its
            // sidecar config is not discoverable during the constructor. The
            // no-config path must return from dlopen so the injector can finish.
            on_load: LoadBehavior::Resume,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum LoadBehavior {
    Wait,
    Resume,
}

struct LoadGate {
    released: Mutex<bool>,
    changed: Condvar,
}

impl LoadGate {
    fn new() -> Self {
        Self {
            released: Mutex::new(false),
            changed: Condvar::new(),
        }
    }

    fn release(&self) {
        let mut released = self.released.lock().unwrap_or_else(|e| e.into_inner());
        *released = true;
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut released = self.released.lock().unwrap_or_else(|e| e.into_inner());
        while !*released {
            released = self.changed.wait(released).unwrap_or_else(|e| e.into_inner());
        }
    }
}

#[no_mangle]
pub extern "C" fn rsfrida_gadget_load() {
    START.call_once(|| {
        let config = match load_config() {
            Ok(config) => config,
            Err(error) => {
                eprintln!("[karina] config error: {}", error);
                GadgetConfig::default()
            }
        };
        if config.interaction.kind != "listen" {
            eprintln!(
                "[karina] unsupported interaction '{}', using listen",
                config.interaction.kind
            );
        }

        let wait_at_load = config.interaction.on_load == LoadBehavior::Wait;
        let gate = Arc::new(LoadGate::new());
        let worker_gate = gate.clone();
        let address = config.interaction.address;
        let port = config.interaction.port;
        let result = std::thread::Builder::new()
            .name("karina".to_string())
            .spawn(move || {
                if let Err(error) = run_listener(&address, port, worker_gate.clone()) {
                    eprintln!("[karina] listener failed: {}", error);
                    worker_gate.release();
                }
            });
        if let Err(error) = result {
            eprintln!("[karina] worker start failed: {}", error);
            gate.release();
        }

        if wait_at_load {
            gate.wait();
        }
    });
}

fn run_listener(address: &str, port: u16, gate: Arc<LoadGate>) -> Result<(), String> {
    let listener = TcpListener::bind((address, port)).map_err(|e| format!("bind {}:{}: {}", address, port, e))?;
    eprintln!("[karina] listening on {}:{}", address, port);

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                if let Err(error) = handle_client(stream, &gate) {
                    eprintln!("[karina] client error: {}", error);
                }
            }
            Err(error) => eprintln!("[karina] accept failed: {}", error),
        }
    }
    Ok(())
}

extern "C" fn release_load_gate(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let gate = unsafe { &*(context as *const LoadGate) };
    gate.release();
}

fn handle_client(mut stream: TcpStream, gate: &LoadGate) -> Result<(), String> {
    let line = read_bootstrap_line(&mut stream)?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    let command = parts.first().copied().unwrap_or("");

    if command == "list" {
        write!(
            stream,
            "0\t{}\tkarina\tconnected\n\n",
            std::process::id()
        )
        .map_err(|e| format!("write list: {}", e))?;
        return Ok(());
    }

    if !matches!(command, "gadget" | "attach" | "use") {
        writeln!(stream, "ERR 用法: gadget [-l script] 或 attach self [-l script]")
            .map_err(|e| format!("write error: {}", e))?;
        return Ok(());
    }

    let expects_script = parts.windows(2).any(|pair| pair == ["-l", "-"]);
    let script = if expects_script {
        Some(read_bootstrap_script(&mut stream)?)
    } else {
        None
    };

    if script.is_some() {
        rustfrida_set_initial_script_ready_callback(
            Some(release_load_gate),
            gate as *const LoadGate as *mut c_void,
        );
    }
    let has_script = script.is_some();

    writeln!(stream, "OK sid=0 pid={}", std::process::id()).map_err(|e| format!("write OK: {}", e))?;
    stream.flush().map_err(|e| format!("flush OK: {}", e))?;
    if !has_script {
        gate.release();
    }

    let command = script
        .map(|(filename, source)| format!("loadjs_init [{}]\n{}", filename, source))
        .unwrap_or_else(|| "novalue".to_string());
    let invocation = AgentInvocation::new(&command);
    let mut args = AgentArgs {
        table: &invocation.table as *const StringTable as u64,
        ctrl_fd: stream.into_raw_fd(),
        agent_memfd: -1,
    };
    hello_entry(&mut args as *mut AgentArgs as *mut c_void);
    // Do not release or clear the callback here. `hello_entry` may return as
    // soon as the host closes stdin, while the initial `loadjs_init` task is
    // still running on the agent JS worker. The one-shot callback is released
    // by the agent only after that task has finished, which keeps xfinject's
    // child paused until early hooks are installed.
    Ok(())
}

struct AgentInvocation {
    _cmdline: Vec<u8>,
    _output_path: Vec<u8>,
    table: StringTable,
}

impl AgentInvocation {
    fn new(command: &str) -> Self {
        let cmdline = nul_terminated(command);
        let output_path = nul_terminated("novalue");
        let table = StringTable {
            sym_name: 0,
            sym_name_len: 0,
            dlsym_err: 0,
            dlsym_err_len: 0,
            cmdline: cmdline.as_ptr() as u64,
            cmdline_len: cmdline.len() as u32,
            output_path: output_path.as_ptr() as u64,
            output_path_len: output_path.len() as u32,
        };
        Self {
            _cmdline: cmdline,
            _output_path: output_path,
            table,
        }
    }
}

fn nul_terminated(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn read_bootstrap_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < MAX_BOOTSTRAP_LINE {
        let count = stream.read(&mut byte).map_err(|e| format!("read bootstrap: {}", e))?;
        if count == 0 {
            return Err("client closed during bootstrap".to_string());
        }
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).trim_end_matches('\r').to_string());
        }
        line.push(byte[0]);
    }
    Err("bootstrap line too long".to_string())
}

fn read_bootstrap_script(stream: &mut TcpStream) -> Result<(String, String), String> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).map_err(|e| format!("read script header: {}", e))?;
    if header[0] != FRAME_KIND_BOOTSTRAP_SCRIPT {
        return Err(format!("unexpected bootstrap frame kind {}", header[0]));
    }
    let length = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    if length > MAX_SCRIPT_SIZE {
        return Err("bootstrap script too large".to_string());
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).map_err(|e| format!("read script: {}", e))?;
    if payload.len() < 4 {
        return Err("invalid bootstrap script frame".to_string());
    }
    let name_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if name_len == 0 || name_len > 256 || 4 + name_len > payload.len() {
        return Err("invalid bootstrap script filename".to_string());
    }
    let filename = String::from_utf8(payload[4..4 + name_len].to_vec())
        .map_err(|_| "bootstrap script filename is not UTF-8".to_string())?;
    let source = String::from_utf8(payload[4 + name_len..].to_vec())
        .map_err(|_| "bootstrap script is not UTF-8".to_string())?;
    Ok((filename, source))
}

fn load_config() -> Result<GadgetConfig, String> {
    for path in config_candidates() {
        if !path.exists() {
            continue;
        }
        let data = std::fs::read_to_string(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        return serde_json::from_str(&data).map_err(|e| format!("parse {}: {}", path.display(), e));
    }
    Ok(GadgetConfig::default())
}

fn config_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = std::env::var_os("RSFRIDA_GADGET_CONFIG") {
        paths.push(PathBuf::from(explicit));
    }
    if let Some(module) = module_path() {
        paths.push(module.with_extension("config"));
        if let Some(stem) = module.file_stem().and_then(|value| value.to_str()) {
            paths.push(module.with_file_name(format!("{}.config.so", stem)));
        }
        // xfinject stages the payload under a randomized filename in the
        // target app's files/ directory. Its -app-file option can place a
        // stable sidecar next to that payload, so check the module directory
        // for the packaged Gadget config as well.
        if let Some(parent) = module.parent() {
            paths.push(parent.join("librsfrida-gadget.config.so"));
            paths.push(parent.join("librsfrida-gadget.config"));
        }
    }
    paths
}

fn module_path() -> Option<PathBuf> {
    let mut info = unsafe { std::mem::zeroed::<libc::Dl_info>() };
    let result = unsafe { libc::dladdr(rsfrida_gadget_load as *const () as *const c_void, &mut info) };
    if result == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy();
    Some(Path::new(path.as_ref()).to_path_buf())
}
