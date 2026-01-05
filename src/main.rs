use clap::Parser;
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use sysinfo::{Pid, System};

#[derive(Parser)]
#[command(name = "wtf")]
#[command(version = "0.1.0")]
#[command(about = "Who the FUCK is using this port?")]
struct Cli {
    port: u16,
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    all: bool,
}

#[derive(Debug)]
struct ProcessInfo {
    pid: u32,
    name: String,
    cmd: Vec<String>,
    user: Option<String>,
    protocol: String,
    local_addr: String,
    state: Option<String>,
}

type SocketInfo = (u64, String, Option<String>); // (inode, address, state)

fn main() {
    let cli = Cli::parse();

    match find_port_owners(cli.port, cli.all) {
        Ok(processes) if processes.is_empty() => print_not_found(cli.port),
        Ok(processes) => print_results(&processes, cli.verbose),
        Err(e) => {
            eprintln!("{}", format!("Error: {}", e).red());
            std::process::exit(1);
        }
    }
}

fn print_not_found(port: u16) {
    if is_root() {
        println!("{}", format!("Port {} is not in use", port).yellow());
    } else {
        println!(
            "{}",
            format!(
                "Port {} should be probably, maybe, or likely not in use... WTF!?",
                port
            )
            .yellow()
        );
        println!("{}", "Try running with sudo?".bright_black());
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn find_port_owners(
    port: u16,
    check_all: bool,
) -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
    let sockets = collect_sockets(port, check_all)?;
    let sys = System::new_all();
    let mut seen_pids = HashMap::new();

    Ok(sockets
        .into_iter()
        .filter_map(|(inode, addr, state, proto)| {
            let pid = find_pid_by_inode(inode)?;

            if seen_pids.contains_key(&pid) {
                return None;
            }
            seen_pids.insert(pid, ());

            let process = sys.process(Pid::from_u32(pid))?;

            Some(ProcessInfo {
                pid,
                name: process.name().to_string_lossy().to_string(),
                cmd: process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect(),
                user: process.user_id().map(|u| u.to_string()),
                protocol: proto,
                local_addr: addr,
                state,
            })
        })
        .collect())
}

fn collect_sockets(
    port: u16,
    check_all: bool,
) -> io::Result<Vec<(u64, String, Option<String>, String)>> {
    let mut sockets = Vec::new();

    // TCP
    for (file, proto) in [("/proc/net/tcp", "TCP"), ("/proc/net/tcp6", "TCP")] {
        if let Ok(info) = parse_net_file(file, port) {
            sockets.extend(
                info.into_iter()
                    .map(|(i, a, s)| (i, a, s, proto.to_string())),
            );
        }
    }

    // UDP (optional)
    if check_all {
        for (file, proto) in [("/proc/net/udp", "UDP"), ("/proc/net/udp6", "UDP")] {
            if let Ok(info) = parse_net_file(file, port) {
                sockets.extend(
                    info.into_iter()
                        .map(|(i, a, _)| (i, a, None, proto.to_string())),
                );
            }
        }
    }

    Ok(sockets)
}

fn parse_net_file(path: &str, target_port: u16) -> io::Result<Vec<SocketInfo>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);

    Ok(reader
        .lines()
        .skip(1) // Skip header
        .filter_map(|line| {
            let line = line.ok()?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 10 {
                return None;
            }

            let local_addr = parts[1];
            let port_hex = local_addr.split(':').nth(1)?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;

            if port != target_port {
                return None;
            }

            let ip_hex = local_addr.split(':').next()?;
            let ip = parse_hex_ip(ip_hex);
            let state = parse_tcp_state(parts[3]);
            let inode = parts[9].parse().ok()?;

            Some((inode, format!("{}:{}", ip, port), state))
        })
        .collect())
}

fn parse_hex_ip(hex: &str) -> String {
    match hex.len() {
        8 => {
            // IPv4 (little-endian)
            let bytes: Vec<u8> = (0..4)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
                .collect();
            format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
        }
        32 => "::".to_string(), // IPv6 simplified
        _ => "0.0.0.0".to_string(),
    }
}

fn parse_tcp_state(hex: &str) -> Option<String> {
    let state = u8::from_str_radix(hex, 16).ok()?;
    Some(
        match state {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            _ => "UNKNOWN",
        }
        .to_string(),
    )
}

fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);

    fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let pid: u32 = path.file_name()?.to_str()?.parse().ok()?;

            let fd_dir = path.join("fd");
            let has_socket = fs::read_dir(fd_dir).ok()?.flatten().any(|fd| {
                fs::read_link(fd.path())
                    .ok()
                    .and_then(|link| link.to_str().map(|s| s.contains(&target)))
                    .unwrap_or(false)
            });

            has_socket.then_some(pid)
        })
        .next()
}

fn print_results(processes: &[ProcessInfo], verbose: bool) {
    let port = processes[0].local_addr.split(':').last().unwrap();

    println!(
        "\n{}",
        format!("Port {} is being used by:", port).cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());

    for (idx, info) in processes.iter().enumerate() {
        if idx > 0 {
            println!("{}", "-".repeat(60).bright_black());
        }

        println!("\n{}: {}", "Protocol".bright_white(), info.protocol.green());
        println!(
            "{}: {}",
            "PID".bright_white(),
            info.pid.to_string().yellow()
        );
        println!("{}: {}", "Process".bright_white(), info.name.bright_green());

        if let Some(ref state) = info.state {
            println!("{}: {}", "State".bright_white(), state.bright_blue());
        }

        if let Some(ref user) = info.user {
            println!("{}: {}", "User".bright_white(), user.magenta());
        }

        println!(
            "{}: {}",
            "Address".bright_white(),
            info.local_addr.bright_cyan()
        );

        if verbose && !info.cmd.is_empty() {
            println!("\n{}:", "Command".bright_white());
            let cmd_str = info.cmd.join(" ");
            let display = if cmd_str.len() > 80 {
                format!("{}...", &cmd_str[..77])
            } else {
                cmd_str
            };
            println!("  {}", display.bright_black());
        }
    }

    println!("\n{}", "=".repeat(60).cyan());

    if !verbose && processes.iter().any(|p| !p.cmd.is_empty()) {
        println!(
            "\n{}",
            "Tip: Use --verbose to show full command".bright_black()
        );
    }
}
