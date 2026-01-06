use clap::Parser;
use colored::*;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use std::collections::HashSet;
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
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Windows doesn't have a simple root check, assume false
        false
    }
}

fn find_port_owners(
    port: u16,
    check_all: bool,
) -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = if check_all {
        ProtocolFlags::TCP | ProtocolFlags::UDP
    } else {
        ProtocolFlags::TCP
    };

    let sockets = get_sockets_info(af_flags, proto_flags)?;
    let sys = System::new_all();
    let mut seen_pids = HashSet::new();
    let mut results = Vec::new();

    for socket in sockets {
        if socket.local_port() != port {
            continue;
        }

        let protocol = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "TCP",
            ProtocolSocketInfo::Udp(_) => "UDP",
        };

        let state = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => Some(format_tcp_state(tcp.state)),
            ProtocolSocketInfo::Udp(_) => None,
        };

        let local_addr = format!("{}:{}", socket.local_addr(), socket.local_port());

        for &pid in &socket.associated_pids {
            if !seen_pids.insert(pid) {
                continue;
            }

            if let Some(process) = sys.process(Pid::from_u32(pid)) {
                results.push(ProcessInfo {
                    pid,
                    name: process.name().to_string_lossy().to_string(),
                    cmd: process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string_lossy().to_string())
                        .collect(),
                    user: process.user_id().map(|u| u.to_string()),
                    protocol: protocol.to_string(),
                    local_addr: local_addr.clone(),
                    state: state.clone(),
                });
            }
        }
    }

    Ok(results)
}

fn format_tcp_state(state: TcpState) -> String {
    match state {
        TcpState::Established => "ESTABLISHED",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynReceived => "SYN_RECV",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::Closed => "CLOSE",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::LastAck => "LAST_ACK",
        TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING",
        _ => "UNKNOWN",
    }
    .to_string()
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
