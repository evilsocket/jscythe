use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

use clap::Parser;
use netstat2::*;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use websocket::{ClientBuilder, Message, OwnedMessage};

mod protocol;

type Error = String;

fn find_process(filter: &str) -> Option<u32> {
    let sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

    for (pid, process) in sys.processes() {
        let process_info = format!(
            "{} {} {:?}",
            process.name(),
            process.exe().display(),
            process.cmd()
        );

        // quick and dirty hack, i know
        let pid = pid.as_u32();
        if process_info.to_ascii_lowercase().contains(filter) && pid != std::process::id() {
            println!(
                "host found as pid {} -> {} ({})",
                pid,
                process.exe().display(),
                process.name()
            );
            return Some(pid);
        }
    }

    None
}

fn find_listening_ports_by_pid(pid: u32) -> Result<Vec<u16>, Error> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).map_err(|e| e.to_string())?;
    let mut by_pid = vec![];

    for si in sockets_info {
        if si.associated_pids.contains(&pid) {
            if let ProtocolSocketInfo::Tcp(tcp_si) = si.protocol_socket_info {
                if tcp_si.state == TcpState::Listen {
                    by_pid.push(tcp_si.local_port);
                }
            }
        }
    }

    Ok(by_pid)
}

fn find_inspection_port(ports: &[u16]) -> Option<u16> {
    for port in ports {
        if protocol::get_debug_url(*port).is_ok() {
            return Some(*port);
        }
    }
    None
}

fn enable_inspection_port(pid: u32) -> Result<u16, Error> {
    let ports_before = find_listening_ports_by_pid(pid)
        .map_err(|e| format!("could not find enumerate process open ports: {:?}", e))?;

    if let Some(port) = find_inspection_port(&ports_before) {
        println!("inspection already enabled on port {}", port);
        return Ok(port);
    }

    println!("sending SIGUSR1 to process {}", pid);

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGUSR1,
    )
    .map_err(|e| format!("could not send SIGUSR1 signal: {:?}", e))?;

    println!("waiting 3 seconds for the debugger to start ...");

    // give the debugger some time to start
    std::thread::sleep(std::time::Duration::from_secs(3));

    let ports_after = find_listening_ports_by_pid(pid)
        .map_err(|e| format!("could not find enumerate process open ports: {:?}", e))?;

    if let Some(port) = find_inspection_port(&ports_after) {
        return Ok(port);
    }

    Err(format!(
        "could not infer inspection port, before={:?} after={:?}",
        ports_before, ports_after
    ))
}

#[derive(Parser, Default, Debug, Clone)]
#[clap(about = "Force any Node/Electron/V8 based process to execute arbitrary javascript code.")]
struct Arguments {
    /// Process id.
    #[clap(long)]
    pid: Option<u32>,
    /// Use this expression to search for the process instead of specifying its PID.
    #[clap(long)]
    search: Option<String>,
    /// Path of the script to inject.
    #[clap(long, default_value = "example_script.js")]
    script: String,
    /// Code to execute.
    #[clap(long)]
    code: Option<String>,
    /// Fetch available objects and exit.
    #[clap(long, takes_value = false)]
    domains: bool,
    /// Execute a custom request payload, use '-' to read from stdin.
    #[clap(long)]
    custom_payload: Option<String>,
    /// Variable polling time in milliseconds.
    #[clap(long, default_value_t = 1000)]
    poll_interval: u64,
    /// Poll variable by name at regular intervals.
    #[clap(long)]
    poll_variable: Option<String>,
    /// If specified along with --poll-variable, this command will be executed and variable values passed to its standard input.
    #[clap(long)]
    poll_command: Option<String>,
}

fn main() {
    let args = Arguments::parse();

    println!(
        "{} v{}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    // 1. find the process
    let host_pid = match args.pid {
        Some(pid) => pid,
        None => match args.search {
            Some(filter) => match find_process(&filter.to_ascii_lowercase()) {
                Some(pid) => pid,
                None => {
                    println!("could not find node host process.");
                    std::process::exit(1);
                }
            },
            None => {
                println!("one of --pid or --search arguments must be specified.");
                std::process::exit(1);
            }
        },
    };

    // 2. enable inspection port by sending SIGUSR1 to it
    //  2.5. infer port by diffing open ports before and after the signal has been sent
    let inspect_port = match enable_inspection_port(host_pid) {
        Ok(port) => port,
        Err(e) => {
            println!("could not find vscode extension host port: {:?}", e);
            std::process::exit(1);
        }
    };

    if args.domains {
        // only show available domains
        let domains = match protocol::get_domains(inspect_port) {
            Ok(url) => url,
            Err(e) => {
                println!("could not find available domains: {:?}", e);
                std::process::exit(1);
            }
        };

        println!("\navailable execution domains:");
        for domain in domains {
            println!("* {}", domain.domain);
            for command in domain.commands {
                println!("  {}", command.display());
            }
        }
        std::process::exit(0);
    }

    // 3. get websocket debug url from http://localhost:<port>/json
    let debug_url = match protocol::get_debug_url(inspect_port) {
        Ok(url) => url,
        Err(e) => {
            println!("could not find debug url: {:?}", e);
            std::process::exit(1);
        }
    };

    // 4. send payload request -> profit
    println!("connecting to {:?}", &debug_url);

    let mut builder = ClientBuilder::new(&debug_url).unwrap();

    let mut client = builder.connect_insecure().unwrap();

    let payload = if let Some(custom) = args.custom_payload {
        // execute custom payload
        if custom == "-" {
            // read payload from stdin
            let stdin = io::stdin();
            stdin
                .lock()
                .lines()
                .into_iter()
                .map(|r| r.unwrap())
                .collect::<Vec<String>>()
                .join("\n")
        } else {
            custom
        }
    } else {
        // execute default Runtime.evaluate payload
        let script = match args.code {
            Some(code) => code,
            None => std::fs::read_to_string(&args.script).unwrap(),
        };

        let request = protocol::requests::RuntimeEval::new(&script);

        serde_json::to_string(&request).unwrap()
    };

    println!("connected, sending payload ...");

    client.send_message(&Message::text(payload)).unwrap();

    println!("payload sent!");

    let varialble_payload = args.poll_variable.map(|name| {
        serde_json::to_string(&protocol::requests::RuntimeEval::new(&format!(
            "JSON.stringify({})",
            name
        )))
        .unwrap()
    });

    let mut poll_process = match args.poll_command {
        Some(cmd) => {
            println!("starting process '{}'", cmd);
            Some(Command::new(cmd).stdin(Stdio::piped()).spawn().unwrap())
        }
        None => None,
    };

    println!("reading events, press ctrl+c to exit ...\n");

    // first read Runtime.eval result
    println!("{:?}", client.recv_message().unwrap());
    println!();

    loop {
        if let Some(poll_payload) = &varialble_payload {
            client.send_message(&Message::text(poll_payload)).unwrap();

            let resp = client.recv_message().unwrap();
            if let OwnedMessage::Text(data) = resp {
                let result: protocol::responses::ResultMessage =
                    serde_json::from_str(&data).unwrap();

                let res_value = result.result.result.value.unwrap_or_else(|| "".to_owned());

                if let Some(ref mut child) = poll_process {
                    child
                        .stdin
                        .as_mut()
                        .unwrap()
                        .write_all(format!("{}\n", &res_value).as_bytes())
                        .unwrap();
                } else {
                    println!("{}", &res_value);
                }
            } else {
                println!("got non text message: {:?}", resp);
            }

            std::thread::sleep(std::time::Duration::from_millis(args.poll_interval));
        } else {
            println!("{:?}", client.recv_message().unwrap());
        }
    }
}
