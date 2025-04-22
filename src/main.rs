use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use clap::{command, Arg, ArgAction, ArgMatches};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use futures::future::join_all;
use rayon::prelude::*;

// Common port to service mapping
fn get_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        _ => "Unknown"
    }
}

#[tokio::main]
async fn main() {
    let match_result: ArgMatches = command!()
        .arg(Arg::new("ip_address").short('a').long("ip_address").required(true).help("IP address of the target to scan"))
        .arg(Arg::new("end_port").short('e').long("ending_port").required(true).help("the last port to get to while scanning"))
        .arg(Arg::new("start_port").short('s').long("starting_port").required(true).help("from what port to start scanning"))
        .arg(Arg::new("port_scan").short('p').long("port-scan").help("a single port to scan"))
        .arg(Arg::new("url").short('u').long("url").help("URL to scan"))
        .arg(Arg::new("banner").short('b').long("banner").help("banner to scan").action(ArgAction::SetFalse))
        .arg(Arg::new("timeout").short('t').long("timeout").help("Connection timeout in milliseconds").default_value("200"))
        .arg(Arg::new("concurrent").short('c').long("concurrent").help("Maximum number of concurrent connections").default_value("5000"))
        .get_matches();

    println!("Starting port scan...");
    let start_time = Instant::now();

    let scan_results = scan_ports(&match_result).await;

    // Print results in organized format
    println!("\n{:-^80}", " SCAN RESULTS ");
    println!("{:<10} | {:<10} | {:<50}", "PORT", "STATUS", "SERVICE/BANNER");
    println!("{:-^80}", "");

    let mut ports: Vec<_> = scan_results.keys().collect();
    ports.sort();

    for port in ports {
        let banner = scan_results.get(port).unwrap();
        let service = get_service_name(*port);

        // Truncate banner if it's too long
        let display_info = if banner == "Open" {
            service.to_string()
        } else {
            // Limit banner length for display
            let clean_banner = banner.replace('\n', " ").replace('\r', "");
            let truncated = if clean_banner.len() > 45 {
                format!("{}...", &clean_banner[..42])
            } else {
                clean_banner
            };

            format!("{} - {}", service, truncated)
        };

        println!("{:<10} | {:<10} | {:<50}", port, "OPEN", display_info);
    }

    println!("{:-^80}", "");
    println!("Scan completed in {:.2?}", start_time.elapsed());
    println!("Found {} open ports", scan_results.len());
}

async fn scan_ports(match_result: &ArgMatches) -> HashMap<u16, String> {
    let start = Instant::now();

    // Extract parameters
    let ip_v4: String = match_result.get_one::<String>("ip_address").unwrap().clone();
    let start_port: u16 = match_result.get_one::<String>("start_port").unwrap().parse().unwrap();
    let end_port: u16 = match_result.get_one::<String>("end_port").unwrap().parse().unwrap();
    let collect_banners = match_result.get_flag("banner");

    // Get timeout from args or use default
    let timeout_ms: u64 = match_result.get_one::<String>("timeout")
        .map(|s| s.parse().unwrap_or(200))
        .unwrap_or(200);

    // Get max concurrent connections
    let max_concurrent: usize = match_result.get_one::<String>("concurrent")
        .map(|s| s.parse().unwrap_or(5000))
        .unwrap_or(5000);

    println!("Scanning {} ports on {} with {}ms timeout", end_port - start_port + 1, ip_v4, timeout_ms);
    println!("Using up to {} concurrent connections", max_concurrent);
    println!("Please wait, results will be displayed when scan completes...");

    // Parse IP address
    let ip_addr = match ip_v4.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            println!("Invalid IP address: {}", ip_v4);
            return HashMap::new();
        }
    };

    // Shared results map
    let results = Arc::new(Mutex::new(HashMap::new()));

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    // Create tasks for each port
    let mut tasks = Vec::new();
    //for port in start_port..=end_port
    for port in start_port..=end_port { //(start_port..=end_port).into_par_iter().for_each(|port| 
        let sem_clone = Arc::clone(&semaphore);
        let results_clone = Arc::clone(&results);
        let ip = ip_addr.clone();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let get_banner = collect_banners;

        // Spawn a task for each port
        let task = tokio::spawn(async move {
            // Acquire a permit from the semaphore
            let _permit = sem_clone.acquire().await.unwrap();

            // Create socket address
            let socket_addr = SocketAddr::new(ip, port);

            // Try to connect with timeout
            match timeout(timeout_duration, TcpStream::connect(&socket_addr)).await {
                Ok(Ok(mut stream)) => {
                    // Successfully connected
                    let mut result = String::from("Open");

                    if get_banner {
                        // Try to get banner
                        let mut buffer = [0u8; 1024];

                        // Some services require a prompt before sending a banner
                        // Send a simple newline to trigger a response
                        let _ = stream.write_all(b"\r\n").await;

                        // Set a read timeout
                        match timeout(timeout_duration, stream.read(&mut buffer)).await {
                            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                                result = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                                // Clean up the banner (remove control characters, limit length)
                                result = result.chars()
                                    .filter(|&c| c >= ' ' && c <= '~' || c == '\n' || c == '\r')
                                    .take(100)
                                    .collect();
                            },
                            _ => {
                                result = "Connected, no banner".to_string();
                            }
                        }
                    }

                    // Update results
                    let mut results_lock = results_clone.lock().await;
                    results_lock.insert(port, result);
                },
                _ => {
                    // Connection failed or timed out - port is closed or filtered
                }
            }
        });

        tasks.push(task);

        // Process in smaller batches to avoid overwhelming the system
        if tasks.len() >= 10000 {
            join_all(tasks).await;
            tasks = Vec::new();
        }
    }

    // Wait for remaining tasks to complete
    join_all(tasks).await;

    let elapsed = start.elapsed();
    let results_lock = results.lock().await;
    let final_results = results_lock.clone();

    final_results
}
