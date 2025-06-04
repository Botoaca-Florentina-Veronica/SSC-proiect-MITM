mod network;
mod detector;

use std::time::Duration;
use std::thread;
use serde_json;

fn main() {
    println!("MITM Detector starting...");

    // Monitorizeaza traficul in bucla
    loop {
        // 1. Captura trafic de retea
        let packets = match network::monitor_traffic("eth0", 5000) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error monitoring traffic: {}", e);
                continue;
            }
        };

        // 2. Verifica tabela ARP
        let arp_table = match network::check_arp_table() {
            Ok(table) => table,
            Err(e) => {
                eprintln!("Error checking ARP table: {}", e);
                continue;
            }
        };

        // 3. Detecteaza atacuri MITM
        let alerts = detector::detect_mitm(&packets, &arp_table);

        // 4. Afiseaza alerte
        if !alerts.is_empty() {
            println!("=== Potential MITM Attacks Detected ===");
            for alert in &alerts {
                println!("[!] {}", alert);
            }
        } else {
            println!("No MITM attacks detected in this interval");
        }

        println!("{}", serde_json::to_string(&alerts).unwrap());

        thread::sleep(Duration::from_secs(5));
    }
}