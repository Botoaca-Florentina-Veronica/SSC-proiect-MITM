// Declară un modul numit `network` (definit într-un fișier `network.rs` sau `network/mod.rs`)
mod network;

// Declară un modul numit `detector` (definit într-un fișier `detector.rs` sau `detector/mod.rs`)
mod detector;

// Importă structura `Duration` din biblioteca standard pentru a gestiona intervale de timp
use std::time::Duration;

// Importă modulul `thread` din biblioteca standard pentru a putea pune programul în pauză
use std::thread;

// Funcția principală a programului
fn main() {
    // Afișează un mesaj la pornire
    println!("MITM Detector starting...");

    // Intră într-o buclă infinită pentru monitorizare continuă
    loop {
        // === 1. CAPTURĂ TRAFIC DE REȚEA ===
        // Încearcă să monitorizeze traficul pe interfața "eth0", capturând maxim 5000 de pachete
        let packets = match network::monitor_traffic("eth0", 5000) {
            // Dacă funcția reușește, returnează pachetele
            Ok(p) => p,
            // Dacă funcția eșuează, afișează eroarea și continuă bucla
            Err(e) => {
                eprintln!("Error monitoring traffic: {}", e);
                continue;
            }
        };

        // === 2. VERIFICARE TABELĂ ARP ===
        // Încearcă să obțină tabela ARP curentă
        let arp_table = match network::check_arp_table() {
            // Dacă reușește, returnează tabela
            Ok(table) => table,
            // Dacă eșuează, afișează eroarea și continuă bucla
            Err(e) => {
                eprintln!("Error checking ARP table: {}", e);
                continue;
            }
        };

        // === 3. DETECȚIE ATACURI MITM ===
        // Folosește modulul `detector` pentru a analiza pachetele și tabela ARP
        let alerts = detector::detect_mitm(&packets, &arp_table);

        // === 4. AFIȘARE ALERTE ===
        // Dacă s-au găsit alerte MITM
        if !alerts.is_empty() {
            println!("=== Potential MITM Attacks Detected ===");
            // Afișează fiecare alertă
            for alert in alerts {
                println!("[!] {}", alert);
            }
        } else {
            // Dacă nu s-au găsit alerte
            println!("No MITM attacks detected in this interval");
        }

        // Așteaptă 5 secunde înainte de a repeta bucla
        thread::sleep(Duration::from_secs(5));
    }
}
