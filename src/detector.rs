use std::collections::HashMap;

// Detecteaza potentiale atacuri MITM
pub fn detect_mitm(
    packets: &[super::network::NetworkPacket],
    arp_table: &HashMap<String, String>,
) -> Vec<String> {
    let mut alerts = Vec::new();

    // 1. Verificare pentru ARP spoofing
    if let Some(arp_spoof_alert) = check_arp_spoofing(arp_table) {
        alerts.push(arp_spoof_alert);
    }

    // 2. Verificare pentru duplicate IP in ARP
    if let Some(duplicate_ip_alert) = check_duplicate_ip(arp_table) {
        alerts.push(duplicate_ip_alert);
    }

    // 3. Verificare pentru trafic suspect (ex: multe cereri DNS)
    if let Some(dns_alert) = check_dns_traffic(packets) {
        alerts.push(dns_alert);
    }

    alerts
}

fn check_arp_spoofing(arp_table: &HashMap<String, String>) -> Option<String> {
    // In implementarea reala, am verifica daca adresele MAC se schimba frecvent
    // Pentru demo, presupunem ca am gasit o anomalie
    if arp_table.len() > 5 { // Conditie arbitrara pentru demo
        Some("Potential ARP spoofing detected: Multiple MAC addresses changing frequently".to_string())
    } else {
        None
    }
}

fn check_duplicate_ip(arp_table: &HashMap<String, String>) -> Option<String> {
    // Verificam daca aceeasi IP apare cu multiple MAC-uri
    let mut ip_counts = HashMap::new();
    for (ip, mac) in arp_table {
        let count = ip_counts.entry(ip).or_insert(0);
        *count += 1;
    }

    if ip_counts.values().any(|&count| count > 1) {
        Some("Duplicate IP addresses detected in ARP table".to_string())
    } else {
        None
    }
}

fn check_dns_traffic(packets: &[super::network::NetworkPacket]) -> Option<String> {
    // Verificam trafic DNS excesiv
    let dns_packets = packets.iter()
        .filter(|p| p.protocol == "DNS")
        .count();

    if dns_packets > 100 { // Prag arbitrar pentru demo
        Some("Excessive DNS traffic detected - potential DNS spoofing".to_string())
    } else {
        None
    }
}