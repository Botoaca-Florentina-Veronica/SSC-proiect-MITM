use mitm_detector::network;
use mitm_detector::detector;
use std::collections::HashMap;

fn main() {
    // Simulam niste date pentru demo
    let packets = vec![
        network::NetworkPacket {
            timestamp: 123456789,
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            protocol: "DNS".to_string(),
            length: 100,
            payload: vec![],
        },
        // ... alte pachete simulate
    ];

    let mut arp_table = HashMap::new();
    arp_table.insert("192.168.1.1".to_string(), "00:11:22:33:44:55".to_string());
    arp_table.insert("192.168.1.1".to_string(), "00:11:22:33:44:56".to_string()); // Duplicat intentionat

    // Rulam detectia
    let alerts = detector::detect_mitm(&packets, &arp_table);

    println!("Demo Results:");
    for alert in alerts {
        println!("Alert: {}", alert);
    }
}