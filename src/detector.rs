use std::collections::HashMap;

// Detecteaza potentiale atacuri MITM
pub fn detect_mitm(
    _packets: &[super::network::NetworkPacket],
    _arp_table: &HashMap<String, String>,
) -> Vec<String> {
    // Forțează mereu o alertă de test
    vec!["Test alert: MITM detected!".to_string()]
}