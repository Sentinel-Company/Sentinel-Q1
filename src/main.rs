//! Sentinel-X Main Binary
//! 
//! Test ve demo uygulaması

use sentinel_x::SentinelCore;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  Sentinel-X - Öngörülü Biyometrik Savunma Kalkanı");
    println!("{}", "=".repeat(60));
    
    // Initialize Sentinel-X
    let mut sentinel = SentinelCore::new()?;
    sentinel.initialize()?;
    
    println!("\n🎯 Test Senaryoları:");
    println!("{}", "-".repeat(40));
    
    // Test 1: System Status
    test_system_status(&sentinel);
    
    // Test 2: Voice Authentication
    test_voice_authentication(&mut sentinel)?;
    
    // Test 3: Network Packet Processing
    test_network_processing(&mut sentinel);
    
    // Test 4: Security Level Management
    test_security_levels(&mut sentinel)?;
    
    // Test 5: IP Blocking
    test_ip_blocking(&mut sentinel);
    
    // Test 6: System Lock/Unlock
    test_system_locking(&mut sentinel)?;
    
    println!("\n🎉 Tüm testler başarıyla tamamlandı!");
    println!("📊 Son Durum:");
    print_final_status(&sentinel);
    
    Ok(())
}

fn test_system_status(sentinel: &SentinelCore) {
    println!("\n1️⃣  Sistem Durumu Kontrolü:");
    let status = sentinel.get_status();
    println!("   • Aktif: {}", if status.is_active { "✅" } else { "❌" });
    println!("   • Güvenlik Seviyesi: {}/4", status.security_level);
    println!("   • Sistem Kilidi: {}", if status.is_locked { "🔒" } else { "🔓" });
    println!("   • Engellenen IP'ler: {}", status.blocked_ips_count);
}

fn test_voice_authentication(sentinel: &mut SentinelCore) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2️⃣  Ses Biyometri Doğrulama:");
    
    // Simulate voice data
    let voice_data = simulate_voice_data();
    
    // Register voice profile
    println!("   📝 Ses profili kaydediliyor...");
    sentinel.register_voice(1, &voice_data)?;
    
    // Verify voice
    println!("   🔍 Ses doğrulanıyor...");
    let confidence = sentinel.verify_voice(1, &voice_data)?;
    println!("   ✅ Doğrulama başarılı! Güven: {:.1}%", confidence * 100.0);
    
    Ok(())
}

fn test_network_processing(sentinel: &mut SentinelCore) {
    println!("\n3️⃣  Network Paket İşleme:");
    
    // Test normal packet
    let normal_packet = create_normal_packet();
    let action = sentinel.process_packet(&normal_packet);
    println!("   📦 Normal paket: {:?}", action);
    
    // Test suspicious packet
    let suspicious_packet = create_suspicious_packet();
    let action = sentinel.process_packet(&suspicious_packet);
    println!("   🚨 Şüpheli paket: {:?}", action);
    
    // Test malicious packet
    let malicious_packet = create_malicious_packet();
    let action = sentinel.process_packet(&malicious_packet);
    println!("   💀 Kötücül paket: {:?}", action);
}

fn test_security_levels(sentinel: &mut SentinelCore) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4️⃣  Güvenlik Seviyesi Yönetimi:");
    
    for level in 1..=4 {
        println!("   🛡️  Seviy {} ayarlanıyor...", level);
        sentinel.set_security_level(level)?;
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("   ✅ Tüm seviyeler başarıyla ayarlandı");
    
    Ok(())
}

fn test_ip_blocking(sentinel: &mut SentinelCore) {
    println!("\n5️⃣  IP Engelleme Testi:");
    
    // Block some test IPs
    let test_ips = [0xC0A80164, 0xC0A80165, 0xC0A80166]; // 192.168.1.100-102
    
    for ip in &test_ips {
        sentinel.block_ip(*ip);
    }
    
    // Test packet from blocked IP
    let packet_from_blocked_ip = create_packet_from_ip(*test_ips.first().unwrap());
    let action = sentinel.process_packet(&packet_from_blocked_ip);
    println!("   🚫 Engellenen IP'den gelen paket: {:?}", action);
    
    // Unblock one IP
    sentinel.unblock_ip(*test_ips.first().unwrap());
    println!("   ✅ IP engeli kaldırıldı");
}

fn test_system_locking(sentinel: &mut SentinelCore) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n6️⃣  Sistem Kilitleme Testi:");
    
    // Lock system
    println!("   🔒 Sistem kilitleniyor...");
    sentinel.lock_system();
    
    // Try to verify voice (should fail)
    let voice_data = simulate_voice_data();
    match sentinel.verify_voice(1, &voice_data) {
        Ok(_) => println!("   ⚠️  Ses doğrulama başarılı (beklenmedik)"),
        Err(_) => println!("   ✅ Ses doğrulama engellendi (beklenen)"),
    }
    
    // Unlock system
    println!("   🔔 Sistem kilidi açılıyor...");
    sentinel.unlock_system(1)?;
    
    // Try voice verification again (should succeed)
    match sentinel.verify_voice(1, &voice_data) {
        Ok(confidence) => println!("   ✅ Ses doğrulama başarılı! Güven: {:.1}%", confidence * 100.0),
        Err(e) => println!("   ❌ Ses doğrulama başarısız: {}", e),
    }
    
    Ok(())
}

fn print_final_status(sentinel: &SentinelCore) {
    let status = sentinel.get_status();
    println!("   • Aktif: {}", if status.is_active { "✅" } else { "❌" });
    println!("   • Güvenlik Seviyesi: {}/4", status.security_level);
    println!("   • Sistem Kilidi: {}", if status.is_locked { "🔒" } else { "🔓" });
    println!("   • Engellenen IP'ler: {}", status.blocked_ips_count);
    println!("   • Aktif Kurallar: {}", status.active_rules_count);
}

// Helper functions to create test data
fn simulate_voice_data() -> Vec<u8> {
    // Create simulated voice data (1KB of random-like data)
    (0..1024).map(|i| ((i * 17 + 42) % 256) as u8).collect()
}

fn create_normal_packet() -> Vec<u8> {
    // Create a normal network packet
    let mut packet = vec![0u8; 64];
    
    // IP header (simplified)
    packet[0] = 0x45; // Version + IHL
    packet[1] = 0x00; // Type of Service
    packet[2] = 0x00; // Total Length (high)
    packet[3] = 0x40; // Total Length (low)
    packet[6] = 0x00; // Flags + Fragment Offset (high)
    packet[7] = 0x00; // Fragment Offset (low)
    packet[8] = 0x40; // TTL
    packet[9] = 0x06; // Protocol (TCP)
    
    // TCP header (simplified)
    packet[20] = 0x00; // Source Port (high)
    packet[21] = 0x50; // Source Port (low) - 80
    packet[22] = 0x00; // Dest Port (high)
    packet[23] = 0x50; // Dest Port (low) - 80
    
    packet
}

fn create_suspicious_packet() -> Vec<u8> {
    // Create a suspicious packet with unusual patterns
    let mut packet = create_normal_packet();
    
    // Add suspicious payload
    for i in 40..60 {
        packet[i] = 0xFF; // Unusual pattern
    }
    
    packet
}

fn create_malicious_packet() -> Vec<u8> {
    // Create a packet with malware signature
    let mut packet = create_normal_packet();
    
    // Add malware signature (simplified)
    let signature = b"MALWARE";
    for (i, &byte) in signature.iter().enumerate() {
        if 40 + i < packet.len() {
            packet[40 + i] = byte;
        }
    }
    
    packet
}

fn create_packet_from_ip(src_ip: u32) -> Vec<u8> {
    let mut packet = create_normal_packet();
    
    // Set source IP
    packet[12] = (src_ip >> 24) as u8;
    packet[13] = (src_ip >> 16) as u8;
    packet[14] = (src_ip >> 8) as u8;
    packet[15] = src_ip as u8;
    
    packet
}