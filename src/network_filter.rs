//! Network Paket Filtreleme - User Space Implementation
//! 
//! Gerçek zamanlı paket analizi ve engelleme

use std::collections::HashMap;
use std::net::Ipv4Addr;

pub struct NetworkFilter {
    filter_rules: Vec<FilterRule>,
    blocked_ips: HashMap<u32, String>, // IP -> reason
    allowed_protocols: Vec<u8>,
    is_active: bool,
}

#[derive(Clone, Debug)]
pub struct FilterRule {
    pub rule_id: u32,
    pub rule_type: RuleType,
    pub pattern: Vec<u8>,
    pub action: FilterAction,
    pub priority: u8,
}

#[derive(Clone, Debug)]
pub enum RuleType {
    IPWhitelist,
    IPBlacklist,
    ProtocolFilter,
    PortFilter,
    ContentFilter,
    SignatureFilter,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FilterAction {
    Allow,
    Block,
    Log,
    Quarantine,
}

#[derive(Debug)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub size: usize,
    pub payload: Vec<u8>,
}

impl NetworkFilter {
    pub fn new() -> Self {
        Self {
            filter_rules: Vec::new(),
            blocked_ips: HashMap::new(),
            allowed_protocols: vec![6, 17], // TCP, UDP
            is_active: false,
        }
    }

    pub fn activate(&mut self) {
        self.is_active = true;
        println!("🌐 Network filter activated");
    }

    pub fn deactivate(&mut self) {
        self.is_active = false;
        println!("🌐 Network filter deactivated");
    }

    pub fn process_packet(&mut self, packet_data: &[u8]) -> FilterAction {
        if !self.is_active {
            return FilterAction::Allow;
        }

        let packet_info = self.parse_packet(packet_data);
        
        // Apply filter rules in priority order
        for rule in &self.filter_rules {
            if self.matches_rule(&packet_info, rule) {
                return rule.action.clone();
            }
        }

        // Default checks
        if self.is_ip_blocked(packet_info.src_ip) {
            return FilterAction::Block;
        }

        if !self.is_protocol_allowed(packet_info.protocol) {
            return FilterAction::Block;
        }

        FilterAction::Allow
    }

    fn parse_packet(&self, packet_data: &[u8]) -> PacketInfo {
        // Simplified packet parsing
        PacketInfo {
            src_ip: self.extract_ip(packet_data, 12),
            dst_ip: self.extract_ip(packet_data, 16),
            src_port: self.extract_port(packet_data, 20),
            dst_port: self.extract_port(packet_data, 22),
            protocol: packet_data.get(9).copied().unwrap_or(0),
            size: packet_data.len(),
            payload: packet_data.get(24..).unwrap_or(&[]).to_vec(),
        }
    }

    fn matches_rule(&self, packet: &PacketInfo, rule: &FilterRule) -> bool {
        match rule.rule_type {
            RuleType::IPBlacklist => {
                rule.pattern.len() >= 4 && 
                packet.src_ip == u32::from_be_bytes([
                    rule.pattern[0], 
                    rule.pattern[1], 
                    rule.pattern[2], 
                    rule.pattern[3]
                ])
            },
            RuleType::IPWhitelist => {
                rule.pattern.len() >= 4 && 
                packet.dst_ip == u32::from_be_bytes([
                    rule.pattern[0], 
                    rule.pattern[1], 
                    rule.pattern[2], 
                    rule.pattern[3]
                ])
            },
            RuleType::ProtocolFilter => {
                rule.pattern.len() >= 1 && 
                packet.protocol == rule.pattern[0]
            },
            RuleType::PortFilter => {
                rule.pattern.len() >= 2 && 
                packet.dst_port == u16::from_be_bytes([
                    rule.pattern[0], 
                    rule.pattern[1]
                ])
            },
            RuleType::ContentFilter => {
                self.check_content_match(&packet.payload, &rule.pattern)
            },
            RuleType::SignatureFilter => {
                self.check_signature_match(&packet.payload, &rule.pattern)
            },
        }
    }

    fn check_content_match(&self, payload: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() > payload.len() {
            return false;
        }

        for i in 0..=payload.len() - pattern.len() {
            if payload[i..i + pattern.len()] == pattern[..] {
                return true;
            }
        }

        false
    }

    fn check_signature_match(&self, _payload: &[u8], _signature: &[u8]) -> bool {
        // Advanced signature matching
        false
    }

    fn extract_ip(&self, data: &[u8], offset: usize) -> u32 {
        if data.len() >= offset + 4 {
            u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        } else {
            0
        }
    }

    fn extract_port(&self, data: &[u8], offset: usize) -> u16 {
        if data.len() >= offset + 2 {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        } else {
            0
        }
    }

    fn is_ip_blocked(&self, ip: u32) -> bool {
        self.blocked_ips.contains_key(&ip)
    }

    fn is_protocol_allowed(&self, protocol: u8) -> bool {
        self.allowed_protocols.contains(&protocol)
    }

    pub fn add_rule(&mut self, rule: FilterRule) {
        self.filter_rules.push(rule);
        self.filter_rules.sort_by_key(|r| r.priority);
    }

    pub fn block_ip(&mut self, ip: u32) {
        if !self.blocked_ips.contains_key(&ip) {
            let ip_str = Ipv4Addr::from(ip).to_string();
            self.blocked_ips.insert(ip, "Manual block".to_string());
            println!("🚫 Blocked IP: {}", ip_str);
        }
    }

    pub fn block_ip_with_reason(&mut self, ip: u32, reason: &str) {
        let ip_str = Ipv4Addr::from(ip).to_string();
        self.blocked_ips.insert(ip, reason.to_string());
        println!("🚫 Blocked IP: {} (Reason: {})", ip_str, reason);
    }

    pub fn unblock_ip(&mut self, ip: u32) {
        if self.blocked_ips.remove(&ip).is_some() {
            let ip_str = Ipv4Addr::from(ip).to_string();
            println!("✅ Unblocked IP: {}", ip_str);
        }
    }

    pub fn get_blocked_ips(&self) -> Vec<u32> {
        self.blocked_ips.keys().cloned().collect()
    }

    pub fn get_blocked_ip_reason(&self, ip: u32) -> Option<&str> {
        self.blocked_ips.get(&ip).map(|s| s.as_str())
    }

    pub fn get_rules(&self) -> &[FilterRule] {
        &self.filter_rules
    }

    pub fn get_filter_stats(&self) -> FilterStats {
        FilterStats {
            is_active: self.is_active,
            blocked_ips_count: self.blocked_ips.len(),
            active_rules_count: self.filter_rules.len(),
            allowed_protocols_count: self.allowed_protocols.len(),
        }
    }
}

#[derive(Debug)]
pub struct FilterStats {
    pub is_active: bool,
    pub blocked_ips_count: usize,
    pub active_rules_count: usize,
    pub allowed_protocols_count: usize,
}