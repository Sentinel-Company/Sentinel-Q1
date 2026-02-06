//! Sentinel-X Core Library
//! 
//! User space implementation for testing and development

pub mod voice_auth;
pub mod ai_detector;
pub mod network_filter;
pub mod security;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub struct SentinelCore {
    voice_engine: Arc<Mutex<voice_auth::VoiceBiometricEngine>>,
    ai_detector: Arc<Mutex<ai_detector::AIThreatDetector>>,
    network_filter: Arc<Mutex<network_filter::NetworkFilter>>,
    security_manager: Arc<Mutex<security::SecurityManager>>,
    is_initialized: bool,
}

impl SentinelCore {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            voice_engine: Arc::new(Mutex::new(voice_auth::VoiceBiometricEngine::new(44100))),
            ai_detector: Arc::new(Mutex::new(ai_detector::AIThreatDetector::new())),
            network_filter: Arc::new(Mutex::new(network_filter::NetworkFilter::new())),
            security_manager: Arc::new(Mutex::new(security::SecurityManager::new())),
            is_initialized: false,
        })
    }
    
    pub fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Initializing Sentinel-X Core...");
        
        // Initialize security manager
        {
            let mut security = self.security_manager.lock().unwrap();
            security.initialize_security()?;
        }
        
        // Voice engine and AI detector are already initialized in new()
        
        // Initialize network filter
        {
            let mut filter = self.network_filter.lock().unwrap();
            filter.activate();
        }
        
        self.is_initialized = true;
        println!("✅ Sentinel-X Core initialized successfully!");
        Ok(())
    }
    
    pub fn process_packet(&mut self, packet_data: &[u8]) -> network_filter::FilterAction {
        if !self.is_initialized {
            return network_filter::FilterAction::Allow;
        }
        
        // Process through AI detector
        let threat_assessment = {
            let mut ai = self.ai_detector.lock().unwrap();
            ai.analyze_packet(packet_data)
        };
        
        // If threat detected, block
        if threat_assessment.threat_level > 0.75 {
            println!("🚨 Threat detected: {:?}, confidence: {:.2}%", 
                threat_assessment.threat_type, 
                threat_assessment.confidence * 100.0
            );
            return network_filter::FilterAction::Block;
        }
        
        // Process through network filter
        {
            let mut filter = self.network_filter.lock().unwrap();
            filter.process_packet(packet_data)
        }
    }
    
    pub fn verify_voice(&mut self, user_id: u32, voice_data: &[u8]) -> Result<f32, Box<dyn std::error::Error>> {
        if !self.is_initialized {
            return Err("Sentinel-X not initialized".into());
        }
        
        // Check if system is locked
        {
            let security = self.security_manager.lock().unwrap();
            if security.is_system_locked() {
                return Err("System is locked".into());
            }
        }
        
        // Verify voice biometric
        let matched_user_id = {
            let mut voice = self.voice_engine.lock().unwrap();
            voice.process_audio_chunk(voice_data)
        };
        
        match matched_user_id {
            Some(id) => {
                if id == user_id {
                    Ok(0.95) // High confidence
} else {
                    return Err("Voice verification failed".into());
                }
            },
            None => Err("Voice profile not found".into()),
        }
    }
    
    pub fn register_voice(&mut self, user_id: u32, voice_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_initialized {
            return Err("Sentinel-X not initialized".into());
        }
        
        // Extract features from voice_data
        let features = {
            let voice = self.voice_engine.lock().unwrap();
            voice.extract_features(voice_data)
        };
        
        // Register voiceprint
        {
            let mut voice = self.voice_engine.lock().unwrap();
            voice.register_voiceprint(user_id, features);
        }
        
        println!("✅ Voice profile registered for user ID: {}", user_id);
        Ok(())
    }
    
    pub fn block_ip(&mut self, ip: u32) {
        {
            let mut filter = self.network_filter.lock().unwrap();
            filter.block_ip(ip);
        }
        println!("🚫 IP address blocked: {:08x}", ip);
    }
    
    pub fn unblock_ip(&mut self, ip: u32) {
        {
            let mut filter = self.network_filter.lock().unwrap();
            filter.unblock_ip(ip);
        }
        println!("✅ IP address unblocked: {:08x}", ip);
    }
    
    pub fn set_security_level(&mut self, level: u8) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_initialized {
            return Err("Sentinel-X not initialized".into());
        }
        
        if level < 1 || level > 4 {
            return Err("Invalid security level".into());
        }
        
        {
            let mut security = self.security_manager.lock().unwrap();
            security.set_security_level(level as u64);
        }
        
        println!("🛡️ Security level set to: {}", level);
        Ok(())
    }
    
    pub fn lock_system(&mut self) {
        {
            let mut security = self.security_manager.lock().unwrap();
            security.lock_system();
        }
        println!("🔒 System locked by Sentinel-X");
    }
    
    pub fn unlock_system(&mut self, user_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        {
            let mut security = self.security_manager.lock().unwrap();
            security.unlock_system(user_id)?;
        }
        println!("🔓 System unlocked by user ID: {}", user_id);
        Ok(())
    }
    
    pub fn get_status(&self) -> Status {
        let security = self.security_manager.lock().unwrap();
        let filter = self.network_filter.lock().unwrap();
        
        Status {
            is_active: self.is_initialized,
            security_level: security.get_security_level() as u8,
            is_locked: security.is_system_locked(),
            kernel_loaded: true,
            voice_profiles_count: 0, // TODO: Get actual count
            blocked_ips_count: filter.get_blocked_ips().len() as u32,
            active_rules_count: filter.get_rules().len() as u32,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            packets_per_second: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Status {
    pub is_active: bool,
    pub security_level: u8,
    pub is_locked: bool,
    pub kernel_loaded: bool,
    pub voice_profiles_count: u32,
    pub blocked_ips_count: u32,
    pub active_rules_count: u32,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub packets_per_second: u32,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            is_active: false,
            security_level: 1,
            is_locked: false,
            kernel_loaded: false,
            voice_profiles_count: 0,
            blocked_ips_count: 0,
            active_rules_count: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            packets_per_second: 0,
        }
    }
}