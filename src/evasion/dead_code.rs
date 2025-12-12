// loader/src/evasion/dead_code.rs

use rand::Rng;

    

/// Injects random dead code for control flow obfuscation and anti-static analysis.
///
/// The purpose of this module is to introduce junk operations that inflate
/// the binary, mislead disassemblers, and confuse heuristics.
/// This function randomly selects one of several dead code patterns and executes it.
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
    

/// Useless arithmetic that looks like meaningful computation.
///
/// Performs multiplications, XORs, and bit rotations in a loop.
/// Designed to inflate instruction count and register usage,
/// without actually impacting program behavior.
fn dead_calculations() {
        let mut x: u64 = 0xDEADBEEF;
        for i in 0..1000 {
            x = x.wrapping_mul(i);
            x ^= 0xCAFEBABE;
            x = x.rotate_left(13);
        }
        let _ = x;
    }
    

/// Fake string parsing and hashing operations.
///
/// Simulates work that looks like path parsing, buffer manipulation,
/// and hashing—patterns that often appear in legitimate software logic.
fn fake_string_operations() {
        let fake_path = "C:\\Windows\\System32\\kernel32.dll";
        let _ = fake_path.len();
        
        let mut buffer = [0u8; 256];
        for (i, byte) in fake_path.bytes().enumerate() {
            buffer[i % 256] = byte;
        }
        
        let mut fake_hash: u32 = 0x811C9DC5;
        for &byte in &buffer {
            fake_hash ^= byte as u32;
            fake_hash = fake_hash.wrapping_mul(0x01000193);
        }
    }
    

/// Nested loops that simulate CPU-bound processing.
///
/// Executes meaningless nested loops to generate instruction noise
/// and distort execution profiling or timing-based detection.
fn loop_noise() {
        for _ in 0..50 {
            let mut x = 0u64;
            for j in 0..100 {
                x = x.wrapping_add(j as u64);
            }
        }
    }
    

/// Constructs branches that are statistically never taken.
///
/// These code paths appear in control flow graphs but are
/// effectively unreachable during normal execution. Their purpose is
/// to confuse static analyzers, fuzzers, or symbolic execution engines.
fn branch_noise() {
        let r: u32 = rand::random();
        if r < 100 {
            panic!("Should never happen");
        } else if r > u32::MAX - 100 {
            unimplemented!();
        } else {
        }
    }