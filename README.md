## VM-based obfuscation for eBPF

This project was developed as part of a **AAU Master’s Project**. 

---

### Project Goals

- Investigate the use of virtualization-based obfuscation for eBPF programs.
- Serve as a research and educational prototype.

---

### System Requirements

Tested primarily on **Linux (Arch)**. Other modern Linux distributions with recent kernels should also work.

| Component | Requirement |
|----------|-------------|
| **Compiler** | Clang ≥ 21.1.6 |
| **Build Tools** | CMake ≥ 3.25.1 |
| | GNU Make ≥ 4.4.1 |
| **BPF Tools** | bpftool ≥ 7.7.0 |
| **Libraries** | libbpf ≥ 1.7 |
| | pkg-config ≥ 2.5.1 |
| **Kernel** | Linux kernel with eBPF support (recommended: 5.x+) |

> **Note:**  
> - A C23 / C++23-capable toolchain is required  
> - Root privileges are required to load and attach eBPF programs

