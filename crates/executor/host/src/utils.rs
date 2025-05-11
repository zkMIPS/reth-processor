use zkm_sdk::ZKMStdin;

/// Dump the program and stdin to files for debugging if `ZKM_DUMP` is set.
pub(crate) fn zkm_dump(elf: &[u8], stdin: &ZKMStdin, block: u64) {
    if std::env::var("ZKM_DUMP").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false) {
        std::fs::write(format!("{}-program.bin", block), elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write(format!("{}-stdin.bin", block), stdin.clone()).unwrap();
    }
}
