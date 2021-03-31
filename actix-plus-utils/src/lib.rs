use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current unix time in seconds. This is useful both for when working with external APIs or libraries that expect a UNIX time, and for cleanly keeping track of time in one's own code.
pub fn current_unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}