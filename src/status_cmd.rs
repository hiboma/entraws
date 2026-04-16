//! Implementation of the `entraws status` subcommand.
//!
//! Reads only the per-process cache under `~/.entraws/cache/` (never
//! the primary sink) so running `status` cannot trigger a keychain
//! prompt. The intended use is for operators to check "how long until I
//! need to `entraws login` again" without incurring biometric friction.

use chrono::Utc;

use crate::config::StatusArgs;
use crate::credential::cache::CacheStore;

pub fn run(args: StatusArgs) -> ! {
    let cache = CacheStore::new(CacheStore::default_root());
    let code = match cache.load(&args.cache_key) {
        Ok(Some(entry)) => {
            let remaining = entry.creds.expiration.signed_duration_since(Utc::now());
            let remaining_secs = remaining.num_seconds();
            if remaining_secs > 0 {
                let hours = remaining_secs / 3600;
                let mins = (remaining_secs % 3600) / 60;
                println!(
                    "cache-key: {}\nrole:      {}\nexpires:   {} ({}h{}m remaining)",
                    entry.cache_key,
                    entry.role_arn,
                    entry.creds.expiration.to_rfc3339(),
                    hours,
                    mins
                );
                0
            } else {
                println!(
                    "cache-key: {}\nrole:      {}\nexpires:   {} (EXPIRED)",
                    entry.cache_key,
                    entry.role_arn,
                    entry.creds.expiration.to_rfc3339()
                );
                1
            }
        }
        Ok(None) => {
            eprintln!(
                "entraws: no cached credentials for cache-key {}",
                args.cache_key
            );
            2
        }
        Err(e) => {
            eprintln!("entraws: cache read failed: {e}");
            3
        }
    };
    std::process::exit(code);
}
