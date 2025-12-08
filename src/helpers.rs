//! Helpers for retrying I/O operations on `Interrupted`.

/// Retries an async I/O expression, looping on `io::ErrorKind::Interrupted`.
///
/// The expression should evaluate to `io::Result<usize>` and already include `.await`
/// for async operations.
macro_rules! retry_on_interrupted {
    ($expr:expr) => {{
        loop {
            match $expr {
                Ok(written) => break Ok(written),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    // Yield to avoid spinning when syscalls are repeatedly interrupted.
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(err) => break Err(err),
            }
        }
    }};
}

pub(crate) use retry_on_interrupted;

#[cfg(test)]
mod tests {
    use super::retry_on_interrupted;
    use std::io;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn retries_on_interrupted_errors() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        let result = retry_on_interrupted!({
            let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected interruption",
                ))
            } else {
                Ok(5)
            }
        })
        .expect("retry should eventually succeed");

        assert_eq!(result, 5);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
