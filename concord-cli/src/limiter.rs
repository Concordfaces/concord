//! Adaptive concurrency limiter for over-the-wire chunk fetches.
//!
//! The operator's reconstruct path contends under load: cold throughput peaks
//! near ~2 concurrent fetches and collapses past ~4. But edge-warm (CDN-cached)
//! chunks are link-bound and tolerate far more. A fixed cap can't be fast in
//! both regimes, so this controller adapts:
//!
//! - **Additive increase:** after a streak of healthy (low-latency) fetches,
//!   raise the in-flight target by 1 — probing for more throughput.
//! - **Multiplicative decrease:** a transient error (post-retry) or a latency
//!   spike (per-MiB time well above the best seen) halves the target — backing
//!   off from contention fast.
//!
//! Concurrency is enforced by a `Semaphore` sized to `max`, with the unused
//! permits "parked" (held) so the effective limit is `max - parked`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const EWMA_ALPHA: f64 = 0.3; // weight of the newest sample
const DEGRADE_RATIO: f64 = 2.0; // ewma > best*this → contention, back off
const HEALTHY_RATIO: f64 = 1.5; // ewma <= best*this → healthy, count toward growth
const GROW_STREAK: u32 = 3; // healthy fetches in a row before +1

/// Pure AIMD decision. Returns `(new_target, new_good_streak)`.
fn decide(
    target: usize,
    min: usize,
    max: usize,
    ewma: f64,
    best: f64,
    good: u32,
    transient_err: bool,
) -> (usize, u32) {
    if transient_err {
        // Multiplicative decrease; reset the growth streak.
        return ((target / 2).max(min).max(1), 0);
    }
    if best.is_finite() && ewma > best * DEGRADE_RATIO && target > min {
        // Per-MiB latency inflated well past best → contention. Step down.
        return (target - 1, 0);
    }
    if !best.is_finite() || ewma <= best * HEALTHY_RATIO {
        let g = good + 1;
        if g >= GROW_STREAK && target < max {
            return (target + 1, 0); // additive increase
        }
        return (target, g);
    }
    (target, 0)
}

#[derive(Debug)]
struct State {
    target: usize,
    parked: Vec<OwnedSemaphorePermit>,
    ewma: f64,
    best: f64,
    good: u32,
}

/// Adaptive in-flight limiter shared across all shard/chunk fetch tasks.
#[derive(Debug)]
pub struct Limiter {
    sem: Arc<Semaphore>,
    min: usize,
    max: usize,
    limit: AtomicUsize, // observable current target (for logging/tests)
    state: Mutex<State>,
}

impl Limiter {
    /// Build a limiter starting at `start` in-flight, ranging `[min, max]`.
    pub fn new(start: usize, min: usize, max: usize) -> Self {
        let max = max.max(1);
        let min = min.clamp(1, max);
        let start = start.clamp(min, max);
        let sem = Arc::new(Semaphore::new(max));
        // Park (max - start) permits so the effective limit starts at `start`.
        let mut parked = Vec::new();
        for _ in 0..(max - start) {
            if let Ok(p) = sem.clone().try_acquire_owned() {
                parked.push(p);
            }
        }
        let target = max - parked.len();
        Self {
            sem,
            min,
            max,
            limit: AtomicUsize::new(target),
            state: Mutex::new(State {
                target,
                parked,
                ewma: 0.0,
                best: f64::INFINITY,
                good: 0,
            }),
        }
    }

    /// Acquire one in-flight slot (awaits if at the current target).
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("limiter semaphore closed")
    }

    /// Current effective in-flight target.
    pub fn current(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    /// Feed back one fetch's outcome and adjust the target concurrency.
    pub async fn record(&self, bytes: usize, dur: Duration, transient_err: bool) {
        let mut st = self.state.lock().await;
        if !transient_err && bytes > 0 {
            let mib = bytes as f64 / (1024.0 * 1024.0);
            let sample = dur.as_micros() as f64 / mib; // µs per MiB
            st.ewma = if st.ewma == 0.0 {
                sample
            } else {
                EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * st.ewma
            };
            if st.ewma < st.best {
                st.best = st.ewma;
            }
        }
        let (nt, good) = decide(
            st.target,
            self.min,
            self.max,
            st.ewma,
            st.best,
            st.good,
            transient_err,
        );
        st.good = good;
        self.apply(&mut st, nt);
    }

    fn apply(&self, st: &mut State, new_target: usize) {
        let nt = new_target.clamp(self.min, self.max);
        // Grow: hand parked permits back to the pool.
        while st.target < nt {
            if st.parked.pop().is_some() {
                st.target += 1;
            } else {
                break;
            }
        }
        // Shrink: park free permits (best-effort; if all in use, we park on a
        // later record as fetches complete).
        while st.target > nt {
            match self.sem.clone().try_acquire_owned() {
                Ok(p) => {
                    st.parked.push(p);
                    st.target -= 1;
                }
                Err(_) => break,
            }
        }
        self.limit.store(st.target, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_error_halves_and_resets_streak() {
        // target 8, error → 4, streak reset.
        assert_eq!(decide(8, 1, 16, 100.0, 100.0, 2, true), (4, 0));
        // never below min.
        assert_eq!(decide(1, 1, 16, 100.0, 100.0, 0, true), (1, 0));
        assert_eq!(decide(3, 2, 16, 100.0, 100.0, 0, true), (2, 0));
    }

    #[test]
    fn latency_spike_steps_down() {
        // ewma (300) > best(100)*2 → step down by 1.
        assert_eq!(decide(5, 1, 16, 300.0, 100.0, 2, false), (4, 0));
        // at min: can't step down, and not healthy (300 > 100*1.5) → hold, no streak.
        assert_eq!(decide(1, 1, 16, 300.0, 100.0, 2, false), (1, 0));
    }

    #[test]
    fn healthy_streak_grows() {
        // healthy (ewma<=best*1.5), streak just below threshold → count up, hold.
        assert_eq!(decide(2, 1, 16, 120.0, 100.0, 1, false), (2, 2));
        // streak reaches GROW_STREAK → +1, reset streak.
        assert_eq!(
            decide(2, 1, 16, 120.0, 100.0, GROW_STREAK - 1, false),
            (3, 0)
        );
        // at max, hold even when the streak would otherwise grow (no effect).
        assert_eq!(
            decide(16, 1, 16, 120.0, 100.0, GROW_STREAK - 1, false),
            (16, GROW_STREAK)
        );
    }

    #[test]
    fn first_sample_no_best_counts_healthy() {
        // best = +inf (no sample yet) → treated as healthy, streak grows.
        assert_eq!(decide(2, 1, 16, 0.0, f64::INFINITY, 0, false), (2, 1));
    }

    #[tokio::test]
    async fn limiter_starts_at_start_and_adapts() {
        let lim = Limiter::new(2, 1, 8);
        assert_eq!(lim.current(), 2);
        // A few healthy fast fetches → grows.
        for _ in 0..(GROW_STREAK + 1) {
            lim.record(4 * 1024 * 1024, Duration::from_millis(50), false)
                .await;
        }
        assert!(lim.current() > 2, "should grow under healthy load");
        // A transient error → backs off.
        let before = lim.current();
        lim.record(0, Duration::from_millis(1), true).await;
        assert!(lim.current() < before, "should back off on error");
    }

    #[tokio::test]
    async fn limiter_enforces_target_permits() {
        let lim = Limiter::new(2, 1, 8);
        let _p1 = lim.acquire().await;
        let _p2 = lim.acquire().await;
        // Third acquire would block at target=2; confirm it's not immediately ready.
        let third = tokio::time::timeout(Duration::from_millis(50), lim.acquire()).await;
        assert!(third.is_err(), "acquire beyond target must wait");
    }
}
