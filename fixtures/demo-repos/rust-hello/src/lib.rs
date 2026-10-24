//! UnboxAnyRepo demo fixture.

/// Returns the n-th Fibonacci number.
pub fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let t = a + b;
        a = b;
        b = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::fib;

    #[test]
    fn small_values() {
        assert_eq!(fib(0), 0);
        assert_eq!(fib(1), 1);
        assert_eq!(fib(10), 55);
    }
}
