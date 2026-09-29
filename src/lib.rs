pub mod analyzers;
pub mod verdict;

pub fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}
