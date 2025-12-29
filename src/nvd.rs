mod client;
pub(crate) mod response;

pub(crate) use client::NvdClient;

#[cfg(test)]
mod tests;
