use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    stopple::cli::run().await
}
