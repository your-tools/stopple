use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let disclaimer =
        "Disclaimer: this product uses the NVD API but is not endorsed or certified by the NVD.";
    println!("{disclaimer}");
    stopple::cli::run().await
}
