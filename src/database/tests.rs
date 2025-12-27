use super::*;

async fn get_test_database() -> Database {
    let database = Database::open("sqlite::memory:").await.unwrap();
    database.migrate().await.unwrap();
    database
}

#[tokio::test]
async fn test_saving_cves() {
    let database = get_test_database().await;

    let cve = include_str!("../tests/cve.json");

    database.save_cve("CVE-2025-27556", cve).await.unwrap();

    let found = database.search("django").await.unwrap();
    assert_eq!(found.len(), 1);
}
