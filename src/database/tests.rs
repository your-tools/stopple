use super::*;

#[tokio::test]
async fn test_read() {
    let database = Database::open("sqlite::memory:").await.unwrap();
    database.migrate().await.unwrap();

    database
        .save_cve("CVE-123", r#"{id: "CVE-123"}"#)
        .await
        .unwrap();

    database
        .save_cve("CVE-456", r#"{id: "CVE-456"}"#)
        .await
        .unwrap();

    database
        .save_cve("CVE-123", r#"{id: "CVE-123", "criteria": "hello"}"#)
        .await
        .unwrap();

    let count = database.cve_count().await.unwrap();

    assert_eq!(count, 2);
}
