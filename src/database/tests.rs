use super::*;

async fn get_test_database() -> Database {
    let database = Database::open("sqlite::memory:").await.unwrap();
    database.migrate().await.unwrap();
    database
}

fn make_cve(id: &str) -> Cve {
    Cve {
        id: id.to_owned(),
        raw_json: "{}".to_owned(),
    }
}

#[tokio::test]
async fn test_save_and_count() {
    let database = get_test_database().await;

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

#[tokio::test]
async fn test_search_no_cache_then_with_a_cache() {
    let database = get_test_database().await;

    let cve = include_str!("../tests/cve.json");

    database.save_cve("CVE-2025-27556", cve).await.unwrap();

    let in_cache = database.in_cache("django").await.unwrap();
    assert!(!in_cache);

    let matches = database.search("django").await.unwrap();

    assert_eq!(matches.len(), 1);

    let in_cache = database.in_cache("django").await.unwrap();
    assert!(in_cache);

    let matches = database.search("django").await.unwrap();
    assert_eq!(matches.len(), 1);
}

#[tokio::test]
async fn test_clear_cache_when_inserting_cves() {
    let database = get_test_database().await;

    let cve = include_str!("../tests/cve.json");

    database.save_cve("CVE-2025-27556", cve).await.unwrap();
    database.search("django").await.unwrap();

    let in_cache = database.in_cache("django").await.unwrap();
    assert!(in_cache);

    let cve_123 = make_cve("CVE-123");
    let cve_456 = make_cve("CVE-456");

    database.save_cves(&[cve_123, cve_456]).await.unwrap();

    let in_cache = database.in_cache("django").await.unwrap();
    assert!(!in_cache);
}
