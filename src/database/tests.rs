use crate::vulnerabilities::Severity;

use super::*;

pub(crate) fn make_cve(
    id: &str,
    severity: Severity,
    package_id: &str,
    start: &str,
    end: &str,
) -> Cve {
    let mut json_template = include_str!("../tests/cve_template.json").to_owned();
    let severity = severity.to_string();

    for (key, value) in [
        ("severity", severity),
        ("package_id", package_id.to_owned()),
        ("start", start.to_owned()),
        ("end", end.to_owned()),
    ] {
        json_template = json_template
            .replace(&format!("@{key}@"), &value)
            .to_owned();
    }
    Cve {
        id: id.to_owned(),
        raw_json: json_template,
    }
}

async fn get_test_database() -> Database {
    let database = Database::open("sqlite::memory:").await.unwrap();
    database.migrate().await.unwrap();
    database
}

#[tokio::test]
async fn test_saving_cves() {
    let database = get_test_database().await;

    let django_cve_123 = make_cve(
        "CVE-2025-123",
        Severity::High,
        "djangoproject:django",
        "5.0",
        "5.3",
    );

    let django_cve_456 = make_cve(
        "CVE-2025-456",
        Severity::Medium,
        "djangoproject:django",
        "5.2",
        "5.4",
    );

    let reqwest_cve = make_cve("CVE-2025-890", Severity::Low, "rust:reqwest", "0.1", "0.2");

    let cves = [django_cve_123, django_cve_456, reqwest_cve];

    database.save_cves(&cves).await.unwrap();

    let found = database.search("django").await.unwrap();
    assert_eq!(found.len(), 2);

    let found = database.search("reqwest").await.unwrap();

    assert_eq!(found.len(), 1);
    let actual_ranges: Vec<_> = found[0]
        .ranges
        .iter()
        .map(|r| (r.start.to_string(), r.end.to_string()))
        .collect();
    assert_eq!(&actual_ranges, &[("0.1".to_owned(), "0.2".to_owned())]);
}
