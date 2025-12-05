use super::*;

#[tokio::test]
async fn test_query_django_vulnerabilities() {
    let mut client = NvdClient::new();
    let found = client.find_vulnerabilities("django").await.unwrap();

    assert!(!found.is_empty())
}
