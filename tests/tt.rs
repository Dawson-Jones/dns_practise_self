#[test]
fn end_with() {
    let qname = "www.google.com";
    let end = "com";

    assert!(qname.ends_with(end));
}