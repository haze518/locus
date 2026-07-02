pub(crate) fn start_replication(slot_name: &str) -> String {
    let result = format!("START_REPLICATION SLOT {} LOGICAL 0/0", slot_name);
    result
}
