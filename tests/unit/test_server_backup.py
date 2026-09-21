from securecode_ai.server.backup_repository import BackupRecord, BackupRepository


def test_backup_plan_is_metadata_only() -> None:
    record = BackupRecord("t", "b", ("a" * 64,), "eu", "key-ref", 1, "PLANNED")
    assert BackupRepository.in_memory().save(record, None).state == "PLANNED"
