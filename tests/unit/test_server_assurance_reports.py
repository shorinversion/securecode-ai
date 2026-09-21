from securecode_ai.server.assurance_reports import generate
from securecode_ai.server.revalidation import CurrentPins


def test_stale_report_is_incomplete_and_has_no_authority() -> None:
    recorded = CurrentPins("a", "b", "c", "d", "e")
    report = generate(
        tenant_id="t",
        repository_id="r",
        ledger_hashes=("a" * 64,),
        recorded=recorded,
        current=CurrentPins("x", "b", "c", "d", "e"),
    )
    assert (
        not report.complete and report.authority == "NONE" and report.stale_reasons == ("source",)
    )
