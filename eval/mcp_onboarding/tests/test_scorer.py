from mcp_onboarding.scorer import (
    turns_to_success,
    wrong_tool_count,
    used_overview_first,
    used_dry_run_before_destructive,
    score_task,
    aggregate,
    TaskScore,
)


def _trace():
    return [
        {"tool": "get_schema_overview", "input": {}, "is_error": False},
        {"tool": "create_collection", "input": {"name": "posts"}, "is_error": False},
        {"tool": "insert_record", "input": {"collection": "posts"}, "is_error": True},
        {"tool": "insert_record", "input": {"collection": "posts"}, "is_error": False},
    ]


def test_turns_to_success_counts_tool_calls():
    assert turns_to_success(_trace()) == 4


def test_wrong_tool_count_counts_errors():
    assert wrong_tool_count(_trace()) == 1


def test_used_overview_first_true_when_first_tool_is_overview():
    assert used_overview_first(_trace()) is True


def test_used_overview_first_false_when_not_first():
    t = [{"tool": "list_collections", "input": {}, "is_error": False}] + _trace()
    assert used_overview_first(t) is False


def test_used_overview_first_false_on_empty_trace():
    assert used_overview_first([]) is False


def test_used_dry_run_detects_dry_run_before_real_delete():
    t = [
        {"tool": "delete_record", "input": {"collection": "posts", "id": 1, "dry_run": True}, "is_error": False},
        {"tool": "delete_record", "input": {"collection": "posts", "id": 1}, "is_error": False},
    ]
    assert used_dry_run_before_destructive(t) is True


def test_used_dry_run_false_when_destructive_has_no_dry_run():
    t = [{"tool": "delete_record", "input": {"collection": "posts", "id": 1}, "is_error": False}]
    assert used_dry_run_before_destructive(t) is False


def test_used_dry_run_false_when_no_destructive_tool():
    assert used_dry_run_before_destructive(_trace()) is False


def test_score_task_packs_all_metrics():
    s = score_task("T1", success=True, trace=_trace())
    assert isinstance(s, TaskScore)
    assert s.task_id == "T1"
    assert s.success is True
    assert s.turns == 4
    assert s.wrong_tool == 1
    assert s.used_overview_first is True
    assert s.used_dry_run is False


def test_aggregate_sums_and_counts():
    a = score_task("T1", success=True, trace=_trace())
    b = score_task("T2", success=False, trace=[{"tool": "query", "input": {}, "is_error": True}])
    run = aggregate("before", [a, b])
    assert run.label == "before"
    assert run.tasks_passed == 1
    assert run.total_turns == 5
    assert run.total_wrong_tool == 2
