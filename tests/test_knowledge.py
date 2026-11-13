from secpipeline.knowledge import answer_question


def test_ask_shift_left():
    result = answer_question("что такое shift left security")
    assert result["sources"]
    assert "Shift" in result["answer"] or "shift" in result["answer"].lower()
