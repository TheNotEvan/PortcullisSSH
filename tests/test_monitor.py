import itertools
import json
import os

from ssh_bfd.monitor import LogMonitor


def write(path, text, mode="w"):
    # newline="" stops Windows from turning \n into \r\n, so tests behave the
    # same on Windows and Linux.
    with open(path, mode, newline="") as f:
        f.write(text)


# --- basic offset tracking ---

def test_reads_existing_lines_from_start(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "one\ntwo\n")
    m = LogMonitor(str(log), start_at_end=False)
    assert m.read_new_lines() == ["one\n", "two\n"]
    m.close()


def test_second_read_returns_nothing(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "one\n")
    m = LogMonitor(str(log), start_at_end=False)
    m.read_new_lines()
    assert m.read_new_lines() == []
    m.close()


def test_reads_only_appended_lines(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "one\n")
    m = LogMonitor(str(log), start_at_end=False)
    m.read_new_lines()
    write(log, "two\n", mode="a")
    assert m.read_new_lines() == ["two\n"]
    m.close()


def test_start_at_end_skips_history(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "ancient history\n")
    m = LogMonitor(str(log))  # start_at_end defaults to True
    assert m.read_new_lines() == []
    write(log, "new event\n", mode="a")
    assert m.read_new_lines() == ["new event\n"]
    m.close()


def test_missing_log_file_returns_empty(tmp_path):
    m = LogMonitor(str(tmp_path / "does_not_exist.log"))
    assert m.read_new_lines() == []
    m.close()


# --- partial lines ---

def test_partial_line_left_for_next_poll(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "complete\nincomp")  # last line has no newline yet
    m = LogMonitor(str(log), start_at_end=False)
    assert m.read_new_lines() == ["complete\n"]
    write(log, "lete\n", mode="a")  # writer finishes the line
    assert m.read_new_lines() == ["incomplete\n"]
    m.close()


# --- state persistence ---

def test_restart_resumes_from_state(tmp_path):
    log = tmp_path / "auth.log"
    state = tmp_path / "state.json"
    write(log, "one\ntwo\n")

    m = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    m.read_new_lines()
    m.close()

    write(log, "three\n", mode="a")
    m2 = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    assert m2.read_new_lines() == ["three\n"]  # not one/two again
    m2.close()


def test_corrupt_state_file_is_ignored(tmp_path):
    log = tmp_path / "auth.log"
    state = tmp_path / "state.json"
    write(log, "one\n")
    write(state, "{ this is not valid json")

    m = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    assert m.read_new_lines() == ["one\n"]  # fresh start, no crash
    m.close()


def test_state_for_different_log_is_ignored(tmp_path):
    log = tmp_path / "auth.log"
    state = tmp_path / "state.json"
    write(log, "one\n")
    # State recorded for some other file, with a huge offset.
    write(state, json.dumps({"log_path": "/somewhere/else.log", "offset": 99999, "inode": 1}))

    m = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    assert m.read_new_lines() == ["one\n"]  # stale offset must not be trusted
    m.close()


def test_state_file_written_atomically(tmp_path):
    log = tmp_path / "auth.log"
    state = tmp_path / "state.json"
    write(log, "one\n")

    m = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    m.read_new_lines()
    m.close()

    assert state.exists()
    assert not (tmp_path / "state.json.tmp").exists()  # temp file cleaned up
    saved = json.loads(state.read_text())
    assert saved["offset"] == os.path.getsize(log)
    assert saved["log_path"] == str(log)
    assert "inode" in saved


# --- rotation ---

def test_truncation_detected(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "one\ntwo\n")
    m = LogMonitor(str(log), start_at_end=False)
    m.read_new_lines()

    write(log, "fresh\n")  # mode "w" truncates: copytruncate rotation
    assert m.read_new_lines() == ["fresh\n"]
    m.close()


def test_restart_across_rotation(tmp_path):
    log = tmp_path / "auth.log"
    state = tmp_path / "state.json"
    write(log, "old file line\n")

    m = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    m.read_new_lines()
    m.close()

    # Rotate while the monitor is down: archive the old file, create a new one.
    os.rename(log, tmp_path / "auth.log.1")
    write(log, "new file line\n")

    m2 = LogMonitor(str(log), state_path=str(state), start_at_end=False)
    # The saved offset belongs to the archived file; the new file must be read
    # from the top, not from a stale byte position.
    assert m2.read_new_lines() == ["new file line\n"]
    m2.close()


def test_rename_rotation_while_running(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "old line\n")
    m = LogMonitor(str(log), start_at_end=False)
    assert m.read_new_lines() == ["old line\n"]

    # Windows cannot rename a file with an open handle, so simulate the
    # rename-rotation sequence with the handle released, as a restart would.
    m.close()
    os.rename(log, tmp_path / "auth.log.1")
    write(log, "new line\n")

    assert m.read_new_lines() == ["new line\n"]
    m.close()


# --- follow() generator ---

def test_follow_yields_lines_without_sleeping(tmp_path):
    log = tmp_path / "auth.log"
    write(log, "one\ntwo\nthree\n")
    m = LogMonitor(str(log), start_at_end=False)
    # islice takes exactly 3 items from the infinite generator, then stops --
    # no lines pending afterward, so no sleep is ever reached.
    got = list(itertools.islice(m.follow(), 3))
    assert got == ["one\n", "two\n", "three\n"]
    m.close()
