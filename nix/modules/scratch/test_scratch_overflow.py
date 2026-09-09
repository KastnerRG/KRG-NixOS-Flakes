"""Unit tests for scratch-overflow's candidate selection.

Scoped deliberately to the part that decides WHICH files get demoted. That decision
already went wrong once in the wild — the TTL sweep archived 68k files of a freshly
staged dataset because it judged idleness on a copied-in atime — and it is the one
piece of this tool whose bugs are silent: the copy machinery fails loudly and
fail-closed, but a wrong candidate list just quietly moves someone's live data to NFS.

Stdlib + pytest only, matching .github/workflows/tests.yml (no ZFS, no NFS, no root).
"""

import importlib.util
import os
import pathlib
import time

MODULE_PATH = pathlib.Path(__file__).with_name("scratch-overflow.py")
_spec = importlib.util.spec_from_file_location("scratch_overflow", MODULE_PATH)
so = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(so)

DAY = 86400.0


def write(path, data=b"x", atime=None, mtime=None):
    """Create a file, optionally back-dating its atime/mtime (never its ctime)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if atime is not None or mtime is not None:
        st = path.stat()
        os.utime(
            path,
            (
                atime if atime is not None else st.st_atime,
                mtime if mtime is not None else st.st_mtime,
            ),
        )
    return path


def paths(cands):
    return {c[2] for c in cands}


def gather(root, cutoff):
    return so.gather_candidates(str(root), cutoff, set(), set())


def test_last_use_ignores_a_stale_copied_in_atime(tmp_path):
    """The bug that started this: `cp -a` et al. carry the SOURCE machine's atime, so a
    file created here seconds ago can carry a years-old one. ctime can't be faked, so
    last_use must report ~now, not the copied-in atime."""
    old = time.time() - 600 * DAY
    f = write(tmp_path / "staged.bin", atime=old, mtime=old)
    st = f.stat()
    assert st.st_atime < time.time() - 500 * DAY  # the file really does look ancient
    assert so.last_use(st) > time.time() - DAY  # ...but it was created here just now


def test_freshly_staged_file_is_not_a_candidate(tmp_path):
    """End to end through the selector: an ancient-looking but newly-arrived file must
    not be offered up for demotion (68,341 of them were)."""
    old = time.time() - 600 * DAY
    write(tmp_path / "staged.bin", atime=old, mtime=old)
    assert gather(tmp_path, time.time() - 180 * DAY) == []


def test_genuinely_idle_file_is_still_a_candidate(tmp_path):
    """The guard must not defeat the sweep itself. A file whose ctime we can't backdate
    is simulated by comparing against a cutoff in the future: everything on this
    filesystem is then 'idle', which is what an actually-abandoned file looks like."""
    f = write(tmp_path / "abandoned.bin")
    assert paths(gather(tmp_path, time.time() + DAY)) == {str(f)}


def test_recent_write_beats_an_old_atime(tmp_path):
    """A file written but never read back has a live mtime and a stale atime. It is in
    use, so mtime must count too."""
    now = time.time()
    f = write(tmp_path / "written.bin", atime=now - 400 * DAY, mtime=now)
    assert so.last_use(f.stat()) > now - DAY


def test_skips_symlinks_empty_files_and_the_state_dir(tmp_path):
    """Already-archived files are symlinks, empty files free nothing, and the manifest
    is the tool's own state — none of the three may ever be demoted."""
    target = write(tmp_path / "real.bin")
    (tmp_path / "already-archived.bin").symlink_to(target)
    write(tmp_path / "empty.bin", data=b"")
    state = tmp_path / so.ARCHIVE_DIR
    write(state / "manifest.jsonl", data=b"{}\n")
    cands = so.gather_candidates(
        str(tmp_path), time.time() + DAY, {str(state) + os.sep}, {str(tmp_path / so.NOTE_NAME)}
    )
    assert paths(cands) == {str(target)}


def test_candidates_are_sorted_coldest_first(tmp_path):
    """The capacity sweep walks this list until it has freed enough and then stops, so
    the order IS the policy: whatever is coldest must be demoted first."""
    write(tmp_path / "a.bin")
    write(tmp_path / "b.bin")
    write(tmp_path / "c.bin")
    keys = [c[0] for c in gather(tmp_path, time.time() + DAY)]
    assert keys == sorted(keys)
