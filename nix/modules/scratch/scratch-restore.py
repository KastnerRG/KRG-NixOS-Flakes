"""scratch-restore — pull an archived /scratch file back to fast local storage.

The overflow job (scratch-overflow) demotes cold files to NFS and leaves a symlink
in their place. This is the self-service inverse: give it the symlink (or a directory
to do every archived file underneath), and it copies the data back from NFS, verifies
it (size + full sha256), and atomically replaces the symlink with the real file. No
admin needed.

Run it as yourself — the restored file ends up owned by you (it was your file). An
admin running it as root preserves the original owner. By default the now-redundant
NFS copy is removed AFTER the local copy is verified (so cold storage doesn't keep
orphans); pass --keep-cold to leave it.
"""

import argparse
import hashlib
import os
import stat
import sys
import time

COPY_CHUNK = 8 * 1024 * 1024


def log(msg):
    print(f"scratch-restore: {msg}", flush=True)


def copy_and_hash(src, dst):
    """Stream src -> dst computing src's sha256. Returns (sha, nbytes, dst_fd).

    dst is created O_CREAT|O_EXCL|O_NOFOLLOW and its fd is LEFT OPEN so the caller
    verifies + sets metadata THROUGH the fd — a user controlling the temp's dir can't
    swap it for a symlink between steps to redirect a root-run restore. src (the
    already-realpath'd cold file) is O_NOFOLLOW too. The caller owns closing dst_fd.
    """
    h = hashlib.sha256()
    n = 0
    src_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        dst_fd = os.open(dst, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except BaseException:
        os.close(src_fd)  # don't leak src_fd if the dst open fails
        raise
    try:
        with os.fdopen(src_fd, "rb") as fi:
            while True:
                buf = fi.read(COPY_CHUNK)
                if not buf:
                    break
                mv = memoryview(buf)
                while mv:  # os.write may short-write; drain it
                    mv = mv[os.write(dst_fd, mv) :]
                h.update(buf)
                n += len(buf)
        os.fsync(dst_fd)
    except BaseException:
        os.close(dst_fd)
        raise
    return h.hexdigest(), n, dst_fd


def tmp_sibling(path, tag):
    """Short unique temp path in path's dir (same fs -> atomic os.replace); a fixed
    short prefix avoids overflowing NAME_MAX when path's basename is near the limit."""
    return os.path.join(os.path.dirname(path) or ".", f".{tag}-{os.urandom(6).hex()}.tmp")


def fd_sha256(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        b = os.read(fd, COPY_CHUNK)
        if not b:
            break
        h.update(b)
    return h.hexdigest()


def fsync_dir(path):
    # Best-effort: never raises. Called AFTER the rename/unlink has committed, so a
    # fsync failure is a warning, not a reason to mis-report the op as failed.
    try:
        fd = os.open(path, os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError as e:
        log(f"warning: fsync of {path} failed: {e} (operation already committed)")
    finally:
        os.close(fd)


def under_any(path, roots):
    return any(path == r or path.startswith(r + os.sep) for r in roots)


def restore_one(link, scratch_roots, cold_roots, pairs, keep_cold, verbose):
    """Restore a single archived symlink. Returns True on a successful restore."""
    if not os.path.islink(link):
        if verbose:
            log(f"skip {link}: not an archived file (not a symlink)")
        return False
    # Containment on the LINK itself: a symlinked DIRECTORY component in the link's
    # parent could make os.replace(part, link) (run as root) write outside /scratch.
    # Resolve the parent and require it to stay within a configured scratch root.
    link_parent = os.path.realpath(os.path.dirname(link))
    if scratch_roots and not under_any(link_parent, scratch_roots):
        log(
            f"REFUSE {link}: resolves outside the scratch area(s) {scratch_roots} "
            f"(symlinked path component?) — not restoring"
        )
        return False
    target = os.readlink(link)
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(link), target)
    target = os.path.realpath(target)
    # Containment on the TARGET: /scratch is writable by lab members, so a planted
    # symlink could point anywhere. We copy FROM and (by default) unlink the target —
    # running as root that could delete an arbitrary file. Only act on targets that
    # resolve inside a configured cold area.
    if not under_any(target, cold_roots):
        log(
            f"REFUSE {link}: target {target} is outside the cold area(s) "
            f"{cold_roots} — not an archived scratch file (suspicious symlink?)"
        )
        return False
    # STRONGER (when we know the scratch->cold pairing): the target must be exactly
    # THIS link's canonical archive location, cold + relpath(link, scratch). Otherwise
    # a planted symlink to ANOTHER user's cold file (still under a cold root) could get
    # that unrelated file unlinked on a root restore.
    if pairs:
        link_real = os.path.join(link_parent, os.path.basename(link))
        expected = None
        for sroot, croot in pairs:
            if under_any(link_parent, [sroot]):
                rel = os.path.relpath(link_real, sroot)
                expected = os.path.realpath(os.path.join(croot, rel))
                break
        if expected is None or target != expected:
            log(
                f"REFUSE {link}: target {target} is not this link's archive location "
                f"(expected {expected}) — not an archived scratch file"
            )
            return False
    # stat() rather than os.path.isfile(): isfile() swallows the errno, so an
    # UNREADABLE archive (EACCES anywhere along the cold path) reported as "missing",
    # which sends people hunting for lost data that is sitting there intact. Keep the
    # two causes apart — they have completely different fixes.
    try:
        tst = os.stat(target)
    except PermissionError as e:
        log(
            f"skip {link}: cannot read the archived copy ({target}): {e.strerror}. "
            f"Your data is intact — the cold area is denying you access. Ask an admin "
            f"to check the export root's ownership/mode (ansible nfs_server "
            f"root_owner/root_group/root_mode)."
        )
        return False
    except FileNotFoundError:
        log(f"skip {link}: archive target missing ({target}) — is NFS mounted?")
        return False
    except OSError as e:
        log(f"skip {link}: cannot stat archive target ({target}): {e.strerror}")
        return False
    if not stat.S_ISREG(tst.st_mode):
        log(f"skip {link}: archive target is not a regular file ({target})")
        return False
    part = tmp_sibling(link, "sr")
    try:
        if os.path.lexists(part):
            os.unlink(part)  # clear any stale/planted temp (no follow)
        src_sha, n, fd = copy_and_hash(target, part)
        try:
            # verify + set metadata THROUGH the fd (never re-resolving `part`).
            if n != tst.st_size or fd_sha256(fd) != src_sha:
                os.unlink(part)
                log(f"FAILED {link}: verification mismatch (left as-is)")
                return False
            os.fchmod(fd, stat.S_IMODE(tst.st_mode))
            # mtime preserved (it's the data's age); atime set to NOW so the restore
            # itself counts as a recent access — the cold copy is on a noatime mount so
            # its atime is stale, and keeping it would make a just-restored file
            # immediately eligible for the next overflow sweep (TTL/capacity).
            os.utime(fd, ns=(max(time.time_ns(), tst.st_atime_ns), tst.st_mtime_ns))
            if os.geteuid() == 0:  # admin restore: preserve the original owner
                os.fchown(fd, tst.st_uid, tst.st_gid)
            os.fsync(fd)
            # if the cold target changed during copy/verify, don't swap in a stale
            # local copy — leave the symlink as-is.
            try:
                tcur = os.stat(target)
            except OSError:
                tcur = None
            if tcur is None or (tcur.st_ino, tcur.st_size, tcur.st_mtime_ns, tcur.st_ctime_ns) != (
                tst.st_ino,
                tst.st_size,
                tst.st_mtime_ns,
                tst.st_ctime_ns,
            ):
                os.unlink(part)
                log(f"skip {link}: cold target changed during restore — left the symlink")
                return False
            # ensure `part` is still our fd's inode (not swapped) before publishing.
            lp = os.lstat(part)
            if stat.S_ISLNK(lp.st_mode) or lp.st_ino != os.fstat(fd).st_ino:
                raise OSError(f"{part} was swapped before publish")
        finally:
            os.close(fd)
        os.replace(part, link)  # atomically replace the symlink with the real file
        fsync_dir(os.path.dirname(link))  # make the local rename durable
    except OSError as e:
        try:
            if os.path.lexists(part):
                os.unlink(part)
        except OSError:
            pass
        log(f"FAILED {link}: {e} (left as-is)")
        return False

    if not keep_cold:
        # Only remove the cold copy if it is STILL byte-for-byte what we just restored
        # (guard against a concurrent write to the cold file during the copy). If it
        # changed, keep it and warn rather than risk deleting newer data.
        try:
            tst2 = os.stat(target)
            unchanged = (tst2.st_ino, tst2.st_size, tst2.st_mtime_ns, tst2.st_ctime_ns) == (
                tst.st_ino,
                tst.st_size,
                tst.st_mtime_ns,
                tst.st_ctime_ns,
            )
        except OSError:
            unchanged = False
        if unchanged:
            try:
                os.unlink(target)
                fsync_dir(os.path.dirname(target))  # make the cold deletion durable
            except OSError as e:
                log(f"restored {link} but could not remove cold copy {target}: {e}")
        else:
            log(
                f"restored {link} but cold copy {target} changed during restore — "
                f"kept it (rerun with the file idle to reclaim NFS space)"
            )
    log(f"restored {link} ({tst.st_size} bytes)")
    return True


def walk_links(root):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                yield p


def main():
    ap = argparse.ArgumentParser(
        description="Restore archived /scratch files (symlinks) to local storage."
    )
    ap.add_argument("paths", nargs="+", help="archived file(s) or directories to restore")
    ap.add_argument(
        "--keep-cold",
        action="store_true",
        help="keep the NFS copy after restoring (default: remove it)",
    )
    ap.add_argument(
        "--cold-root",
        action="append",
        default=[],
        metavar="DIR",
        help="allowed cold-area root a symlink target must resolve under "
        "(repeatable). Defaults to $SCRATCH_COLD_ROOTS (colon-separated).",
    )
    ap.add_argument(
        "--scratch-root",
        action="append",
        default=[],
        metavar="DIR",
        help="allowed scratch root a link must resolve under (repeatable). "
        "Defaults to $SCRATCH_ROOTS (colon-separated).",
    )
    ap.add_argument(
        "--overflow-map",
        action="append",
        default=[],
        metavar="SCRATCH=COLD",
        help="scratch-root=cold-root pairing used to pin a link's target to "
        "its canonical archive location (repeatable). Defaults to "
        "$SCRATCH_OVERFLOW_MAP (semicolon-separated).",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    def build(flag_vals, env_name):
        vals = list(flag_vals) + [r for r in os.environ.get(env_name, "").split(":") if r]
        return sorted({os.path.realpath(r) for r in vals})

    # Cold roots (where targets must live) are mandatory: without them we can't tell a
    # legit archive from a planted symlink, and refusing to follow/delete is fail-safe.
    cold_roots = build(args.cold_root, "SCRATCH_COLD_ROOTS")
    if not cold_roots:
        log(
            "no cold-area root configured — set $SCRATCH_COLD_ROOTS or pass "
            "--cold-root DIR (refusing to follow/delete arbitrary symlink targets)"
        )
        return 2
    # Scratch roots (where links must live) are a best-effort extra containment.
    scratch_roots = build(args.scratch_root, "SCRATCH_ROOTS")
    # scratch->cold pairs ("scratch=cold;..."): when present, restore pins each link's
    # target to its canonical archive location (the strongest check).
    raw_pairs = list(args.overflow_map) + [
        m for m in os.environ.get("SCRATCH_OVERFLOW_MAP", "").split(";") if m
    ]
    pairs = []
    for m in raw_pairs:
        if "=" in m:
            sroot, croot = m.split("=", 1)
            pairs.append((os.path.realpath(sroot), os.path.realpath(croot)))

    restored = 0
    failed = 0
    for p in args.paths:
        if os.path.isdir(p) and not os.path.islink(p):
            for link in walk_links(p):
                if restore_one(
                    link, scratch_roots, cold_roots, pairs, args.keep_cold, args.verbose
                ):
                    restored += 1
                else:
                    # every link under the dir is an archived file we meant to restore
                    failed += 1
        else:
            if restore_one(p, scratch_roots, cold_roots, pairs, args.keep_cold, args.verbose):
                restored += 1
            elif os.path.islink(p):
                failed += 1
    log(f"done: {restored} restored, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
