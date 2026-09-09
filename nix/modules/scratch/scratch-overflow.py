"""scratch-overflow — demote the coldest /scratch files to NFS to relieve capacity.

Greenfield scratch design (docs/scratch-greenfield.md): /scratch lives on a striped
HDD pool fronted by NVMe ARC/L2ARC, so ZFS handles hot/cold for READS by itself.
This job moves the least-recently-used files to a cold NFS area for two reasons, both
keyed on last use — max(atime, mtime, ctime), NOT atime alone; see last_use(), a
copied-in atime is not evidence the data is idle HERE: a TTL sweep (--max-idle-days)
demotes anything untouched that long, every run, regardless of fullness (GC of
abandoned data); and a capacity sweep demotes the coldest files when the pool fills
past --high percent, until it drops below --low. Each demoted file is replaced with a
symlink to its NFS copy (the path keeps working, reads just go over the network); a
self-service `scratch-restore` pulls a file back to fast local storage.

FAIL-CLOSED BY CONSTRUCTION — this is the whole point of writing it carefully:
a local file is only ever unlinked AFTER its NFS copy is fully written, fsynced,
and verified (size + full sha256). If the cold area is not mounted, or any copy/
verify step fails, the local file is left exactly as it was. We never trust a
half-written cold copy. Run as root (the NFS export is no_root_squash) so the cold
copy preserves each file's owner/group/mode.

The krg.scratch overflow systemd timer invokes this; it is safe to run by hand,
and --dry-run reports what it WOULD move without touching anything.
"""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import time

COPY_CHUNK = 8 * 1024 * 1024  # 8 MiB streaming copy/hash buffer
ARCHIVE_DIR = ".scratch-overflow"  # per-scratch state dir (manifest), root-owned
NOTE_NAME = "WHERE-IS-MY-DATA.txt"  # breadcrumb dropped at the scratch root


def log(msg):
    print(f"scratch-overflow: {msg}", flush=True)


def die(msg, code=1):
    log(f"ERROR: {msg}")
    sys.exit(code)


def pool_bytes(zpool, pool):
    """(size, alloc, free) in bytes for the pool, via `zpool list -Hp`."""
    r = subprocess.run(
        [zpool, "list", "-Hp", "-o", "size,alloc,free", pool], capture_output=True, text=True
    )
    if r.returncode != 0:
        die(f"`zpool list {pool}` failed: {r.stderr.strip()}")
    try:
        size, alloc, free = (int(x) for x in r.stdout.split())
    except ValueError:
        die(f"could not parse `zpool list` output: {r.stdout!r}")
    return size, alloc, free


def capacity_pct(size, free):
    if size <= 0:
        return 0.0
    return 100.0 * (size - free) / size


def copy_and_hash(src, dst):
    """Stream src -> dst computing src's sha256. Returns (sha, nbytes, dst_fd).

    dst is created O_CREAT|O_EXCL|O_NOFOLLOW (no pre-existing/symlinked temp) and its
    fd is LEFT OPEN so the caller verifies + sets metadata THROUGH the fd, never
    re-resolving the path. A user who can write in the dir then can't swap the temp for
    a symlink between steps to redirect a root-run chown/chmod/verify. src is O_NOFOLLOW
    too. The caller owns closing dst_fd.
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
    """A short, unique temp path in the SAME directory as `path` (same filesystem, so
    os.replace is atomic). Fixed short prefix + random suffix, so it can't overflow
    NAME_MAX (255) the way `path + ".part"` would when path's basename is at the limit.
    """
    return os.path.join(os.path.dirname(path) or ".", f".{tag}-{os.urandom(6).hex()}.tmp")


def fd_sha256(fd):
    """sha256 of an open fd's contents (rewinds first)."""
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        b = os.read(fd, COPY_CHUNK)
        if not b:
            break
        h.update(b)
    return h.hexdigest()


def fsync_dir(path):
    # Best-effort durability of a directory's metadata (a rename/unlink). Deliberately
    # never raises: it is called AFTER the op has already committed, so a fsync failure
    # must be a warning — not something that flips an already-done operation into a
    # reported failure (and an unsynced rename still persists on a clean shutdown).
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


def open_manifest(state_dir):
    """Open <state_dir>/manifest.jsonl for append, SAFELY.

    The scratch root is group-writable by lab members, so a user could plant a
    symlink at .scratch-overflow or manifest.jsonl to redirect this root-run write.
    Refuse to use a state dir that isn't a real root-owned directory, and open the
    file O_NOFOLLOW. The dir is 0700 and the file 0600, ROOT-ONLY: the manifest lists
    paths from users' private (0700) per-user subtrees, so it must not be readable by
    the (setgid) lab group. Returns an fp, or None (manifest skipped — it's an audit
    log, non-critical; the archive symlinks are the source of truth for restore).
    """
    try:
        ds = os.lstat(state_dir)
        if stat.S_ISLNK(ds.st_mode) or not stat.S_ISDIR(ds.st_mode) or ds.st_uid != 0:
            log(
                f"WARNING: {state_dir} is not a root-owned dir (symlink/planted?) — "
                "skipping manifest this run"
            )
            return None
        os.chmod(state_dir, 0o700)  # enforce root-only even if it pre-existed group-readable
    except FileNotFoundError:
        try:
            os.mkdir(state_dir, 0o700)
        except OSError as e:
            log(f"WARNING: cannot create {state_dir}: {e} — skipping manifest")
            return None
    try:
        fd = os.open(
            os.path.join(state_dir, "manifest.jsonl"),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        return os.fdopen(fd, "a")
    except OSError as e:
        log(f"WARNING: cannot open manifest: {e} — skipping manifest")
        return None


def write_note(scratch, cold):
    """Write the breadcrumb at the scratch root, refusing to follow a planted symlink."""
    path = os.path.join(scratch, NOTE_NAME)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(NOTE_TEXT.format(cold=cold))
    except OSError:
        pass  # cosmetic; never fail the run over the note


def makedirs_mirror(scratch, cold, rel):
    """Create cold/<dirname(rel)>, mirroring each source dir's owner/mode (+ setgid).

    The default root umask would leave the cold tree as root:root 0755, which would
    undermine the per-user 0700 privacy of the scratch tree. Replicate the source
    directory perms level by level instead.
    """
    sub = os.path.dirname(rel)
    if not sub:
        return
    cur_src, cur_cold = scratch, cold
    for part in sub.split(os.sep):
        if not part:
            continue
        cur_src = os.path.join(cur_src, part)
        cur_cold = os.path.join(cur_cold, part)
        # Refuse a symlink at any cold component: a symlinked dir (even one resolving
        # back INSIDE cold) would let our root-run chown/chmod/write land in the wrong
        # place and break per-user isolation. lstat (no follow) + S_ISLNK check.
        try:
            cst = os.lstat(cur_cold)
            exists = True
        except FileNotFoundError:
            exists = False
        if exists:
            if stat.S_ISLNK(cst.st_mode):
                raise OSError(f"cold path component is a symlink: {cur_cold}")
            if not stat.S_ISDIR(cst.st_mode):
                raise OSError(f"cold path component is not a directory: {cur_cold}")
        else:
            os.mkdir(cur_cold)
        try:
            sst = os.stat(cur_src)
            os.chown(cur_cold, sst.st_uid, sst.st_gid, follow_symlinks=False)
            os.chmod(cur_cold, stat.S_IMODE(sst.st_mode))
        except OSError:
            pass


def last_use(st):
    """When this file was last used ON THIS POOL — max(atime, mtime, ctime).

    atime alone is NOT that, because atime travels with the data. Anything staged in
    with timestamps preserved (`cp -a`, `rsync --atimes`, `tar --atime-preserve`, a
    zfs send/recv migration) arrives carrying the atime it had on the machine it came
    from, so a dataset copied onto /scratch yesterday can present as years idle and
    the TTL sweep archives it the very first night — which is exactly what happened to
    68k files of a just-staged dataset here (manifest atimes predating the pool's own
    creation date). ctime is the guard: userspace cannot set it, the kernel stamps it
    when the file is created/written/chowned on THIS filesystem, so it bounds how long
    the file can possibly have been sitting here untouched. mtime is folded in for the
    same reason — a file written but never read back is not abandoned.

    Erring late is the right direction: the cost of a too-late demotion is some HDD
    space on a pool that is 16% full; the cost of a too-early one is a researcher's
    live dataset behind an NFS symlink.
    """
    return max(st.st_atime, st.st_mtime, st.st_ctime)


def gather_candidates(scratch, cutoff, skip_dir_prefixes, skip_exact):
    """Regular, non-symlink files under scratch not used (see last_use) since cutoff.

    `skip_dir_prefixes` are directory paths (each ending in os.sep) whose subtrees are
    excluded; `skip_exact` are individual file paths excluded by exact match (so e.g.
    the breadcrumb note isn't a prefix that also hides "WHERE-IS-MY-DATA.txt.bak").

    Builds one in-memory list of (last_use, size, path) and sorts it. That's bounded in
    practice: sharding is the data-layout standard here (a few large shards, not
    millions of tiny files — see docs/scratch-greenfield.md), the tuples are light
    (~tens of MB even at a million files), and the sweep runs Nice=10 / idle I/O once
    a day. If file counts ever explode, switch to a streaming bounded-heap selection.
    """
    cands = []
    for root, dirs, files in os.walk(scratch, topdown=True):
        # never descend into an excluded subtree (e.g. the state dir)
        dirs[:] = [d for d in dirs if os.path.join(root, d) + os.sep not in skip_dir_prefixes]
        for name in files:
            p = os.path.join(root, name)
            if p in skip_exact:
                continue
            if any(p.startswith(pref) for pref in skip_dir_prefixes):
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):  # symlinks/dirs/sockets -> skip
                continue
            if st.st_size == 0:
                continue
            lu = last_use(st)
            if lu > cutoff:  # recently used -> too hot to move
                continue
            cands.append((lu, st.st_size, p))
    # coldest first; for equal last-use, bigger first (frees space in fewer moves)
    cands.sort(key=lambda t: (t[0], -t[1]))
    return cands


def archive_one(path, scratch, cold, manifest_fp, dry_run, reason="capacity"):
    """Copy path -> cold, verify, then atomically replace path with a symlink.

    `reason` is recorded in the manifest ("ttl" = idle longer than max-idle-days,
    "capacity" = demoted to relieve a full pool). Returns bytes freed (the file
    size) on success, 0 on skip/failure. NEVER unlinks the local file unless the
    cold copy verified.
    """
    rel = os.path.relpath(path, scratch)
    dest = os.path.join(cold, rel)
    try:
        st = os.stat(path)  # re-stat (TOCTOU): the walk may be stale
    except OSError:
        return 0
    size = st.st_size  # logical size — for the manifest + human-facing logs
    # ALLOCATED bytes (st_blocks * 512) is what actually frees from the pool. Pool
    # fullness is measured by `zpool list` (physical), and with zstd compression the
    # logical size can differ a lot — so accounting toward the low-water target must
    # use allocated, not logical, or the capacity sweep stops early / overshoots.
    freed_bytes = st.st_blocks * 512

    if dry_run:
        log(f"would archive [{reason}] {rel} ({size} bytes) -> {dest}")
        return freed_bytes

    # Path-traversal guard: the cold tree is on a no_root_squash export and we run as
    # root, so a stray symlink in a path component must not let a write escape `cold`.
    # realpath() resolves any symlink component; refuse if dest lands outside cold.
    cold_real = os.path.realpath(cold)
    dest_real = os.path.realpath(dest)
    if dest_real != cold_real and not dest_real.startswith(cold_real + os.sep):
        log(f"skip {rel}: cold dest escapes {cold} (symlinked path component?) — refusing")
        return 0

    part = tmp_sibling(dest, "so")
    try:
        makedirs_mirror(scratch, cold, rel)  # mirror source dir owner/mode into cold
        if os.path.lexists(part):
            os.unlink(part)  # clear any stale/planted temp (no follow)
        src_sha, nbytes, fd = copy_and_hash(path, part)
        try:
            if nbytes != size:
                os.unlink(part)
                log(f"skip {rel}: size changed during copy ({size}->{nbytes})")
                return 0
            # verify + set metadata THROUGH the fd (never re-resolving `part`), so a
            # swapped-in symlink can't redirect the checksum/chown/chmod/utime.
            if fd_sha256(fd) != src_sha:
                os.unlink(part)
                log(f"skip {rel}: checksum mismatch after copy (NOT removed locally)")
                return 0
            os.fchown(fd, st.st_uid, st.st_gid)  # owner (root + no_root_squash)
            os.fchmod(fd, stat.S_IMODE(st.st_mode))  # mode
            os.utime(fd, ns=(st.st_atime_ns, st.st_mtime_ns))
            os.fsync(fd)
            # ensure `part` still IS our fd's inode (not swapped) right before publish.
            lp = os.lstat(part)
            if stat.S_ISLNK(lp.st_mode) or lp.st_ino != os.fstat(fd).st_ino:
                raise OSError(f"{part} was swapped before publish")
        finally:
            os.close(fd)
        os.replace(part, dest)  # atomic publish of the verified cold copy
        fsync_dir(os.path.dirname(dest))
    except OSError as e:
        # any failure: clean the partial, leave the local file in place
        try:
            if os.path.lexists(part):
                os.unlink(part)
        except OSError:
            pass
        log(f"skip {rel}: {e} (local file left intact)")
        return 0

    # The cold copy reflects the source AS IT WAS when we read it. If the source was
    # modified after that (a job rewrote it), swapping in the symlink now would discard
    # the newer local content. Re-stat and bail if identity/size/mtime/ctime changed —
    # the cold copy is then a stale orphan, so drop it and leave the local file intact.
    try:
        st2 = os.stat(path)
    except OSError:
        st2 = None
    changed = st2 is None or (st2.st_ino, st2.st_size, st2.st_mtime_ns, st2.st_ctime_ns) != (
        st.st_ino,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )
    if changed:
        try:
            os.unlink(dest)
        except OSError:
            pass
        log(f"skip {rel}: source changed during archive — local file kept, cold copy discarded")
        return 0

    # cold copy is durable + verified + source unchanged — swap local file for a symlink.
    link_tmp = tmp_sibling(path, "so")
    try:
        if os.path.lexists(link_tmp):
            os.unlink(link_tmp)
        os.symlink(dest, link_tmp)
        os.replace(link_tmp, path)  # atomically frees the local file's blocks
        fsync_dir(os.path.dirname(path))  # make the local rename durable too
    except OSError as e:
        try:
            if os.path.lexists(link_tmp):
                os.unlink(link_tmp)
        except OSError:
            pass
        log(
            f"archived {rel} to NFS but FAILED to swap symlink: {e} "
            f"(cold copy kept at {dest}; local file intact)"
        )
        return 0

    manifest_fp.write(
        json.dumps(
            {
                "ts": int(time.time()),
                "reason": reason,
                "path": path,
                "dest": dest,
                "size": size,
                "sha256": src_sha,
                "atime": int(st.st_atime),
                # what the sweep actually judged it on (see last_use) — differs from
                # atime whenever the file was staged in with preserved timestamps
                "last_use": int(last_use(st)),
            }
        )
        + "\n"
    )
    manifest_fp.flush()
    log(f"archived [{reason}] {rel} ({size} bytes) -> {dest}")
    return freed_bytes


NOTE_TEXT = """\
Some files under this scratch directory have been moved to network storage (NFS):
either they had not been touched in a long time, or they were the coldest files when
scratch filled up and space had to be freed.

A moved file now appears as a SYMLINK pointing into {cold}.
Reading it still works exactly as before — the data is just served over the
network, so it is slower. Nothing has been lost.

To pull a file (or a whole directory) back to fast local storage:

    scratch-restore PATH [PATH ...]

Anything you are actively using will stay local; only cold files get moved.
This is automatic and reversible — you never need to ask an admin.
"""


def main():
    ap = argparse.ArgumentParser(description="Demote cold /scratch files to NFS.")
    ap.add_argument("--pool", required=True, help="ZFS pool to measure (e.g. scratchpool)")
    ap.add_argument("--scratch", required=True, help="scratch mountpoint (e.g. /scratch/krg)")
    ap.add_argument(
        "--cold", required=True, help="cold NFS mountpoint (e.g. /srv/scratch-cold/krg)"
    )
    ap.add_argument("--high", type=float, default=85.0, help="start moving above this pool %% full")
    ap.add_argument("--low", type=float, default=75.0, help="stop moving below this pool %% full")
    ap.add_argument(
        "--min-age-days",
        type=float,
        default=14.0,
        help="never move a file used within this many days (capacity sweep floor); "
        "use = max(atime, mtime, ctime)",
    )
    ap.add_argument(
        "--max-idle-days",
        type=float,
        default=0.0,
        help="TTL sweep: move ANY file not used in this many days, "
        "regardless of pool fullness. 0 = disabled.",
    )
    ap.add_argument("--zpool", default="zpool", help="zpool binary (PATH by default)")
    ap.add_argument("--dry-run", action="store_true", help="report only; touch nothing")
    args = ap.parse_args()

    # FAIL-CLOSED: refuse to run unless both ends are real mountpoints. If the cold
    # NFS area is not mounted we must NOT move anything (and the systemd unit also
    # guards this via RequiresMountsFor). If scratch isn't mounted there's nothing
    # to do and we must not walk the bare mountpoint dir.
    if not os.path.ismount(args.scratch):
        log(f"{args.scratch} is not mounted; nothing to do")
        return 0
    if not os.path.ismount(args.cold):
        die(f"cold area {args.cold} is not mounted — refusing to archive (fail-closed)")
    if not (0 < args.low < args.high <= 100):
        die(f"need 0 < low ({args.low}) < high ({args.high}) <= 100")

    size, alloc, free = pool_bytes(args.zpool, args.pool)
    pct = capacity_pct(size, free)
    ttl_on = args.max_idle_days > 0
    log(
        f"pool {args.pool}: {pct:.1f}% full (high={args.high} low={args.low}"
        f"{f'; ttl={args.max_idle_days}d' if ttl_on else ''})"
    )
    if pct < args.high and not ttl_on:
        log("below high-water mark and no TTL set; nothing to do")
        return 0

    # One tree walk -> everything idle longer than the capacity-sweep floor
    # (min-age-days), coldest first. The TTL and capacity passes both draw from this.
    state_dir = os.path.join(args.scratch, ARCHIVE_DIR)
    skip_dir_prefixes = {state_dir + os.sep}
    skip_exact = {os.path.join(args.scratch, NOTE_NAME)}
    now = time.time()
    cutoff = now - args.min_age_days * 86400.0
    cands = gather_candidates(args.scratch, cutoff, skip_dir_prefixes, skip_exact)
    if not cands:
        log("no eligible files (all used too recently or already archived)")
        return 0

    # Split: TTL = idle past max-idle-days (move unconditionally); the rest are only
    # eligible for the capacity sweep (idle between min-age and max-idle).
    ttl_cutoff = (now - args.max_idle_days * 86400.0) if ttl_on else None
    ttl_list = [c for c in cands if ttl_on and c[0] < ttl_cutoff]
    cap_list = [c for c in cands if not (ttl_on and c[0] < ttl_cutoff)]

    if args.dry_run:
        manifest_fp = open(os.devnull, "w")
    else:
        manifest_fp = open_manifest(state_dir) or open(os.devnull, "w")

    freed = 0
    moved = 0
    try:
        # --- TTL pass: unconditional, runs even when the pool is nowhere near full ---
        if ttl_list:
            log(f"TTL sweep: {len(ttl_list)} file(s) idle > {args.max_idle_days}d")
            for _lu, _size, path in ttl_list:
                got = archive_one(
                    path, args.scratch, args.cold, manifest_fp, args.dry_run, reason="ttl"
                )
                if got:
                    freed += got
                    moved += 1

        # --- capacity pass: only if still over the high-water mark after the TTL pass ---
        if not args.dry_run:
            size, alloc, free = pool_bytes(args.zpool, args.pool)
            pct = capacity_pct(size, free)
        else:
            # nothing was actually moved; estimate the post-TTL fullness so the dry-run
            # capacity decision reflects what the TTL sweep WOULD have freed.
            free += freed
            pct = capacity_pct(size, free)
        if pct >= args.high:
            target_free = size * (1.0 - args.low / 100.0)
            to_free = max(0, int(target_free - free))
            log(
                f"capacity sweep: {pct:.1f}% full, need to free ~{to_free} bytes "
                f"to reach {args.low}%"
            )
            cap_freed = 0
            for _lu, _size, path in cap_list:
                if cap_freed >= to_free:
                    break
                got = archive_one(
                    path, args.scratch, args.cold, manifest_fp, args.dry_run, reason="capacity"
                )
                if got:
                    cap_freed += got
                    freed += got
                    moved += 1
            if cap_freed < to_free:
                log(
                    "capacity sweep moved every eligible file but is still above "
                    f"{args.low}% (nothing left older than {args.min_age_days}d)"
                )
    finally:
        manifest_fp.close()

    if not args.dry_run and moved:
        write_note(args.scratch, args.cold)
        size, alloc, free = pool_bytes(args.zpool, args.pool)
        log(
            f"done: moved {moved} files, freed ~{freed} bytes; "
            f"pool now {capacity_pct(size, free):.1f}% full"
        )
    else:
        log(
            f"done: {'would free' if args.dry_run else 'freed'} ~{freed} bytes across {moved} files"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
