#!/usr/bin/env python3
"""Materialize the Alpine rootfs fixture used by mcr smoke tests.

The script intentionally uses only Python's standard library so a fresh checkout
can prepare `tests/fixtures/rootfs/alpine-rootfs` without requiring Docker,
Podman, or a host `apk` binary.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


DEFAULT_ARCH = "x86_64"
DEFAULT_FIXTURE_ROOT = "tests/fixtures"
DEFAULT_MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
DEFAULT_PACKAGES = ("curl", "git", "ca-certificates", "ca-certificates-bundle")
DEFAULT_ROOTFS_NAME = "alpine-rootfs"
ROOTFS_MANIFEST = "rootfs/manifest.mcr"
REPOSITORIES = ("main", "community")


class MaterializeError(Exception):
    """Raised when the rootfs cannot be materialized safely."""


@dataclass(frozen=True)
class AlpineRelease:
    branch: str
    version: str
    file: str
    sha256: str


@dataclass(frozen=True)
class RootfsRecord:
    name: str
    path: Path
    archive_path: Path
    source_url: str


@dataclass(frozen=True)
class ApkPackage:
    name: str
    version: str
    repo: str
    depends: tuple[str, ...]
    provides: tuple[str, ...]

    @property
    def filename(self) -> str:
        return f"{self.name}-{self.version}.apk"


@dataclass(frozen=True)
class WorktreeCache:
    main_repo_root: Path
    fixtures_dir: Path
    rootfs_dir: Path
    archive_path: Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download and extract the Alpine rootfs fixture for mcr."
    )
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=Path(DEFAULT_FIXTURE_ROOT),
        help=f"fixture root containing {ROOTFS_MANIFEST} (default: {DEFAULT_FIXTURE_ROOT})",
    )
    parser.add_argument(
        "--mirror",
        default=DEFAULT_MIRROR,
        help=f"Alpine mirror base URL (default: {DEFAULT_MIRROR})",
    )
    parser.add_argument(
        "--arch",
        default=DEFAULT_ARCH,
        help=f"Alpine architecture (default: {DEFAULT_ARCH})",
    )
    parser.add_argument(
        "--rootfs-name",
        default=DEFAULT_ROOTFS_NAME,
        help=f"rootfs manifest entry to materialize (default: {DEFAULT_ROOTFS_NAME})",
    )
    parser.add_argument(
        "--package",
        dest="packages",
        action="append",
        help="extra Alpine package to install into the fixture; may be repeated",
    )
    parser.add_argument(
        "--no-network-packages",
        action="store_true",
        help="only extract the Alpine minirootfs; do not add curl/git/CA packages",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing rootfs fixture",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="validate the existing fixture and do not download or extract anything",
    )
    parser.add_argument(
        "--no-worktree-cache",
        action="store_true",
        help="materialize inside this checkout even when it is a linked git worktree",
    )
    args = parser.parse_args()

    try:
        script_root = Path(__file__).resolve().parents[1]
        repo_root = discover_repo_root(script_root)
        fixtures_dir = absolutize(repo_root, args.fixtures_dir)
        rootfs_name = args.rootfs_name
        record = read_rootfs_record(fixtures_dir, rootfs_name)
        rootfs_dir = fixtures_dir / record.path
        archive_path = fixtures_dir / record.archive_path
        cache = None
        if not args.no_worktree_cache and not args.fixtures_dir.is_absolute():
            cache = discover_worktree_cache(repo_root, args.fixtures_dir, record)

        if args.check_only:
            validate_rootfs(rootfs_dir, require_network_packages=not args.no_network_packages)
            print(f"{rootfs_name} is ready at {rootfs_dir}")
            return 0

        if cache is not None:
            ensure_cached_worktree_rootfs(
                rootfs_name=rootfs_name,
                cache=cache,
                mirror=args.mirror.rstrip("/"),
                arch=args.arch,
                force=args.force,
                package_names=()
                if args.no_network_packages
                else package_list(args.packages),
            )
            link_worktree_rootfs(
                rootfs_name=rootfs_name,
                rootfs_dir=rootfs_dir,
                cached_rootfs_dir=cache.rootfs_dir,
                force=args.force,
            )
            validate_rootfs(rootfs_dir, require_network_packages=not args.no_network_packages)
            print(f"{rootfs_name} is ready at {rootfs_dir}")
            return 0

        if rootfs_dir.exists() and not args.force:
            validate_rootfs(rootfs_dir, require_network_packages=not args.no_network_packages)
            print(f"{rootfs_name} already exists at {rootfs_dir}; use --force to rebuild")
            return 0

        materialize_rootfs(
            rootfs_name=rootfs_name,
            mirror=args.mirror.rstrip("/"),
            arch=args.arch,
            fixtures_dir=fixtures_dir,
            rootfs_dir=rootfs_dir,
            archive_path=archive_path,
            force=args.force,
            package_names=() if args.no_network_packages else package_list(args.packages),
        )
    except MaterializeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    return 0


def materialize_rootfs(
    *,
    rootfs_name: str,
    mirror: str,
    arch: str,
    fixtures_dir: Path,
    rootfs_dir: Path,
    archive_path: Path,
    force: bool,
    package_names: tuple[str, ...],
) -> None:
    release = fetch_latest_minirootfs_release(mirror, arch)
    archive_url = f"{mirror}/latest-stable/releases/{arch}/{release.file}"
    download_file(archive_url, archive_path, expected_sha256=release.sha256)

    tmp_dir = rootfs_dir.with_name(f"{rootfs_dir.name}.tmp")
    if tmp_dir.exists():
        remove_tree(tmp_dir)
    tmp_dir.mkdir(parents=True)

    try:
        extract_tar(archive_path, tmp_dir, skip_apk_metadata=False)
        write_runtime_defaults(tmp_dir, mirror, release.branch)
        if package_names:
            install_packages(
                mirror=mirror,
                branch=release.branch,
                arch=arch,
                fixtures_dir=fixtures_dir,
                rootfs_dir=tmp_dir,
                package_names=package_names,
            )
        write_runtime_defaults(tmp_dir, mirror, release.branch)
        validate_rootfs(tmp_dir, require_network_packages=bool(package_names))

        if rootfs_dir.exists():
            if not force:
                raise MaterializeError(f"{rootfs_dir} already exists; use --force to replace it")
            remove_tree(rootfs_dir)
        tmp_dir.replace(rootfs_dir)
    except Exception:
        if tmp_dir.exists():
            remove_tree(tmp_dir)
        raise

    print(f"materialized {rootfs_name} at {rootfs_dir}")
    print(f"Alpine {release.version} ({release.branch}) archive: {archive_path}")
    if package_names:
        print("installed packages: " + ", ".join(package_names))


def discover_repo_root(script_root: Path) -> Path:
    output = git_capture(script_root, "rev-parse", "--show-toplevel")
    if output is None:
        return script_root.resolve()
    return Path(output).resolve()


def discover_worktree_cache(
    repo_root: Path, fixtures_arg: Path, record: RootfsRecord
) -> WorktreeCache | None:
    main_repo_root = discover_main_worktree(repo_root)
    if main_repo_root is None or same_path(main_repo_root, repo_root):
        return None

    main_fixtures_dir = main_repo_root / fixtures_arg
    main_record = read_rootfs_record(main_fixtures_dir, record.name)
    return WorktreeCache(
        main_repo_root=main_repo_root,
        fixtures_dir=main_fixtures_dir,
        rootfs_dir=main_fixtures_dir / main_record.path,
        archive_path=main_fixtures_dir / main_record.archive_path,
    )


def discover_main_worktree(repo_root: Path) -> Path | None:
    output = git_capture(repo_root, "worktree", "list", "--porcelain")
    if output is None:
        return None
    for line in output.splitlines():
        if line.startswith("worktree "):
            return Path(line.removeprefix("worktree ")).resolve()
    return None


def git_capture(cwd: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ("git", "-C", str(cwd), *args),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def ensure_cached_worktree_rootfs(
    *,
    rootfs_name: str,
    cache: WorktreeCache,
    mirror: str,
    arch: str,
    force: bool,
    package_names: tuple[str, ...],
) -> None:
    require_network_packages = bool(package_names)
    if cache.rootfs_dir.exists():
        try:
            validate_rootfs(
                cache.rootfs_dir,
                require_network_packages=require_network_packages,
            )
        except MaterializeError as error:
            if not force:
                raise MaterializeError(
                    f"cached {rootfs_name} at {cache.rootfs_dir} is invalid: {error}; "
                    "rerun with --force to rebuild it"
                ) from error
        else:
            print(f"using cached {rootfs_name} from main worktree {cache.rootfs_dir}")
            return
    elif os.path.lexists(cache.rootfs_dir):
        if not force:
            raise MaterializeError(
                f"cached {rootfs_name} path is a broken symlink: {cache.rootfs_dir}; "
                "rerun with --force to rebuild it"
            )
        cache.rootfs_dir.unlink()

    print(f"materializing cached {rootfs_name} in main worktree {cache.main_repo_root}")
    materialize_rootfs(
        rootfs_name=rootfs_name,
        mirror=mirror,
        arch=arch,
        fixtures_dir=cache.fixtures_dir,
        rootfs_dir=cache.rootfs_dir,
        archive_path=cache.archive_path,
        force=force,
        package_names=package_names,
    )


def link_worktree_rootfs(
    *, rootfs_name: str, rootfs_dir: Path, cached_rootfs_dir: Path, force: bool
) -> None:
    rootfs_dir.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(rootfs_dir):
        if rootfs_dir.is_symlink():
            if rootfs_dir.exists() and same_path(rootfs_dir.resolve(), cached_rootfs_dir):
                print(f"{rootfs_name} already links to {cached_rootfs_dir}")
                return
            if not force:
                raise MaterializeError(
                    f"{rootfs_dir} is already a symlink; use --force to relink it"
                )
            rootfs_dir.unlink()
        elif rootfs_dir.is_dir():
            if not force:
                raise MaterializeError(
                    f"{rootfs_dir} already exists; use --force to replace it with "
                    f"a symlink to {cached_rootfs_dir}"
                )
            remove_tree(rootfs_dir)
        else:
            if not force:
                raise MaterializeError(
                    f"{rootfs_dir} already exists; use --force to replace it with "
                    f"a symlink to {cached_rootfs_dir}"
                )
            rootfs_dir.unlink()

    target = symlink_target(cached_rootfs_dir, rootfs_dir.parent)
    os.symlink(target, rootfs_dir, target_is_directory=True)
    print(f"linked {rootfs_dir} -> {target}")


def symlink_target(target: Path, start: Path) -> str:
    try:
        return os.path.relpath(target, start)
    except ValueError:
        return str(target)


def same_path(left: Path, right: Path) -> bool:
    return left.resolve() == right.resolve()


def package_list(extra_packages: list[str] | None) -> tuple[str, ...]:
    packages = list(DEFAULT_PACKAGES)
    if extra_packages:
        packages.extend(extra_packages)
    seen: set[str] = set()
    deduped: list[str] = []
    for package in packages:
        if package not in seen:
            seen.add(package)
            deduped.append(package)
    return tuple(deduped)


def absolutize(repo_root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return repo_root / path


def read_rootfs_record(fixtures_dir: Path, name: str) -> RootfsRecord:
    manifest = fixtures_dir / ROOTFS_MANIFEST
    if not manifest.is_file():
        raise MaterializeError(f"missing fixture manifest: {manifest}")

    for record in parse_manifest_records(manifest.read_text()):
        if record.get("name") == name:
            try:
                return RootfsRecord(
                    name=record["name"],
                    path=Path(record["path"]),
                    archive_path=Path(record["archive_path"]),
                    source_url=record["source_url"],
                )
            except KeyError as error:
                raise MaterializeError(
                    f"{manifest}: rootfs `{name}` is missing {error.args[0]}"
                ) from error

    raise MaterializeError(f"{manifest}: rootfs `{name}` is not declared")


def parse_manifest_records(contents: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "[[rootfs]]":
            if current is not None:
                records.append(current)
            current = {}
            continue
        if current is None or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        current[key.strip()] = value.strip().strip('"')
    if current is not None:
        records.append(current)
    return records


def fetch_latest_minirootfs_release(mirror: str, arch: str) -> AlpineRelease:
    url = f"{mirror}/latest-stable/releases/{arch}/latest-releases.yaml"
    contents = fetch_text(url)
    records = parse_latest_release_records(contents)
    for record in records:
        if record.get("flavor") == "alpine-minirootfs" and record.get("arch") == arch:
            try:
                return AlpineRelease(
                    branch=record["branch"],
                    version=record["version"],
                    file=record["file"],
                    sha256=record["sha256"],
                )
            except KeyError as error:
                raise MaterializeError(
                    f"{url}: alpine-minirootfs record is missing {error.args[0]}"
                ) from error
    raise MaterializeError(f"{url}: no alpine-minirootfs release for {arch}")


def parse_latest_release_records(contents: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    in_block_value = False

    for line in contents.splitlines():
        if line.startswith("-"):
            if current:
                records.append(current)
            current = {}
            in_block_value = False
            continue
        if current is None:
            continue
        if line.startswith("  ") and not line.startswith("    ") and ":" in line:
            key, value = line.strip().split(":", 1)
            value = value.strip()
            in_block_value = value == "|"
            if not in_block_value:
                current[key] = value.strip('"')
        elif not line.startswith("    "):
            in_block_value = False

    if current:
        records.append(current)
    return records


def install_packages(
    *,
    mirror: str,
    branch: str,
    arch: str,
    fixtures_dir: Path,
    rootfs_dir: Path,
    package_names: tuple[str, ...],
) -> None:
    packages, providers = load_package_indexes(mirror, branch, arch)
    installed = load_installed_packages(rootfs_dir)
    plan = resolve_packages(package_names, packages, providers, installed)
    cache_dir = fixtures_dir / "rootfs" / "apk-cache" / branch / arch

    for package in plan:
        package_url = package_url_for(mirror, branch, arch, package)
        package_path = cache_dir / package.repo / package.filename
        download_file(package_url, package_path, expected_sha256=None)
        extract_tar(package_path, rootfs_dir, skip_apk_metadata=True)


def load_package_indexes(
    mirror: str, branch: str, arch: str
) -> tuple[dict[str, ApkPackage], dict[str, ApkPackage]]:
    packages: dict[str, ApkPackage] = {}
    providers: dict[str, ApkPackage] = {}
    for repo in REPOSITORIES:
        url = f"{mirror}/{branch}/{repo}/{arch}/APKINDEX.tar.gz"
        index_text = fetch_apkindex(url)
        for package in parse_apkindex(index_text, repo):
            packages.setdefault(package.name, package)
            for provided in package.provides:
                providers.setdefault(normalize_dependency(provided), package)
    return packages, providers


def fetch_apkindex(url: str) -> str:
    data = fetch_bytes(url)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("APKINDEX")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise MaterializeError(f"{url}: APKINDEX is empty")
        return extracted.read().decode()


def parse_apkindex(contents: str, repo: str) -> list[ApkPackage]:
    packages: list[ApkPackage] = []
    for record in parse_apk_records(contents):
        if "P" not in record or "V" not in record:
            continue
        packages.append(
            ApkPackage(
                name=record["P"],
                version=record["V"],
                repo=repo,
                depends=tuple(record.get("D", "").split()),
                provides=tuple(record.get("p", "").split()),
            )
        )
    return packages


def load_installed_packages(rootfs_dir: Path) -> set[str]:
    installed_path = rootfs_dir / "lib/apk/db/installed"
    installed: set[str] = set()
    if not installed_path.is_file():
        return installed
    for record in parse_apk_records(installed_path.read_text()):
        name = record.get("P")
        if name:
            installed.add(name)
        for provided in record.get("p", "").split():
            installed.add(normalize_dependency(provided))
    return installed


def parse_apk_records(contents: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in contents.splitlines():
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if len(line) >= 2 and line[1] == ":":
            current[line[0]] = line[2:]
    if current:
        records.append(current)
    return records


def resolve_packages(
    package_names: tuple[str, ...],
    packages: dict[str, ApkPackage],
    providers: dict[str, ApkPackage],
    installed: set[str],
) -> list[ApkPackage]:
    resolved: dict[str, ApkPackage] = {}
    planned_provides: set[str] = set()
    queue = list(package_names)

    while queue:
        requested = queue.pop(0)
        normalized = normalize_dependency(requested)
        if should_ignore_dependency(requested, normalized):
            continue
        if normalized in installed or normalized in planned_provides:
            continue
        if normalized in resolved:
            continue

        package = packages.get(normalized) or providers.get(normalized)
        if package is None:
            raise MaterializeError(f"cannot resolve Alpine package dependency `{requested}`")

        if package.name not in resolved:
            resolved[package.name] = package
            planned_provides.add(package.name)
            for provided in package.provides:
                planned_provides.add(normalize_dependency(provided))
            queue.extend(package.depends)

    return topo_sort_packages(resolved, packages, providers, installed)


def topo_sort_packages(
    resolved: dict[str, ApkPackage],
    packages: dict[str, ApkPackage],
    providers: dict[str, ApkPackage],
    installed: set[str],
) -> list[ApkPackage]:
    ordered: list[ApkPackage] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(package: ApkPackage) -> None:
        if package.name in visited:
            return
        if package.name in visiting:
            return
        visiting.add(package.name)
        for dependency in package.depends:
            normalized = normalize_dependency(dependency)
            if should_ignore_dependency(dependency, normalized):
                continue
            if normalized in installed:
                continue
            dependency_package = resolved.get(normalized)
            if dependency_package is None:
                provider = providers.get(normalized)
                if provider and provider.name in resolved:
                    dependency_package = provider
            if dependency_package is None:
                named = packages.get(normalized)
                if named and named.name in resolved:
                    dependency_package = named
            if dependency_package is not None:
                visit(dependency_package)
        visiting.remove(package.name)
        visited.add(package.name)
        ordered.append(package)

    for package in resolved.values():
        visit(package)
    return ordered


def normalize_dependency(value: str) -> str:
    value = value.strip()
    if value.startswith("!"):
        value = value[1:]
    return re.split(r"[<>=~]", value, maxsplit=1)[0]


def should_ignore_dependency(original: str, normalized: str) -> bool:
    if not normalized:
        return True
    if original.startswith("!"):
        return True
    if normalized.startswith("/"):
        return True
    return False


def package_url_for(mirror: str, branch: str, arch: str, package: ApkPackage) -> str:
    filename = urllib.parse.quote(package.filename)
    return f"{mirror}/{branch}/{package.repo}/{arch}/{filename}"


def write_runtime_defaults(rootfs_dir: Path, mirror: str, branch: str) -> None:
    write_text_if_missing(rootfs_dir / "etc/resolv.conf", "nameserver 1.1.1.1\n")
    write_text_if_missing(
        rootfs_dir / "etc/hosts",
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
    )
    write_text_if_missing(rootfs_dir / "etc/nsswitch.conf", "hosts: files dns\n")
    repositories = rootfs_dir / "etc/apk/repositories"
    repositories.parent.mkdir(parents=True, exist_ok=True)
    repositories.write_text(
        f"{mirror}/{branch}/main\n{mirror}/{branch}/community\n", newline="\n"
    )

    for directory in ("dev", "proc", "sys", "run", "tmp"):
        (rootfs_dir / directory).mkdir(parents=True, exist_ok=True)
    os.chmod(rootfs_dir / "tmp", 0o1777)


def write_text_if_missing(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or not path.read_text().strip():
        path.write_text(contents, newline="\n")


def validate_rootfs(rootfs_dir: Path, *, require_network_packages: bool) -> None:
    required = ["bin/sh", "etc/os-release"]
    if require_network_packages:
        required.extend(
            [
                "usr/bin/curl",
                "usr/bin/git",
                "etc/ssl/certs/ca-certificates.crt",
            ]
        )

    missing = [path for path in required if not rootfs_path_exists(rootfs_dir, path)]
    if missing:
        raise MaterializeError(
            f"{rootfs_dir} is missing required files: " + ", ".join(missing)
        )
    tmp_dir = rootfs_dir / "tmp"
    if not tmp_dir.is_dir():
        raise MaterializeError(f"{rootfs_dir} is missing writable tmp directory")
    if os.name != "nt":
        mode = stat.S_IMODE(tmp_dir.stat().st_mode)
        if mode != 0o1777:
            raise MaterializeError(f"{tmp_dir} must have mode 1777, found {mode:o}")


def rootfs_path_exists(rootfs_dir: Path, relative_path: str) -> bool:
    path = rootfs_dir / relative_path
    if path.exists():
        return True
    if not path.is_symlink():
        return False

    target = os.readlink(path)
    if target.startswith("/"):
        return os.path.lexists(rootfs_dir / target.lstrip("/"))
    return os.path.lexists(path.parent / target)


def download_file(url: str, destination: Path, *, expected_sha256: str | None) -> None:
    if destination.is_file() and expected_sha256:
        if sha256_file(destination) == expected_sha256:
            return
    elif destination.is_file() and expected_sha256 is None:
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(f"{destination.name}.tmp")
    data = fetch_bytes(url)
    if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise MaterializeError(f"sha256 mismatch for {url}")
    tmp.write_bytes(data)
    tmp.replace(destination)


def fetch_text(url: str) -> str:
    return fetch_bytes(url).decode()


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "mcr-fixture-materializer/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except OSError as error:
        raise MaterializeError(f"download failed for {url}: {error}") from error


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_tar(archive_path: Path, destination: Path, *, skip_apk_metadata: bool) -> None:
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive:
            rel = safe_member_path(member.name)
            if rel is None:
                continue
            if skip_apk_metadata and rel.parts and rel.parts[0].startswith("."):
                continue
            extract_member(archive, member, destination, rel)


def safe_member_path(name: str) -> PurePosixPath | None:
    normalized = PurePosixPath(name)
    parts = [part for part in normalized.parts if part not in ("", ".")]
    if not parts:
        return None
    if parts[0] == "/":
        parts = parts[1:]
    if any(part == ".." for part in parts):
        raise MaterializeError(f"archive member escapes rootfs: {name}")
    return PurePosixPath(*parts)


def extract_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, root: Path, rel: PurePosixPath
) -> None:
    target = root.joinpath(*rel.parts)
    ensure_no_symlink_parent(root, target.parent)

    if member.isdir():
        target.mkdir(parents=True, exist_ok=True)
        chmod_best_effort(target, member.mode)
        return

    if member.issym():
        target.parent.mkdir(parents=True, exist_ok=True)
        remove_existing(target)
        os.symlink(member.linkname, target)
        return

    if member.islnk():
        link_rel = safe_member_path(member.linkname)
        if link_rel is None:
            return
        source = root.joinpath(*link_rel.parts)
        ensure_no_symlink_parent(root, source.parent)
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            remove_existing(target)
            try:
                os.link(source, target)
            except OSError:
                shutil.copy2(source, target)
        return

    if member.isfile():
        extracted = archive.extractfile(member)
        if extracted is None:
            raise MaterializeError(f"archive member has no file payload: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        remove_existing(target)
        with target.open("wb") as output:
            shutil.copyfileobj(extracted, output)
        chmod_best_effort(target, member.mode)
        return

    if member.ischr() or member.isblk() or member.isfifo():
        target.parent.mkdir(parents=True, exist_ok=True)
        return

    raise MaterializeError(f"unsupported archive member type: {member.name}")


def ensure_no_symlink_parent(root: Path, parent: Path) -> None:
    try:
        rel = parent.relative_to(root)
    except ValueError as error:
        raise MaterializeError(f"refusing to write outside rootfs: {parent}") from error

    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise MaterializeError(f"refusing to write through symlink parent: {current}")


def remove_existing(path: Path) -> None:
    if os.path.lexists(path):
        if path.is_dir() and not path.is_symlink():
            remove_tree(path)
        else:
            path.unlink()


def remove_tree(path: Path) -> None:
    def onexc(function, target, error):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            function(target)
        except OSError as retry_error:
            raise retry_error from error

    try:
        shutil.rmtree(path, onexc=onexc)
    except TypeError:
        shutil.rmtree(path, onerror=lambda function, target, _: onexc(function, target, _))


def chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, stat.S_IMODE(mode))
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
