"""Archivo Linux de proyecciones y referencias; no publica estado global."""
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import threading
import uuid

from ardrec.analytical import decode_projection, encode_projection
from ardrec.analytical_references import (
    MAX_BYTES, MAX_OBJECTS, ROLES, ResolvedReferences, canonical, decode,
    fields, fingerprint, resolve_references,
)
from .codec import StorageError, require

FORMAT = 'ardrec-analytical-archive-1'
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ArchivedReferences:
    """Conjunto recuperado; su integridad no certifica autoridad ni semántica."""
    snapshot_sha256: str
    projections: tuple
    references: ResolvedReferences


class AnalyticalArchive:
    """Un escritor cooperativo; sin HEAD, búsqueda de la última generación o borrado."""

    def __init__(self, path, *, create=False, fault=None):
        self._fds = []
        self._closed = False
        self._poisoned = False
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._fault = fault or (lambda point: None)
        self._path = Path(os.path.abspath(path))
        try:
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                parts = self._path.parts[1:]
                require(bool(parts), 'root_forbidden')
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                if create:
                    os.mkdir(parts[-1], 0o700, dir_fd=parent)
                    os.fsync(parent)
                self._root = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                self._fds.append(self._root)
            finally:
                os.close(parent)
            self._directory(self._root)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            self._lock = os.open('LOCK', flags, 0o600, dir_fd=self._root)
            self._fds.append(self._lock)
            self._regular(self._lock)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise StorageError('writer_busy') from error
            os.fsync(self._lock)
            os.fsync(self._root)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _directory(fd):
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o077 == 0, 'directory_not_private')
        return info

    @staticmethod
    def _regular(fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'file_invalid')
        return info

    def _check(self):
        require(not self._closed and not self._poisoned, 'session_unavailable')
        require(os.getpid() == self._pid and threading.get_ident() == self._thread, 'session_owner')
        try:
            for fd, actual in ((self._root, os.stat(self._path, follow_symlinks=False)),
                               (self._lock, os.stat('LOCK', dir_fd=self._root, follow_symlinks=False))):
                opened = os.fstat(fd)
                require((actual.st_dev, actual.st_ino) == (opened.st_dev, opened.st_ino), 'session_replaced')
            self._directory(self._root)
            self._regular(self._lock)
        except BaseException:
            self._poisoned = True
            raise

    @staticmethod
    def _read(folder, reference):
        fingerprint(reference)
        fd = os.open(reference + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
        try:
            before = AnalyticalArchive._regular(fd)
            require(before.st_size <= MAX_BYTES, 'object_too_large')
            raw = bytearray()
            while True:
                chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= MAX_BYTES, 'object_too_large')
            after = AnalyticalArchive._regular(fd)
            require(len(raw) == before.st_size == after.st_size
                    and before.st_mtime_ns == after.st_mtime_ns
                    and before.st_ctime_ns == after.st_ctime_ns, 'file_changed')
            raw = bytes(raw)
            require(digest(raw) == reference, 'object_hash_mismatch')
            os.fsync(fd)
            return raw
        finally:
            os.close(fd)

    def _load(self, snapshot_sha256):
        fingerprint(snapshot_sha256)
        folder = os.open(snapshot_sha256, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root)
        try:
            self._directory(folder)
            total = 0
            def read(reference):
                nonlocal total
                raw = self._read(folder, reference)
                total += len(raw)
                require(total <= MAX_ARCHIVE_BYTES, 'archive_too_large')
                return raw
            metadata = decode(read(snapshot_sha256))
            fields(metadata, ('format', 'manifest_sha256', 'projection_sha256'))
            require(metadata['format'] == FORMAT, 'archive_version_incompatible')
            fingerprint(metadata['manifest_sha256'])
            ids = metadata['projection_sha256']
            require(type(ids) is list and 0 < len(ids) <= MAX_OBJECTS // len(ROLES), 'projections_invalid')
            for reference in ids:
                fingerprint(reference)
            projections = tuple(decode_projection(read(reference)) for reference in ids)
            # El códec de proyecciones admite entradas equivalentes: aquí exigir bytes canónicos.
            for reference, projection in zip(ids, projections):
                require(digest(encode_projection(projection)) == reference, 'noncanonical_projection')
            resolved = resolve_references(projections, read(metadata['manifest_sha256']),
                                          expected_manifest_sha256=metadata['manifest_sha256'], load_object=read)
            os.fsync(folder)
            os.fsync(self._root)
            self._check()
            return ArchivedReferences(snapshot_sha256, projections, resolved)
        finally:
            os.close(folder)

    def load(self, snapshot_sha256):
        """Recuperar solo la huella solicitada por el llamador; nunca elegir autoridad."""
        self._check()
        try:
            return self._load(snapshot_sha256)
        except BaseException:
            self._poisoned = True
            raise

    def store(self, projections, manifest_bytes, *, expected_manifest_sha256, load_object):
        """Archivar el conjunto completo antes de devolver su huella externa.

        Un fallo no confirma el resultado; reabrir y recuperar por la huella conocida.
        La publicación global, el origen confiable de esa huella y las guardas son externos.
        """
        self._check()
        # Validar y capturar bytes antes de crear el directorio temporal.
        resolved = resolve_references(projections, manifest_bytes,
                                      expected_manifest_sha256=expected_manifest_sha256, load_object=load_object)
        projection_bytes = tuple(encode_projection(p) for p in projections)
        projection_ids = [digest(raw) for raw in projection_bytes]
        metadata = canonical({'format': FORMAT, 'manifest_sha256': expected_manifest_sha256,
                              'projection_sha256': projection_ids})
        snapshot = digest(metadata)
        blobs = {}
        for raw in (metadata, manifest_bytes, *projection_bytes, *resolved.object_bytes):
            reference = digest(raw)
            require(reference not in blobs or blobs[reference] == raw, 'object_collision')
            blobs[reference] = raw
        require(sum(map(len, blobs.values())) <= MAX_ARCHIVE_BYTES, 'archive_too_large')
        self._check()
        folder = None
        try:
            try:
                os.stat(snapshot, dir_fd=self._root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                previous = self._load(snapshot)
                require(previous.projections == projections and previous.references == resolved, 'archive_conflict')
                return snapshot
            temporary = '.pending-' + uuid.uuid4().hex
            os.mkdir(temporary, 0o700, dir_fd=self._root)
            folder = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root)
            self._directory(folder)
            self._fault('directory_created')
            for reference, raw in sorted(blobs.items()):
                fd = os.open(reference + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=folder)
                try:
                    offset = 0
                    while offset < len(raw):
                        count = os.write(fd, raw[offset:])
                        require(count > 0, 'write_stalled')
                        offset += count
                        self._fault('object_write')
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
                    self._fault('object_synced')
                finally:
                    os.close(fd)
            os.fsync(folder)
            self._fault('snapshot_synced')
            self._check()
            self._fault('before_install')
            # Todos los escritores admitidos usan LOCK. Un conjunto existente nunca se sustituye.
            try:
                os.stat(snapshot, dir_fd=self._root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise StorageError('archive_conflict')
            os.rename(temporary, snapshot, src_dir_fd=self._root, dst_dir_fd=self._root)
            self._fault('after_install')
            os.fsync(self._root)
            self._fault('root_synced')
            self._check()
            return snapshot
        except BaseException:
            self._poisoned = True
            raise
        finally:
            if folder is not None:
                os.close(folder)
            # Conservar restos para diagnóstico; nunca promoverlos durante la recuperación.

    def close(self):
        if not self._closed:
            for fd in reversed(self._fds):
                os.close(fd)
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
