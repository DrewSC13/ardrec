"""Archivo inmutable de magnitudes exactas, separado del estado operacional."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid

from ardrec.contracts import (
    ContractError, dump_magnitude, parse_magnitude,
)
from .codec import StorageError, require

FORMAT = 'ardrec-magnitude-1'
MAX_RECORD_BYTES = 8192


def encode_record(value):
    """Conservar racionales de 256 bits y el motivo explícito de ND."""
    try:
        raw = json.dumps({'format': FORMAT, 'magnitude': dump_magnitude(value)},
                         ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                         allow_nan=False).encode('ascii')
    except (ContractError, TypeError, ValueError, RecursionError) as error:
        raise StorageError('magnitude_invalid') from error
    require(len(raw) <= MAX_RECORD_BYTES, 'object_too_large')
    return raw


def decode_record(raw):
    """Validar formato y campos sin corregir valores inválidos."""
    require(type(raw) is bytes and len(raw) <= MAX_RECORD_BYTES, 'object_too_large')

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_key')
            value[key] = item
        return value

    def reject(_):
        raise StorageError('noninteger_number')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_float=reject, parse_constant=reject)
        require(type(value) is dict and set(value) == {'format', 'magnitude'}, 'fields_invalid')
        require(value['format'] == FORMAT, 'version_incompatible')
        return parse_magnitude(value['magnitude'])
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        if isinstance(error, StorageError):
            raise
        raise StorageError('magnitude_invalid') from error


class MagnitudeArchive:
    """Un escritor local; cada referencia designa bytes completos e inmutables."""

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
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=parent)
                    os.close(parent)
                    parent = child
                if create:
                    os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
                    os.fsync(parent)
                self._root = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=parent)
                self._fds.append(self._root)
            finally:
                os.close(parent)
            info = os.fstat(self._root)
            require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'directory_not_private')
            flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            self._lock = os.open('LOCK', flags, 0o600, dir_fd=self._root)
            self._fds.append(self._lock)
            self._regular(self._lock)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise StorageError('writer_busy') from error
            if create:
                os.fsync(self._lock)
            os.fsync(self._root)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _regular(fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'file_invalid')
        return info

    def _check(self):
        require(not self._closed and not self._poisoned, 'session_unavailable')
        require(os.getpid() == self._pid and threading.get_ident() == self._thread, 'session_owner')
        for fd, info in ((self._root, os.stat(self._path, follow_symlinks=False)),
                         (self._lock, os.stat('LOCK', dir_fd=self._root, follow_symlinks=False))):
            original = os.fstat(fd)
            require((original.st_dev, original.st_ino) == (info.st_dev, info.st_ino), 'session_replaced')
        root = os.fstat(self._root)
        require(root.st_uid == os.geteuid() and root.st_mode & 0o077 == 0, 'directory_not_private')
        self._regular(self._lock)

    def _read(self, reference):
        require(type(reference) is str and re.fullmatch('[0-9a-f]{64}', reference) is not None,
                'hash_invalid')
        fd = os.open(reference + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self._root)
        try:
            info = self._regular(fd)
            require(info.st_size <= MAX_RECORD_BYTES, 'object_too_large')
            raw = bytearray()
            while True:
                chunk = os.read(fd, min(4096, MAX_RECORD_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= MAX_RECORD_BYTES, 'object_too_large')
            require(len(raw) == info.st_size, 'file_changed')
            raw = bytes(raw)
            require(hashlib.sha256(raw).hexdigest() == reference, 'object_hash_mismatch')
            value = decode_record(raw)
            require(encode_record(value) == raw, 'noncanonical_object')
            # Una recuperación no confirma durabilidad antes de sincronizar.
            os.fsync(fd)
            os.fsync(self._root)
            return value, raw
        finally:
            os.close(fd)

    def read(self, reference):
        """Leer únicamente el objeto exacto solicitado y verificar su integridad."""
        self._check()
        try:
            return self._read(reference)[0]
        except BaseException:
            self._poisoned = True
            raise

    def write(self, value):
        """Publicar un objeto completo; la referencia no confirma una generación global."""
        self._check()
        raw = encode_record(value)
        reference = hashlib.sha256(raw).hexdigest()
        target = reference + '.json'
        temporary = '.pending-' + uuid.uuid4().hex
        fd = None
        try:
            try:
                os.stat(target, dir_fd=self._root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                require(self._read(reference)[1] == raw, 'object_conflict')
                return reference
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self._root)
            self._fault('after_temp_create')
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                require(count > 0, 'short_write')
                offset += count
            self._fault('after_write')
            os.fsync(fd)
            self._fault('after_file_sync')
            os.close(fd)
            fd = None
            self._fault('before_replace')
            # El bloqueo excluye otros escritores cooperativos durante la publicación.
            try:
                os.stat(target, dir_fd=self._root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise StorageError('object_conflict')
            os.rename(temporary, target, src_dir_fd=self._root, dst_dir_fd=self._root)
            self._fault('after_replace')
            os.fsync(self._root)
            self._fault('after_directory_sync')
            return reference
        except BaseException:
            self._poisoned = True
            raise
        finally:
            if fd is not None:
                os.close(fd)
            # Los temporales de una interrupción se conservan como objetos sin autoridad.

    def close(self):
        """Liberar descriptores sin modificar objetos ni eliminar restos de fallos."""
        if not self._closed:
            for fd in reversed(self._fds):
                os.close(fd)
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
