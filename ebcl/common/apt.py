""" APT helper functions """
from abc import ABC, abstractmethod
from collections import defaultdict
import glob
import gzip
import logging
import lzma
import os
from pathlib import Path
import tempfile
import time

from types import NotImplementedType
from typing import Optional, Any, Tuple
from urllib.parse import urlparse

import requests

from . import get_cache_folder
from .deb import Package
from .fake import Fake
from .version import parse_depends, VersionDepends, PackageRelation, Version

from .types.cpu_arch import CpuArch

from typing_extensions import Self


class AptCache:
    _cache_dir: Path

    def __init__(self, cache_dir: Path):
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_local(self, path: Path) -> bytes:
        with path.open("rb") as f:
            return f.read()

    def get_as_str(self, url: str, encoding="utf-8") -> str | None:
        data = self.get(url)
        if not data:
            return None
        return data.decode(encoding, errors="ignore")

    def get(self, url: str) -> bytes | None:
        """ Download the given url. """

        parsed_url = urlparse(url)
        if parsed_url.scheme == "file":
            return self._get_local(Path(parsed_url.path))

        # Check for cached data.
        cache_file_path = self._cache_dir / parsed_url.path.replace('/', '_')

        cache_files = glob.glob(f'{cache_file_path}_*')
        if cache_files:
            cache_files.sort()
            cache_file = cache_files[-1]

            logging.debug('Cache file found for %s: %s', url, cache_file)

            ts_str = cache_file.split('_')[-1]
            ts = float(ts_str)
            age = time.time() - ts

            if age > 24 * 60 * 60:
                # older than one day
                logging.debug('Removing outdated cache file %s', cache_file)
                try:
                    os.remove(cache_file)
                except Exception as e:
                    logging.error(
                        'Removing old cache file %s failed! %s', cache_file, e)
            else:
                # Read cached data
                logging.debug('Reading cached data from %s...', cache_file)
                try:
                    return self._get_local(Path(cache_file))
                except Exception as e:
                    logging.error(
                        'Reading cached data from %s failed! %s', cache_file, e)
        else:
            logging.info('No cache file found for %s', url)

        # Download the url
        try:
            result = requests.get(url, allow_redirects=True, timeout=10)
        except Exception as e:
            logging.error('Downloading %s failed! %s', url, e)
            return None

        if result.status_code != 200:
            return None

        # Cache the file
        save_file = f'{cache_file_path}_{time.time()}'

        file_bytes: bytes = b''
        with open(save_file, 'wb') as f:
            for chunk in result.iter_content(chunk_size=512 * 1024):
                if chunk:  # filter out keep-alive new chunks
                    file_bytes += chunk
                    f.write(chunk)

        return file_bytes


class DebMetadata:
    stanzas: list[dict[str, str]]

    def __init__(self, content: str, multi_stanza=True) -> None:
        self.stanzas = []
        cur_stanza: dict[str, str] | None = None
        cur_key: str | None = None
        for line in content.splitlines():
            # Skip pgp signature
            if line == "-----BEGIN PGP SIGNED MESSAGE-----":
                continue
            elif line == "-----BEGIN PGP SIGNATURE-----":
                break

            if not line.strip():
                cur_key = None
                if multi_stanza:
                    cur_stanza = None
                continue
            elif cur_stanza is None:
                cur_stanza = {}
                self.stanzas.append(cur_stanza)
                cur_key = None

            # continuation line
            if (line.startswith(" ") or line.startswith("\t")) and cur_key:
                cur_stanza[cur_key] += "\n" + line
            elif ":" in line:
                key, value = map(str.strip, line.split(':', 1))
                # Keys should be reqad case-insensitve, so store them lowered
                key = key.lower()
                cur_key = key
                cur_stanza[key] = value


class DebPackagesInfo:
    RELATIONS = [
        ("depends", PackageRelation.DEPENDS),
        ("pre-depends", PackageRelation.PRE_DEPENS),
        ("recommends", PackageRelation.RECOMMENDS),
        ("suggests", PackageRelation.SUGGESTS),
        ("enhances", PackageRelation.ENHANCES),
        ("breaks", PackageRelation.BREAKS),
        ("conflicts", PackageRelation.CONFLICTS)
    ]
    _arch: CpuArch
    packages: list[Package]

    def __init__(self, content: str, arch: CpuArch) -> None:
        self._arch = arch
        meta = DebMetadata(content)
        self.packages = []
        for stanza in meta.stanzas:
            pkg = Package(stanza.get("package", ""), arch, "filled-later")
            pkg.file_url = stanza.get("filename")
            pkg.version = Version(stanza.get("version", ""))

            for key, rel in self.RELATIONS:
                value = stanza.get(key, None)
                if value is None:
                    continue
                pkg.set_relation(
                    rel,
                    self._parse_relation(pkg.name, value, rel)
                )
            self.packages.append(pkg)

    def _parse_relation(
        self, name: str, relation: str, package_relation: PackageRelation
    ) -> list[list[VersionDepends]]:
        """ Parse relation string from stanza. """
        deps: list[list[VersionDepends]] = []

        for rel in relation.split(','):
            dep = parse_depends(rel.strip(), self._arch, package_relation)
            if dep:
                deps.append(dep)
            else:
                logging.error('Invalid package relation %s to %s for %s.',
                              rel.strip(), package_relation, name)

        return deps


class DebReleaseInfo:
    CHECKSUM_KEYS = ["md5sum", "sha1", "sha256", "sha512"]
    _data: dict[str, str]
    _hashes: dict[str, list[tuple[str, int, str]]]

    def __init__(self, content: str) -> None:
        self._data = {}
        self._hashes = defaultdict(list)
        self._data = DebMetadata(content, multi_stanza=False).stanzas[0]

        for hash_key in self.CHECKSUM_KEYS:
            if hash_key in self._data:
                self._hashes[hash_key] = []
                for line in self._data[hash_key].splitlines():
                    parts = line.split()
                    if len(parts) == 3:
                        self._hashes[hash_key].append((parts[0], int(parts[1]), parts[2]))

    @property
    def components(self) -> list[str]:
        return self._data.get("components", "").split()

    @property
    def hashes(self) -> dict[str, list[tuple[str, int, str]]]:
        return self._hashes


class AptRepo(ABC):
    _url: str
    _arch: CpuArch
    _packages: dict[str, list[Package]]

    def __init__(self, url: str, arch: CpuArch) -> None:
        self._url = url
        self._arch = arch
        self._packages = defaultdict(list)

    @property
    @abstractmethod
    def _meta_path(self) -> str:
        raise NotImplementedError()

    @property
    def id(self) -> str:
        return f'{self._url}_{self._get_id()}'

    @property
    @abstractmethod
    def sources_entry(self) -> str:
        raise NotImplementedError()

    @property
    def url(self) -> str:
        return self._url

    @property
    def arch(self) -> CpuArch:
        return self._arch

    @property
    def packages(self) -> dict[str, list[Package]]:
        return self._packages

    @property
    def loaded(self) -> bool:
        return bool(self._packages)

    def __repr__(self) -> str:
        return f"AptDebRepo<url: {self.url}, {self._get_repr()}>"

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other) -> bool | NotImplementedType:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._arch == other._arch and self._url == other._url and self._is_eq(other)

    @abstractmethod
    def _get_id(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def _get_repr(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def _is_eq(self, other: Self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def _parse_release_file(self, cache: AptCache, releaseInfo: DebReleaseInfo) -> None:
        raise NotImplementedError()

    def load_index(self, cache: AptCache) -> None:
        release_file = cache.get_as_str(f"{self._url}/{self._meta_path}/InRelease")
        if release_file:
            self._parse_release_file(cache, DebReleaseInfo(release_file))

    def _parse_packages(self, cache: AptCache, path: str) -> None:
        data: bytes | None = cache.get(f"{self._url}/{self._meta_path}/{path}")
        if not data:
            logging.error("Unable to fetch %s (%s)", path, self)
            return

        if path.endswith('xz'):
            data = lzma.decompress(data)
        elif path.endswith('gz'):
            data = gzip.decompress(data)
        else:
            logging.error('Unkown compression of index %s (%s)! Cannot parse index.', path, self)
            return
        content = data.decode(encoding="utf-8", errors="ignore")
        packages_info = DebPackagesInfo(content, self._arch)
        for package in packages_info.packages:
            package.repo = self.id
            package.file_url = f"{self._url}/{package.file_url}"
            self._packages[package.name].append(package)


class AptFlatRepo(AptRepo):
    _directory: str

    def __init__(
        self,
        url: str,
        directory: str,
        arch: CpuArch
    ) -> None:
        super().__init__(url, arch)
        self._directory = directory

    @property
    def _meta_path(self) -> str:
        return f'{self._directory}'

    @property
    def sources_entry(self) -> str:
        return f"deb {self._url} {self._directory}/"

    def _is_eq(self, other: Self) -> bool:
        return self._directory == other._directory

    def _get_id(self):
        return f'{self._directory}'

    def _get_repr(self):
        return f"directory: {self._directory}"

    def _parse_release_file(self, cache: AptCache, releaseInfo: DebReleaseInfo) -> None:
        name: list[str] = [
            'Packages.xz',
            'Packages.gz'
        ]
        for hash in releaseInfo.hashes.values():
            for file in hash:
                if file[2] in name:
                    self._parse_packages(cache, file[2])


class AptDebRepo(AptRepo):
    _dist: str
    _components: set[str]

    def __init__(
        self,
        url: str,
        dist: str,
        components: list[str],
        arch: CpuArch
    ) -> None:
        super().__init__(url, arch)
        self._dist = dist
        self._components = set(components)

    @property
    def _meta_path(self) -> str:
        return f'dists/{self._dist}'

    @property
    def sources_entry(self) -> str:
        return f"deb {self._url} {self._dist} {' '.join(self._components)}"

    @property
    def dist(self) -> str:
        return self._dist

    @property
    def components(self) -> set[str]:
        return self._components

    def _get_id(self):
        return f'{self._dist}_{"_".join(self._components)}'

    def _get_repr(self):
        return f"dist: {self._dist}, components: {' '.join(self._components)}"

    def _is_eq(self, other: Self) -> bool:
        return self._dist == other._dist \
            and self._components == other._components

    def _find_package_file(self, releaseInfo: DebReleaseInfo, component: str) -> str | None:
        name = [
            f'{component}/binary-{self._arch}/Packages.xz',
            f'{component}/binary-{self._arch}/Packages.gz'
        ]
        for hash in releaseInfo.hashes.values():
            for file in hash:
                if file[2] in name:
                    return file[2]
        return None

    def _parse_release_file(self, cache: AptCache, releaseInfo: DebReleaseInfo) -> None:
        for component in self._components:
            if component not in releaseInfo.components:
                logging.warning('No package index for component %s found!', component)
                continue
            package_file = self._find_package_file(releaseInfo, component)
            if not package_file:
                logging.warning('No package index for component %s found!', component)
            else:
                self._parse_packages(cache, package_file)


class Apt:
    """ Get packages from apt repositories. """

    _repo: AptRepo
    _cache: AptCache

    @classmethod
    def from_config(cls, repo_config: dict[str, Any], arch: CpuArch):
        """ Get an apt repositry for a config entry. """
        if 'apt_repo' not in repo_config:
            return None

        repo: AptRepo
        if 'distro' in repo_config:
            repo = AptDebRepo(
                url=repo_config['apt_repo'],
                dist=repo_config['distro'],
                components=repo_config.get('components', 'main'),
                arch=arch
            )
        elif 'directory' in repo_config:
            repo = AptFlatRepo(
                url=repo_config['apt_repo'],
                directory=repo_config['directory'],
                arch=arch
            )
        else:
            return None

        return cls(
            repo=repo,
            key_url=repo_config.get('key', None),
            key_gpg=repo_config.get('gpg', None)
        )

    @classmethod
    def ebcl(cls, arch: CpuArch, dist: str, release: str, components: list[str]) -> Self:
        """ Get the EBcL apt repo. """
        url = os.environ.get('EBCL_REPO_URL', 'http://linux.elektrobit.com/eb-corbos-linux')
        release = os.environ.get('EBCL_VERSION', release)
        key = os.environ.get('EBCL_REPO_KEY', 'file:///build/keys/elektrobit.pub')
        gpg = os.environ.get('EBCL_REPO_GPG', '/etc/apt/trusted.gpg.d/elektrobit.gpg')
        return cls(
            repo=AptDebRepo(
                url=f'{url}/{release}',
                dist=dist,
                components=components,
                arch=arch
            ),
            key_url=key,
            key_gpg=gpg
        )

    @classmethod
    def ebcl_apt(cls, arch: CpuArch, release: str = '1.4') -> Self:
        """ Get the EBcL apt repo. """
        return cls.ebcl(arch, "ebcl", release, ['prod', 'dev'])

    @classmethod
    def ebcl_primary_repo(cls, arch: CpuArch, release: str = '1.4') -> Self:
        """ Get the EBcL apt repo. """
        return cls.ebcl(arch, "jammy", release, ['main'])

    def __init__(
        self,
        repo: AptRepo,
        key_url: str | None = None,
        key_gpg: str | None = None,
        state_folder: str | None = None
    ) -> None:
        self._repo = repo
        self._cache = AptCache(Path(state_folder and state_folder or get_cache_folder("apt")))

        self.key_url: Optional[str] = key_url
        self.key_gpg: Optional[str] = key_gpg

        if not key_gpg and 'ubuntu.com/ubuntu' in self._repo.url:
            self.key_gpg = '/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg'
            logging.info('Using default Ubuntu key %s for %s.',
                         self.key_gpg, self._repo.url)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Apt):
            return False

        return self._repo == value._repo

    @property
    def id(self) -> str:
        """ Get a unique identifier for this repo. """
        return self._repo.id

    @property
    def url(self) -> str:
        return self._repo.url

    @property
    def arch(self) -> CpuArch:
        return self._repo.arch

    @property
    def deb_repo(self) -> AptDebRepo | None:
        return isinstance(self._repo, AptDebRepo) and self._repo or None

    @property
    def repo(self) -> AptRepo:
        return self._repo

    @property
    def sources_entry(self) -> str:
        return self._repo.sources_entry

    def _load_packages(self) -> None:
        """ Download repo metadata and parse package indices. """
        if self._repo.loaded:
            return
        self._repo.load_index(self._cache)

        logging.info('Repo %s provides %s packages.',
                     self._repo, len(self._repo.packages))

    def find_package(self, package_name: str) -> Optional[list[Package]]:
        """ Find a binary deb package. """
        self._load_packages()

        if package_name in self._repo.packages:
            return self._repo.packages[package_name]
        else:
            return None

    def __str__(self) -> str:
        return f'Apt<{self._repo}, key: {self.key_url}, gpg: {self.key_gpg}>'

    def __repr__(self) -> str:
        return self.__str__()

    def get_key(self) -> Optional[str]:
        """ Get key for this repo. """
        # TODO: test
        if not self.key_url:
            return None

        key_url = self.key_url
        if key_url.startswith('file://'):
            key_url = key_url[7:]

        contents = None

        if os.path.isfile(key_url):
            # handle local file
            logging.info('Reading key for %s from %s', self, key_url)
            with open(key_url, encoding='utf8') as f:
                contents = f.read()
        elif key_url.startswith('http://') or key_url.startswith('https://'):
            # download key
            logging.info('Downloading key for %s from %s', self, key_url)
            data = self._cache.get(key_url)
            if data:
                contents = data.decode(encoding='utf8', errors='ignore')
            else:
                logging.error(
                    'Download of key %s for %s failed!', key_url, self)
        else:
            logging.error(
                'Unknown key url %s, cannot download key!', self.key_url)
            return None

        return contents

    def get_key_files(
            self, output_folder: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """ Get gpg key file for repo key. """
        # TODO: test
        if not self.key_url:
            return (None, self.key_gpg)

        contents = self.get_key()
        if not contents:
            return (None, self.key_gpg)

        key_pub_file = tempfile.mktemp(suffix=".pub", dir=output_folder)
        key_gpg_file = tempfile.mktemp(suffix=".gpg", dir=output_folder)

        try:
            with open(key_pub_file, 'w', encoding='utf8') as f:
                f.write(contents)
        except Exception as e:
            logging.error('Writing pub key of %s to %s failed! %s',
                          self, key_pub_file, e)
            return (None, self.key_gpg)

        if not self.key_gpg:
            fake = Fake()
            try:
                fake.run_cmd(
                    f'cat {key_pub_file} | gpg --dearmor > {key_gpg_file}')
            except Exception as e:
                logging.error('Dearmoring key %s of %s as %s failed! %s',
                              key_pub_file, self, key_gpg_file, e)
                return (key_pub_file, None)
        else:
            key_gpg_file = self.key_gpg

        return (key_pub_file, key_gpg_file)
