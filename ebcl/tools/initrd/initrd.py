#!/usr/bin/env python
""" EBcL initrd generator. """
import argparse
import glob
import logging
import os
import queue
import shutil
import tempfile

from io import BufferedWriter
from pathlib import Path
from typing import Tuple, Any, Optional

from ebcl.common import init_logging, promo, log_exception
from ebcl.common.apt import Apt
from ebcl.common.config import load_yaml
from ebcl.common.fake import Fake
from ebcl.common.files import Files, EnvironmentType, parse_files, reslove_file
from ebcl.common.proxy import Proxy
from ebcl.common.templates import render_template
from ebcl.common.version import VersionDepends, parse_package_config, parse_package


class InitrdGenerator:
    """ EBcL initrd generator. """

    # config file
    config: Path
    # config values
    modules: list[str]
    modules_packages: list[VersionDepends]
    root_device: str
    devices: list[dict[str, str]]
    files: list[dict[str, Any]]
    kversion: Optional[str]
    arch: str
    template: Optional[str]
    modules_folder: Optional[str]
    use_ebcl_apt: bool
    initrd_tarball: Optional[str]
    # use fakeroot or sudo
    fakeroot: bool
    # name of busybox package
    busybox: VersionDepends
    # name of the initrd image file
    initrd_name: str
    # name of the initrd image
    name: str
    # out and tmp folders
    target_dir: str
    image_path: str
    # proxy
    proxy: Proxy
    # fakeroot helper
    fake: Fake
    # files helper
    fh: Files
    # env for files helper
    env: EnvironmentType

    @log_exception(call_exit=True)
    def __init__(self, config_file: str):
        """ Parse the yaml config file.

        Args:
            config_file (Path): Path to the yaml config file.
        """
        config = load_yaml(config_file)

        self.config = Path(config_file)

        config_dir = os.path.dirname(config_file)

        self.modules = config.get('modules', [])
        self.root_device = config.get('root_device', '/dev/vda1')
        self.devices = config.get('devices', [])
        self.files = parse_files(
            config.get('files', []),
            relative_base_dir=config_dir)
        self.kversion = config.get('kversion', None)
        self.apt_repos = config.get('apt_repos', None)
        self.template = config.get('template', None)
        self.modules_folder = config.get('modules_folder', None)

        self.initrd_name = config.get('initrd_name', 'initrd.img')
        self.name = config.get('name', 'root')

        self.fakeroot = config.get('fakeroot', False)
        self.env = EnvironmentType.FAKEROOT
        if not self.fakeroot:
            self.env = EnvironmentType.CHROOT

        self.arch = config.get('arch', 'arm64')

        self.modules_packages = parse_package_config(
            config.get('modules_packages', []), self.arch)

        busybox = parse_package(config.get(
            'busybox', 'busybox-static'), self.arch)
        if busybox:
            logging.debug('Busybox package: %s', busybox)
            self.busybox = busybox
        else:
            logging.critical('Parsing of busybox %s failed!',
                             config.get('busybox', 'busybox-static'))
            # raise exception
            assert busybox

        kernel = parse_package(config.get('kernel', None), self.arch)
        if kernel:
            self.modules_packages.append(kernel)

        self.proxy = Proxy()
        self.proxy.parse_apt_repos(
            apt_repos=config.get('apt_repos', None),
            arch=self.arch,
            ebcl_version=config.get('ebcl_version', None)
        )

        self.use_ebcl_apt = config.get('use_ebcl_apt', False)
        if self.use_ebcl_apt:
            ebcl_apt = Apt.ebcl_apt(self.arch)
            self.proxy.add_apt(ebcl_apt)

        self.fake = Fake()
        self.fh = Files(self.fake)

        self.initrd_tarball = config.get('initrd_tarball', None)
        if isinstance(self.initrd_tarball, dict):
            self.initrd_tarball = reslove_file(
                file=self.initrd_tarball['name'],
                file_base_dir=self.initrd_tarball.get('base_dir', None),
                relative_base_dir=config_dir
            )

    def _run_chroot(self, cmd: str) -> Tuple[str, str, int]:
        """ Run command in chroot target environment. """
        if self.fakeroot:
            return self.fake.run_chroot(cmd, self.target_dir)
        else:
            return self.fake.run_sudo_chroot(cmd, self.target_dir)

    def _run_root(
        self,
        cmd: str,
        cwd: Optional[str] = None,
        stdout: Optional[BufferedWriter] = None,
        check=True
    ) -> Tuple[Optional[str], str, int]:
        """ Run command as root. """
        if self.fakeroot:
            return self.fake.run(cmd=cmd, cwd=cwd, stdout=stdout, check=check)
        else:
            return self.fake.run_sudo(cmd=cmd, cwd=cwd, stdout=stdout, check=check)

    def install_busybox(self) -> bool:
        """Get busybox and add it to the initrd. """
        package = None

        if not self.busybox:
            logging.critical('No busybox!')
            return False

        self.install_package(self.busybox)

        if not os.path.isfile(os.path.join(self.target_dir, 'bin', 'busybox')):
            logging.critical(
                'Busybox binary is missing! target: %s package: %s', self.target_dir, package)
            return False

        self._run_chroot('/bin/busybox --install -s /bin')

        return True

    def install_package(self, name: str) -> bool:
        """Get package and add it to the initrd. """
        package = None

        package = self.proxy.find_package(name)
        if not package:
            return False

        package = self.proxy.download_package(
            arch=self.arch,
            package=package
        )

        if not package:
            logging.error('Package %s was not found!', package)
            return False

        if package.local_file and \
                os.path.isfile(package.local_file):
            # Download was successful.
            logging.debug('Using package deb %s.', package.local_file)
        else:
            logging.critical('Package download failed!')
            return False

        if not package.local_file:
            logging.critical('Package download failed! %s', package)
            return False

        logging.info('Using package %s (%s).', package, name)

        res = package.extract(self.target_dir)
        if res is None:
            logging.critical(
                'Extraction of package %s (deb: %s) failed!', package, package.local_file)
            return False

        logging.debug('Package %s extracted to %s.', package, res)

        return True

    def find_kernel_version(self, mods_dir: str) -> Optional[str]:
        """ Find the right kernel version. """
        if self.kversion:
            return self.kversion

        kernel_dirs = os.path.abspath(os.path.join(mods_dir, 'lib', 'modules'))
        versions = glob.glob(f'{kernel_dirs}/*')

        if not versions:
            logging.critical(
                'Kernel version not found! mods_dir: %s, kernel_dirs: %s', mods_dir, kernel_dirs)
            return None

        versions.sort()

        return os.path.basename(versions[-1])

    def extract_modules_from_deb(self, mods_dir: str):
        """Extract the required kernel modules from the deb package.

        Args:
            mods_dir (str): Folder containing the modules.
        """
        if not self.modules:
            logging.info('No modules defined.')
            return

        logging.debug('Modules tmp folder: %s.', mods_dir)
        logging.debug('Target tmp folder: %s.', self.target_dir)

        kversion = self.find_kernel_version(mods_dir)
        if not kversion:
            logging.error(
                'Kernel version not found, extracting modules failed!')
            return

        logging.info('Using kernel version %s.', kversion)

        mods_src = os.path.abspath(os.path.join(
            mods_dir, 'lib', 'modules', kversion))

        mods_dep_src = os.path.join(mods_src, 'modules.dep')

        mods_dst = os.path.abspath(os.path.join(
            self.target_dir, 'lib', 'modules', kversion))

        mods_dep_dst = os.path.join(mods_dst, 'modules.dep')

        logging.debug('Mods src: %s', mods_src)
        logging.debug('Mods dst: %s', mods_dst)

        logging.debug('Create modules target...')
        self._run_root(f'mkdir -p {mods_dst}')

        orig_deps: dict[str, list[str]] = {}

        # TODO: fix depends

        if os.path.isfile(mods_dep_src):
            with open(mods_dep_src, encoding='utf8') as f:
                lines = f.readlines()
                for line in lines:
                    parts = line.split(':', maxsplit=1)
                    key = parts[0].strip()
                    values = []
                    if len(parts) > 1:
                        vs = parts[1].strip()
                        if vs:
                            values = [dep.strip()
                                      for dep in vs.split(' ') if dep != '']
                    orig_deps[key] = values

        mq: queue.Queue[str] = queue.Queue(maxsize=-1)

        for module in self.modules:
            mq.put_nowait(module)

        while not mq.empty():
            module = mq.get_nowait()

            logging.info('Processing module %s...', module)

            src = os.path.join(mods_src, module)
            dst = os.path.join(mods_dst, module)
            dst_dir = os.path.dirname(dst)

            logging.debug('Copying module %s to folder %s.', src, dst)

            if not os.path.isfile(src):
                logging.error('Module %s not found.', module)
                continue

            self._run_root(f'mkdir -p {dst_dir}')

            self.fh.copy_file(
                src=src,
                dst=dst,
                environment=self.env,
                uid=0,
                gid=0,
                mode='644'
            )

            # Find module dependencies.
            deps = ''
            if module in orig_deps:
                mdeps = orig_deps[module]
                deps = ' '.join(mdeps)
                for mdep in mdeps:
                    mq.put_nowait(mdep)

            self._run_root(f'echo {module}: {deps} >> {mods_dep_dst}')

    def add_devices(self):
        """ Create device files. """
        self._run_root(f'mkdir -p {self.target_dir}/dev')

        dev_folder = os.path.join(self.target_dir, 'dev')

        for device in self.devices:
            major = (int)(device['major'])
            minor = (int)(device['major'])

            if device['type'] == 'char':
                dev_type = 'c'
                mode = '200'
            elif device['type'] == 'block':
                dev_type = 'b'
                mode = '600'
            else:
                logging.error('Unsupported device type %s for %s',
                              device['type'], device['name'])
                continue

            self._run_root(
                f'mknod -m {mode} {dev_folder}/{device["name"]} {dev_type} {major} {minor}')

            uid = device.get('uid', '0')
            gid = device.get('uid', '0')
            self._run_root(f'chown {uid}:{gid} {dev_folder}/{device["name"]}')

    def copy_files(self, output_path: str):
        """ Copy user-specified files in the initrd. """
        logging.debug('Files: %s', self.files)

        for entry in self.files:
            src = entry.get('source', None)
            if not src:
                logging.error(
                    'Invalid file entry %s, source is missing!', entry)

            if '$$RESULTS$$' in src:
                logging.debug(
                    'Replacing $$RESULTS$$ with %s for file %s.', output_path, entry)
                parts = src.split('$$RESULTS$$/')
                src = os.path.abspath(os.path.join(output_path, parts[-1]))

            src = Path(os.path.abspath(os.path.join(
                self.config.parent, entry['source'])))

            dst = Path(self.target_dir) / entry['destination']

            dst_file = Path(self.target_dir) / entry['destination'] / src.name

            uid = entry.get('uid', '0')
            gid = entry.get('gid', '0')
            mode: str = entry.get('mode', '666')

            logging.debug('Copying %s to %s.', src, dst_file)

            self._run_root(f'mkdir -p {dst}')

            fs = self.fh.copy_file(
                src=str(src),
                dst=dst,
                environment=self.env,
                uid=uid,
                gid=gid,
                mode=mode
            )

            if not fs:
                logging.error('Copying of %s failed!', src)

    @log_exception()
    def create_initrd(self, output_path: str) -> Optional[str]:
        """ Create the initrd image.  """
        self.target_dir = tempfile.mkdtemp()

        self.fh.target_dir = self.target_dir

        image_path = os.path.join(output_path, self.initrd_name)

        logging.info('Installing busybox...')

        success = self.install_busybox()
        if not success:
            return None

        # Create necessary directories
        for dir_name in ['proc', 'sys', 'dev', 'sysroot', 'var', 'bin',
                         'tmp', 'run', 'root', 'usr', 'sbin', 'lib', 'etc']:
            self._run_root(
                f'mkdir -p {os.path.join(self.target_dir, dir_name)}')
            self._run_root(
                f'chown 0:0 {os.path.join(self.target_dir, dir_name)}')

        if self.initrd_tarball:
            if '$$RESULTS$$' in self.initrd_tarball:
                parts = self.initrd_tarball.split('$$RESULTS$$/')
                self.initrd_tarball = os.path.abspath(
                    os.path.join(output_path, parts[-1]))

            logging.info('Extracting initrd tarball...')
            boot_tar_temp = tempfile.mkdtemp()

            logging.debug(
                'Temporary folder for initrd tarball: %s', boot_tar_temp)

            tarball = os.path.join(os.path.dirname(
                self.config), self.initrd_tarball)

            logging.debug('Extracting initrd tarball %s to %s',
                          tarball, boot_tar_temp)

            self.fh.extract_tarball(
                archive=tarball,
                directory=boot_tar_temp
            )

            # Merge deb content and boot tarball
            self.fake.run(cmd=f'rsync -av {boot_tar_temp}/* {self.target_dir}')

            # Delete temporary tar folder
            self.fake.run(f'rm -rf {boot_tar_temp}', check=False)

        mods_dir = None

        if self.modules_folder:
            mods_dir = os.path.abspath(os.path.join(
                self.config.parent, self.modules_folder))
            logging.info('Using modules from folder %s...', mods_dir)
        elif self.modules_packages:
            mods_dir = tempfile.mkdtemp()

            logging.info('Using modules from deb packages...')
            (_debs, _contents, missing) = self.proxy.download_deb_packages(
                packages=self.modules_packages,
                contents=mods_dir
            )

            if missing:
                logging.error('Not found packages: %s', missing)
        elif self.modules:
            logging.error('No module sources defined!')
        else:
            logging.info('No module sources defined.')

        if self.modules:
            # Extract modules directly to the initrd /lib/modules directory
            self.extract_modules_from_deb(mods_dir)
        else:
            logging.info('No modules defined.')

        if mods_dir and not self.modules_folder:
            # Remove mods temporary folder
            shutil.rmtree(mods_dir)

        # Add device nodes
        self.add_devices()

        # Copy files and directories specified in the files
        self.copy_files(output_path=output_path)

        # Create init script
        init_script: Path = Path(self.target_dir) / 'init'

        if self.template is None:
            template = os.path.join(os.path.dirname(__file__), 'init.sh')
        else:
            template = os.path.join(
                os.path.dirname(self.config), self.template)

        params = {
            'root': self.root_device,
            'mods': [m.split("/")[-1] for m in self.modules]
        }

        (_init_file, init_script_content) = render_template(
            template_file=template,
            params=params,
            generated_file_name=f'{self.name}.init.sh',
            results_folder=output_path,
            template_copy_folder=output_path
        )

        if not init_script_content:
            logging.critical('Rendering init script failed!')
            return None

        init_script.write_text(init_script_content)
        os.chmod(init_script, 0o755)

        # Create initrd image
        os.makedirs(os.path.dirname(image_path), exist_ok=True)
        with open(image_path, 'wb') as img:
            self._run_root(
                'find . -print0 | cpio --null -ov --format=newc', cwd=self.target_dir, stdout=img)

        return image_path

    @log_exception()
    def finalize(self):
        """ Finalize output and cleanup. """

        # delete temporary folder
        self._run_root(f' rm -rf {self.target_dir}')


@log_exception(call_exit=True)
def main() -> None:
    """ Main entrypoint of EBcL initrd generator. """
    init_logging()

    logging.info('\n====================\n'
                 'EBcL Initrd Generator\n'
                 '=====================\n')

    parser = argparse.ArgumentParser(
        description='Create an initrd image for Linux.')
    parser.add_argument('config_file', type=str,
                        help='Path to the YAML configuration file')
    parser.add_argument('output', type=str,
                        help='Path to the output directory')

    args = parser.parse_args()

    logging.debug('Running initrd_generator with args %s', args)

    generator = InitrdGenerator(args.config_file)

    image = None

    # Create the initrd.img
    image = generator.create_initrd(args.output)

    generator.finalize()

    if image:
        print(f'Image was written to {image}.')
        promo()
    else:
        print(f'Image build failed!')
        exit(1)


if __name__ == '__main__':
    main()
