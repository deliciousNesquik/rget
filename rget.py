#!/usr/bin/env python3

import argparse
import asyncio
import asyncssh
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

VERSION = "1.2.0"

# Try to import tqdm for progress bars, fall back to simple logging if not available
try:
    from tqdm.asyncio import tqdm_asyncio
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Install 'tqdm' for progress bars: pip install tqdm")


class Config:
    """Configuration class for default values and settings."""

    # Default SSH settings
    DEFAULT_SSH_PORT = 22
    DEFAULT_MAX_CONCURRENT = 5  # Parallel downloads
    DEFAULT_TIMEOUT = 30  # seconds
    DEFAULT_VERBOSE = False
    DEFAULT_MAX_DEPTH = 1

    # Default remote settings (can be overridden)
    DEFAULT_REMOTE_USER = ""
    DEFAULT_REMOTE_HOST = ""
    DEFAULT_REMOTE_DIR = ""


class RemoteFileSyncClient:
    """High-performance async SFTP client for parallel file transfers."""

    def __init__(
            self,
            host: str,
            username: str,
            port: int = 22,
            password: Optional[str] = None,
            ssh_key_path: Optional[str] = None,
            passphrase: Optional[str] = None,
            max_concurrent: int = 5,
            timeout: int = 30,
            max_depth: int = 1,
            accept_new: bool = False,
            ignore_case: bool = False,
            dry_run: bool = False,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.password = password
        self.ssh_key_path = ssh_key_path
        self.passphrase = passphrase
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.max_depth = max_depth
        self.accept_new = accept_new
        self.ignore_case = ignore_case
        self.dry_run = dry_run


    async def connect(self) -> asyncssh.SSHClientConnection:
        """Establish SSH connection with host key verification (accept-new support)."""
        
        ssh_dir = Path.home() / '.ssh'
        known_hosts_path = ssh_dir / 'known_hosts'
        
        # Создаём ~/.ssh если не существует
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        
        connection_kwargs = {
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'connect_timeout': self.timeout,
        }
        
        # === АУТЕНТИФИКАЦИЯ ===
        if self.ssh_key_path:
            self.logger.debug(f"Connecting with SSH key: {self.ssh_key_path}")
            connection_kwargs['client_keys'] = [self.ssh_key_path]
            if self.passphrase:
                connection_kwargs['passphrase'] = self.passphrase
        elif self.password:
            self.logger.debug("Connecting with password")
            connection_kwargs['password'] = self.password
        else:
            self.logger.debug("Attempting to use SSH agent")
        
        # === УПРАВЛЕНИЕ КЛЮЧАМИ ХОСТА ===
        if self.accept_new:
            self.logger.warning(
                "accept-new mode active: New host keys will be accepted and saved to ~/.ssh/known_hosts. "
                "CHANGED keys will be REJECTED (MITM protection)."
            )
            
            # Шаг 1: Попробуем подключиться со строгой проверкой (если known_hosts существует)
            if known_hosts_path.exists():
                connection_kwargs['known_hosts'] = str(known_hosts_path)
                try:
                    conn = await asyncssh.connect(**connection_kwargs)
                    self.logger.debug(f"Connected with verified host key from {known_hosts_path}")
                    return conn
                except asyncssh.HostKeyNotVerifiable as e:
                    error_msg = str(e).lower()
                    # Если ключ не найден — продолжаем к шагу 2
                    if 'is not in the known_hosts file' not in error_msg and \
                    'host key is not trusted' not in error_msg:
                        # Ключ изменился — это MITM!
                        if 'does not match' in error_msg or 'host key has changed' in error_msg:
                            self.logger.critical(
                                "SECURITY ALERT: Server host key CHANGED!\n"
                                "Possible MITM attack or server rekey. Connection ABORTED.\n"
                                f"To reset: ssh-keygen -R [{self.host}]:{self.port}"
                            )
                            raise RuntimeError("Host key changed — possible MITM attack") from e
                        raise
            
            # Шаг 2: Первое подключение — отключаем проверку для получения ключа
            self.logger.warning(f"New host detected: {self.host}:{self.port}. Accepting key...")
            connection_kwargs['known_hosts'] = None
            conn = await asyncssh.connect(**connection_kwargs)
            
            # Шаг 3: Получаем ключ сервера и сохраняем в known_hosts
            server_key = conn.get_server_host_key()
            key_data = server_key.export_public_key().decode('ascii').strip()
            
            # Формат OpenSSH known_hosts:
            #   hostname ssh-rsa AAAAB3NzaC1yc2EAAA...
            #   [hostname]:port ssh-rsa AAAAB3NzaC1yc2EAAA... (для нестандартных портов)
            if self.port == 22:
                host_spec = self.host
            else:
                host_spec = f"[{self.host}]:{self.port}"
            
            # Ключ уже содержит тип + данные: "ssh-rsa AAAAB3NzaC1yc2EAAA..."
            entry = f"{host_spec} {key_data}\n"
            
            # Добавляем запись в known_hosts
            with open(known_hosts_path, 'a', encoding='utf-8') as f:
                f.write(entry)
            known_hosts_path.chmod(0o600)  # Обязательно 600!
            
            self.logger.warning(
                f"New host key accepted and saved to {known_hosts_path}\n"
                f"Host: {host_spec} | Key type: {server_key.get_algorithm()}"
            )
            
            return conn
        
        else:
            # Строгая проверка (поведение по умолчанию)
            if known_hosts_path.exists():
                connection_kwargs['known_hosts'] = str(known_hosts_path)
                self.logger.debug(f"Using strict host key verification with {known_hosts_path}")
            else:
                self.logger.error(
                    "~/.ssh/known_hosts not found. Cannot verify server identity.\n"
                    "Options:\n"
                    "1. Pre-populate: ssh-keyscan -p {port} {host} >> ~/.ssh/known_hosts\n"
                    "2. Use --accept-new for FIRST connection in trusted environments ONLY"
                )
                raise RuntimeError("Host key verification impossible: known_hosts missing")
        
        # Выполняем подключение
        try:
            conn = await asyncssh.connect(**connection_kwargs)
            self.logger.debug(f"Connected to {self.username}@{self.host}:{self.port}")
            return conn
        except asyncssh.HostKeyNotVerifiable as e:
            self.logger.error(
                f"Host key verification failed: {e}\n"
                "Possible causes:\n"
                "• First connection (use --accept-new ONLY in trusted environments)\n"
                "• Server key changed (MITM risk!)\n"
                "• ~/.ssh/known_hosts permissions too open (should be 600)"
            )
            raise
        except Exception as e:
            self.logger.error(f"Connection error: {type(e).__name__}: {e}")
            raise
    
    async def find_files(
            self,
            conn: asyncssh.SSHClientConnection,
            remote_dir: str,
            pattern: str
    ) -> List[str]:
        """Find files on remote server matching pattern."""

        find_cmd = f"find {remote_dir} -maxdepth {self.max_depth} " \
                   f"{'-iname' if self.ignore_case else '-name'} '{pattern}' -type f -size +0c"
        self.logger.debug(f"Searching {find_cmd}")

        try:
            result = await conn.run(find_cmd, check=True, timeout=self.timeout)
            files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

            self.logger.debug(f"Files found: {len(files)}")
            return files

        except asyncssh.ProcessError as e:
            self.logger.error(f"File search error: {e}")
            return []

    async def download_file(
            self,
            sftp: asyncssh.SFTPClient,
            remote_path: str,
            local_path: Path
    ) -> tuple[str, bool]:
        """Download single file via SFTP."""

        filename = os.path.basename(remote_path)

        try:
            await sftp.get(remote_path, str(local_path))

            # Verify file was downloaded and has size
            if local_path.exists() and local_path.stat().st_size > 0:
                self.logger.debug(f"{filename}")
                return filename, True
            else:
                self.logger.error(f"{filename} - the file is empty or not created")
                return filename, False


        except Exception as e:
            if local_path.exists():
                local_path.unlink()  # Удаляем битый файл

            self.logger.error(f"{filename} - {str(e)}")
            return filename, False

    async def download_files_sequential(
            self,
            remote_files: List[str],
            local_dir: Path,
            conn: asyncssh.SSHClientConnection,  # Соединение НЕ закрываем здесь
            master_pbar: Optional[tqdm] = None,
    ) -> dict:
        """Download files sequentially via SINGLE connection (no internal parallelism)."""
        if not remote_files:
            return {'success': [], 'failed': []}

        local_dir.mkdir(parents=True, exist_ok=True)
        success, failed = [], []

        async with conn.start_sftp_client() as sftp:
            for remote_path in remote_files:
                filename = os.path.basename(remote_path)
                local_path = local_dir / filename
                fname, ok = await self.download_file(sftp, remote_path, local_path)
                if ok:
                    success.append(fname)
                else:
                    failed.append(fname)

                if master_pbar:
                    master_pbar.update(1)

        return {'success': success, 'failed': failed}


def setup_logging(verbose: bool = False):
    """Configure logging with appropriate level and format."""

    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    asyncssh_logger = logging.getLogger('asyncssh')
    asyncssh_logger.setLevel(logging.WARNING)  # Скрываем DEBUG/INFO от asyncssh


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments with detailed help."""

    parser = argparse.ArgumentParser(
        description=f"A high-performance utility for downloading files from remote servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of use:

  1. Basic usage (with SSH key from agent):
     python rget.py "2026_01_15__*" /logs/2026/01_15/

  2. With the indication of the private key and passphrase:
     python rget.py "backup_*" /backups/ -k ~/.ssh/id_rsa

  3. With a password instead of a key:
     python rget.py "data_*" /data/ -p mypassword

  4. Custom server and parameters:
     python rget.py "*.log" /logs/ -H server.com -u admin -P 2222

  5. Maximum parallelism:
     python rget.py "*.zip" /downloads/ -c 20

  6. Detailed output for debugging:
     python rget.py "*.tar.gz" /archives/ -v

For quick setup, edit the Config class in the script.
        """
    )

    # Positional arguments
    parser.add_argument(
        'pattern',
        help='File search pattern (for example: "2026_01_15__*" or "backup_*.tar.gz")'
    )

    parser.add_argument(
        'local_dir',
        help='Local directory for saving files'
    )

    other_group = parser.add_argument_group('other arguments')

    other_group.add_argument(
        '--dry-run',
        action='store_true',
        help="Shows which files will be downloaded without actual data transfer"
    )

    # SSH Connection options
    ssh_group = parser.add_argument_group('connection arguments')

    ssh_group.add_argument(
        '--accept-new',
        action='store_true',
        help='Automatically accept and save new host keys (like OpenSSH StrictHostKeyChecking=accept-new). '
            'Keys are saved to ~/.ssh/known_hosts. Safer than disabling verification entirely.'
    )

    ssh_group.add_argument(
        '-H', '--host',
        default=(Config.DEFAULT_REMOTE_HOST if Config.DEFAULT_REMOTE_HOST else "None"),
        help=f'Remote server host (default: {Config.DEFAULT_REMOTE_HOST if Config.DEFAULT_REMOTE_HOST else "None"})'
    )

    ssh_group.add_argument(
        '-u', '--username',
        default=(Config.DEFAULT_REMOTE_USER if Config.DEFAULT_REMOTE_USER else "None"),
        help=f'Server username (default: {Config.DEFAULT_REMOTE_USER if Config.DEFAULT_REMOTE_USER else "None"})'
    )

    ssh_group.add_argument(
        '-P', '--port',
        type=int,
        default=Config.DEFAULT_SSH_PORT,
        help=f'SSH port (default: {Config.DEFAULT_SSH_PORT})'
    )

    ssh_group.add_argument(
        '-d', '--remote-dir',
        default=(Config.DEFAULT_REMOTE_DIR if Config.DEFAULT_REMOTE_DIR else "None"),
        help=f'Directory on the server to search (default: {Config.DEFAULT_REMOTE_DIR if Config.DEFAULT_REMOTE_DIR else "None"})'
    )

    find_group = parser.add_argument_group('find arguments')

    find_group.add_argument(
        '-m', '--maxdepth',
        type=int,
        default=(Config.DEFAULT_MAX_DEPTH if Config.DEFAULT_MAX_DEPTH else "None"),
        help='Maximum search depth'
    )

    find_group.add_argument(
        '-i', '--ignore-case',
        action='store_true',
        help='Perform case-insensitive file search (uses -iname in find)'
    )

    # Authentication options
    auth_group = parser.add_argument_group('Authentication arguments')

    auth_group.add_argument(
        '-k', '--ssh-key',
        help='Path to private SSH key (if not specified, uses SSH agent)'
    )

    auth_group.add_argument(
        '--passphrase',
        help='Passphrase for SSH key (if required)'
    )

    auth_group.add_argument(
        '-p', '--password',
        help='User password (alternative to SSH key) WARNING: -p exposes password in process list. Prefer SSH keys.'
    )

    # Performance options
    perf_group = parser.add_argument_group('performance arguments')

    perf_group.add_argument(
        '-c', '--concurrent',
        type=int,
        default=(Config.DEFAULT_MAX_CONCURRENT if Config.DEFAULT_MAX_CONCURRENT else "None"),
        help=f'Number of parallel downloads (default: {Config.DEFAULT_MAX_CONCURRENT if Config.DEFAULT_MAX_CONCURRENT else "None"})'
    )

    perf_group.add_argument(
        '-t', '--timeout',
        type=int,
        default=(Config.DEFAULT_TIMEOUT if Config.DEFAULT_TIMEOUT else "None"),
        help=f'Connection timeout in seconds (default: {Config.DEFAULT_TIMEOUT if Config.DEFAULT_TIMEOUT else "None"})'
    )

    # Other options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Detailed output for debugging'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'rget v{VERSION}'
    )

    return parser.parse_args()


async def async_main():
    """Main async entry point."""

    # Parse arguments
    args = parse_arguments()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if not args.host or not args.username:
        logger.error("--host and --username are required")
        sys.exit(1)

    if not args.remote_dir:
        logger.error("--remote-dir is required")
        sys.exit(1)

    # Prepare local directory
    local_dir = Path(args.local_dir)

    # Check for authentication method
    if not args.ssh_key and not args.password and args.verbose:
        logger.debug("SSH agent is used for authentication")
        logger.debug("Make sure the key is added: ssh-add\n")

    # Create client
    client = RemoteFileSyncClient(
        host=args.host,
        username=args.username,
        port=args.port,
        password=args.password,
        ssh_key_path=args.ssh_key,
        passphrase=args.passphrase,
        max_concurrent=args.concurrent,
        timeout=args.timeout,
        max_depth=args.maxdepth,
        accept_new=args.accept_new,
        ignore_case=args.ignore_case,
        dry_run=args.dry_run,
    )

    try:
        # Connect and find files
        conn_search = await client.connect()
        #conn = await client.connect()

        try:
            # Find files
            remote_files = await client.find_files(conn_search, args.remote_dir, args.pattern)

            if not remote_files:
                logger.error(f"Files by pattern '{args.pattern}' not found in {args.remote_dir}")
                return 1

            # Show file list if verbose
            if args.verbose:
                logger.debug("\nList of files to download:")
                for f in remote_files:
                    logger.debug(f"• {os.path.basename(f)}")

        finally:
            conn_search.close()
            await conn_search.wait_closed()

        if args.dry_run:
            if not args.verbose:
                logger.info("DRY RUN — files that would be downloaded:")
                logger.info(f"Files matching pattern '{args.pattern}':")
                for f in remote_files:
                    logger.info(f"• {os.path.basename(f)}")
                logger.info(f"Total: {len(remote_files)} file(s) | Use without --dry-run to download")

            return 0

        # Download files in parallel
        if args.verbose:
            logger.debug(f"Parallel downloads: {args.concurrent}")
            logger.debug(f"Target directory: {local_dir.absolute()}\n")

        if TQDM_AVAILABLE and not args.dry_run:
            master_pbar = tqdm(
                total=len(remote_files),
                desc="Downloading",
                unit="file",
                ncols=80,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
            )
        else:
            master_pbar = None

        num_conns = min(args.concurrent, len(remote_files))  # Не создаём лишних
        download_conns = [await client.connect() for _ in range(num_conns)]

        groups = [[] for _ in range(num_conns)]
        for i, f in enumerate(remote_files):
            groups[i % num_conns].append(f)

        tasks = [
            client.download_files_sequential(group, local_dir, download_conns[i], master_pbar)
            for i, group in enumerate(groups) if group
        ]

        start_time = datetime.now()

        group_results = await asyncio.gather(*tasks, return_exceptions=True)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        all_success, all_failed = [], []
        for res in group_results:
            if isinstance(res, dict):
                all_success.extend(res['success'])
                all_failed.extend(res['failed'])
            else:
                logger.error(f"Group download failed: {res}")

        # Print results
        print(f"Successfully downloaded: {len(all_success)}/{len(remote_files)} file(s)")

        if all_failed:
            print(f"Failed: {len(all_failed)} file(s)")
            if args.verbose:
                for f in all_failed:
                    logger.debug(f"• {f}")

        if args.verbose:
            logger.debug(f"Duration: {duration:.2f} seconds")
            if all_success:
                logger.debug(f"Average time per file: {duration / len(all_success):.2f} seconds")

        # Exit with appropriate code
        return 0 if not all_failed else 1

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    finally:
        # Закрываем ВСЕ соединения скачивания
        for c in download_conns:
            c.close()
            await c.wait_closed()


def main():
    """Synchronous entry point."""

    # Check Python version
    if sys.version_info < (3, 7):
        print("Требуется Python 3.7 или выше")
        sys.exit(1)

    # Check dependencies
    try:
        import asyncssh
    except ImportError:
        print("The asyncssh library is required.")
        print("Install: pip install asyncssh")
        sys.exit(1)

    # Run async main
    try:
        exit_code = asyncio.run(async_main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
