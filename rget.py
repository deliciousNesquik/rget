#!/usr/bin/env python3
"""
Remote File Sync Utility
A high-performance, cross-platform tool for downloading files from remote servers via SSH/SFTP
with parallel transfers, progress tracking, and flexible authentication.
"""

import argparse
import asyncio
import asyncssh
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import platform

# Try to import tqdm for progress bars, fall back to simple logging if not available
try:
    from tqdm.asyncio import tqdm_asyncio
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Install 'tqdm' for progress bars: pip install tqdm")

VERSION = "1.0.0"


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
    DEFAULT_LOCAL_DIR = ""


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

    async def connect(self) -> asyncssh.SSHClientConnection:
        """Establish SSH connection with flexible authentication."""

        connection_kwargs = {
            'host': self.host,
            'port': self.port,
            'username': self.username,
            #'known_hosts': asyncssh.SSHKnownHosts.from_file('~/.ssh/known_hosts'),
            'connect_timeout': self.timeout
        }

        # Priority: SSH key -> Password
        if self.ssh_key_path:
            self.logger.debug(f"Connecting with an SSH key: {self.ssh_key_path}")
            connection_kwargs['client_keys'] = [self.ssh_key_path]
            if self.passphrase:
                connection_kwargs['passphrase'] = self.passphrase
        elif self.password:
            self.logger.debug("Connection with a password")
            connection_kwargs['password'] = self.password
        else:
            # Try to use SSH agent
            self.logger.debug("Attempting to use SSH agent")

        try:
            conn = await asyncssh.connect(**connection_kwargs)
            self.logger.debug(f"Connected to {self.username}@{self.host}:{self.port}")
            return conn
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            raise

    async def find_files(
            self,
            conn: asyncssh.SSHClientConnection,
            remote_dir: str,
            pattern: str
    ) -> List[str]:
        """Find files on remote server matching pattern."""

        find_cmd = f"find {remote_dir} -maxdepth {self.max_depth} -name '{pattern}' -type f -size +0c"
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
            local_path: Path,
            pbar: Optional[tqdm] = None
    ) -> tuple[str, bool]:
        """Download single file via SFTP."""

        filename = os.path.basename(remote_path)

        try:
            await sftp.get(remote_path, str(local_path))

            # Verify file was downloaded and has size
            if local_path.exists() and local_path.stat().st_size > 0:
                if pbar:
                    pbar.update(1)
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

    async def download_files_parallel(
            self,
            remote_files: List[str],
            local_dir: Path
    ) -> dict:
        """Download multiple files in parallel with progress tracking."""

        if not remote_files:
            self.logger.warning("There are no files to upload.")
            return {'success': [], 'failed': []}

        # Ensure local directory exists
        local_dir.mkdir(parents=True, exist_ok=True)

        # Connect and start SFTP
        conn = await self.connect()

        try:
            async with conn.start_sftp_client() as sftp:
                # Create semaphore for concurrent downloads
                semaphore = asyncio.Semaphore(self.max_concurrent)

                async def download_with_semaphore(remote_path: str, pbar):
                    async with semaphore:
                        filename = os.path.basename(remote_path)
                        local_path = local_dir / filename
                        return await self.download_file(sftp, remote_path, local_path, pbar)

                # Progress bar
                if TQDM_AVAILABLE:
                    pbar = tqdm(
                        total=len(remote_files),
                        desc="Loading",
                        unit="file",
                        ncols=80,
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
                    )
                else:
                    pbar = None
                    self.logger.debug(f"Start downloading {len(remote_files)} file(s)...")

                # Download all files in parallel
                tasks = [
                    download_with_semaphore(remote_path, pbar)
                    for remote_path in remote_files
                ]

                results = await asyncio.gather(*tasks)

                if pbar:
                    pbar.close()

                # Separate successful and failed downloads
                success = [f for f, status in results if status]
                failed = [f for f, status in results if not status]

                return {'success': success, 'failed': failed}

        finally:
            conn.close()
            await conn.wait_closed()


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
        default=Config.DEFAULT_LOCAL_DIR,
        help='Local directory for saving files'
    )

    # SSH Connection options
    ssh_group = parser.add_argument_group('Connection parameters')

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

    parser.add_argument(
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

    ssh_group.add_argument(
        '-m', '--maxdepth',
        type=int,
        default=(Config.DEFAULT_MAX_DEPTH if Config.DEFAULT_MAX_DEPTH else "None"),
        help='Maximum search depth (default: 1; use 0 for unlimited)'
    )

    # Authentication options
    auth_group = parser.add_argument_group('Authentication')

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
    perf_group = parser.add_argument_group('Performance parameters')

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
        action='store_true',  # ← Правильный способ для флагов
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
    )

    try:
        # Connect and find files
        conn = await client.connect()

        try:
            # Find files
            remote_files = await client.find_files(conn, args.remote_dir, args.pattern)

            if not remote_files:
                logger.error(f"Files by pattern '{args.pattern}' not found in {args.remote_dir}")
                return 0

            # Show file list if verbose
            if args.verbose:
                logger.debug("\nList of files to download:")
                for f in remote_files:
                    logger.debug(f"• {os.path.basename(f)}")

        finally:
            conn.close()
            await conn.wait_closed()

        # Download files in parallel
        if args.verbose:
            logger.debug(f"Parallel downloads: {args.concurrent}")
            logger.debug(f"Target directory: {local_dir.absolute()}\n")

        start_time = datetime.now()

        results = await client.download_files_parallel(remote_files, local_dir)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Print results
        print(f"Successfully uploaded: {len(results['success'])}/{len(remote_files)} file(s)")

        if results['failed']:
            print(f"Failed to load: {len(results['failed'])} file(s)")
            if args.verbose:
                logger.warning("Download errors:")
                for f in results['failed']:
                    logger.debug(f"• {f}")

        if args.verbose:
            logger.debug(f"Finish time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.debug(f"Duration: {duration:.2f} seconds")

        if args.verbose:
            if len(results['success']) > 0:
                avg_time = duration / len(results['success'])
                logger.debug(f"Average time per file: {avg_time:.2f} seconds")

        # Exit with appropriate code
        return 0 if not results['failed'] else 1

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


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
