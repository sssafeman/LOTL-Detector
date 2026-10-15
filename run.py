#!/usr/bin/env python3
"""
LOTL Detection Framework - REST API Server

Usage:
    python run.py [options]

Options:
    --host HOST         Host to bind to (default: from config)
    --port PORT         Port to bind to (default: from config)
    --db PATH           Database path (default: from config)
    --rules DIR         Rules directory (default: from config)
    --debug             Enable debug mode (default: from config)
"""
import argparse
import sys
import os
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from api.auth import CredentialConfigurationError
from api.server import create_app
from api.startup import StartupError, validate_startup_binding
from core.config import get_api_config, get_database_path, get_rules_directory, get_logging_config


def main():
    """Main entry point"""
    # Load configuration defaults. Configuration errors are fatal: the
    # server must not invent defaults (the old fallback could bind 0.0.0.0).
    try:
        api_config = get_api_config()
        db_path = get_database_path()
        rules_dir = get_rules_directory()
        logging_config = get_logging_config()
    except Exception as e:
        print(f"Error: failed to load configuration: {e}", file=sys.stderr)
        print(
            "Fix config.yml or remove it to use built-in defaults.",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='LOTL Detection Framework REST API Server'
    )
    parser.add_argument(
        '--host',
        default=api_config['host'],
        help=f'Host to bind to (default: {api_config["host"]})'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=api_config['port'],
        help=f'Port to bind to (default: {api_config["port"]})'
    )
    parser.add_argument(
        '--db',
        default=db_path,
        help=f'Database path (default: {db_path})'
    )
    parser.add_argument(
        '--rules',
        default=rules_dir,
        help=f'Rules directory (default: {rules_dir})'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=api_config['debug'],
        help=f'Enable debug mode (default: {api_config["debug"]})'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default=logging_config['level'],
        help=f'Logging level (default: {logging_config["level"]})'
    )

    args = parser.parse_args()

    # Create configuration for Flask app
    config = {
        'DATABASE_PATH': args.db,
        'RULES_DIR': args.rules,
        'LOG_LEVEL': args.log_level
    }

    # Create Flask app
    print(f"LOTL Detection Framework REST API Server")
    print(f"=========================================")
    print(f"Database: {args.db}")
    print(f"Rules Directory: {args.rules}")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Debug: {args.debug}")
    print(f"Log Level: {args.log_level}")
    print(f"=========================================\n")

    try:
        app = create_app(config)
    except (StartupError, CredentialConfigurationError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    # Refuse unsafe bindings before any socket is opened (shared with
    # api/server.py so every entry point enforces the same rules).
    try:
        validate_startup_binding(
            args.host,
            debug=args.debug,
            allow_unauthenticated=bool(
                app.config.get('ALLOW_UNAUTHENTICATED_DEMO')
            ),
        )
    except StartupError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    # Run server
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\nError starting server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
