#!/usr/bin/env python3
"""
LOTL Detection Framework - REST API Server

Usage:
    python run.py [options]

Options:
    --host HOST         Host to bind to (default: 0.0.0.0)
    --port PORT         Port to bind to (default: 5000)
    --db PATH           Database path (default: alerts.db)
    --rules DIR         Rules directory (default: rules)
    --debug             Enable debug mode
"""
import argparse
import sys
import os
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from api.server import create_app


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='LOTL Detection Framework REST API Server'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind to (default: 5000)'
    )
    parser.add_argument(
        '--db',
        default='alerts.db',
        help='Database path (default: alerts.db)'
    )
    parser.add_argument(
        '--rules',
        default='rules',
        help='Rules directory (default: rules)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    args = parser.parse_args()

    # Create configuration
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

    app = create_app(config)

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
