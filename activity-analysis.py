#!/usr/bin/env python3

#
# A script for querying a GreptimeDB with systemd journal message for failed login attempts.
# Connects to the MySQL interface of GreptimeDB.
# The GreptimeDB password is read from an environment variable GREPTIMEDB_PASSWORD.
#

import argparse
import os
import sys
from datetime import datetime

import pymysql


class GreptimeDBClient:
    """
    A client for querying GreptimeDB via MySQL interface.
    """

    def __init__(self, host, port, user, password, database, since):
        """
        Initialize the GreptimeDB client with connection parameters.

        Args:
            host (str): Database host
            port (int): Database port
            user (str): Database user
            password (str): Database password
            database (str): Database name
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.since = since

    def get_messages(self, host, pid):
        query = f"""
        SELECT message 
        FROM logs 
        WHERE host='{host}' AND `_PID`={pid} AND greptime_timestamp > '{self.since}'
        """
        records = self.query(query)

        # Extract messages and join them together
        messages = []
        for record in records:
            messages.append(record["message"])
        return messages

    def get_events(self):
        query = f"""
        SELECT 
            `_PID` as pid, 
            MIN(greptime_timestamp) as ts, 
            MIN(`_MACHINE_ID`) as machine_id,
            host 
        FROM logs
        WHERE 
            message LIKE '%authentication failure%' AND
            greptime_timestamp > '{self.since}'
        GROUP BY `_PID`,host
        ORDER BY ts DESC
        """
        return self.query(query)

    def get_db_end_date(self):
        query = f"""
        SELECT MAX(greptime_timestamp) as ts, 
        FROM logs WHERE greptime_timestamp >= '{self.since}'
        ORDER BY ts DESC;
        """
        ts = self.query(query)[0]['ts']
        # return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
        return ts

    def query(self, query):
        """
        Query the GreptimeDB database using an SQL statement.

        Returns:
            list: List of dictionaries with column names as keys

        Raises:
            pymysql.Error: If database connection or query fails
        """

        try:
            # Connect to the database
            connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                charset='utf8mb4'
            )

            with connection:
                with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                    cursor.execute(query)
                    # Fetch all results as list of dictionaries
                    records = cursor.fetchall()
                    return records

        except pymysql.Error as e:
            raise pymysql.Error(f"Error connecting to MySQL: {e}")


def indent_list(list, padding):
    result = [list.pop(0)]
    for item in list:
        result.append(f"{' ' * padding}{item}")
    return "\n".join(result)


def store_ts(data_dir: str, ts: datetime):
    filename = os.path.join(data_dir, 'greptimedb-query-ts.txt')
    with open(filename, 'w') as f:
        f.write(ts.isoformat())


def get_ts(data_dir):
    """
    Read timestamp from file and return as datetime object.

    Args:
        data_dir (str): Directory containing the timestamp file

    Returns:
        datetime: The stored timestamp or default if file doesn't exist/is invalid
    """
    filename = os.path.join(data_dir, 'greptimedb-query-ts.txt')
    try:
        with open(filename, 'r') as f:
            timestamp_str = f.read().strip()
            if timestamp_str:
                return datetime.fromisoformat(timestamp_str)
            else:
                return datetime(1900, 1, 1, 0, 0, 0)
    except FileNotFoundError:
        return datetime(1900, 1, 1, 0, 0, 0)
    except ValueError as e:
        print(f"Warning: Invalid timestamp format in {filename}: {e}")
        return datetime(1900, 1, 1, 0, 0, 0)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Query GreptimeDB for systemd journal messages'
    )
    parser.add_argument(
        '--db-host',
        default='127.0.0.1',
        help='Database host (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--db-port',
        type=int,
        default=4002,
        help='Database port (default: 4002)'
    )
    parser.add_argument(
        '--db-user',
        required=True,
        help='Database user (mandatory)'
    )
    parser.add_argument(
        '--db-name',
        required=True,
        help='Database name (mandatory)'
    )
    parser.add_argument(
        '--since',
        required=False,
        help='Show records older than this date, accepts date and time, e.g. "2025-07-15" or "2025-07-15 08:47:26"',
    )
    parser.add_argument(
        '--data-dir',
        required=False,
        help='Data directory (default: /var/tmp)',
        default='/var/tmp'
    )
    parser.add_argument(
        '--since-last-run',
        action='store_true',
        help='Continue querying starting from the timestamp of last run',
        default=False
    )

    args = parser.parse_args()

    # Check if GREPTIMEDB_PASSWORD environment variable is set
    password = os.getenv('GREPTIMEDB_PASSWORD')
    if password is None:
        print("Error: GREPTIMEDB_PASSWORD environment variable is not set", file=sys.stderr)
        sys.exit(1)

    if args.since:
        since = datetime.fromisoformat(args.since)
    elif args.since_last_run:
        since = get_ts(args.data_dir)
    else:
        since = '1900-01-01 00:00:00'

    try:
        # Create database client instance
        db_client = GreptimeDBClient(
            host=args.db_host,
            port=args.db_port,
            user=args.db_user,
            password=password,
            database=args.db_name,
            since=since,
        )

        # Query the database
        events = db_client.get_events()
        db_end_date = db_client.get_db_end_date()
        store_ts(args.data_dir, db_end_date)
        if args.since_last_run:
            print(f"Resuming at last ts {since}")
        if len(events) == 0:
            print("No events found")
            sys.exit(0)

        for event in events:
            date_obj = datetime.fromisoformat(str(event['ts']).replace('Z', '+00:00'))
            print(f"{'HOST':>6}: {event['host']} ({event['machine_id']})")
            print(f"{'DATE':>6}: {date_obj.strftime('%Y-%m-%d')} {date_obj.strftime('%H:%M:%s')}")
            print(f"{'PID':>6}: {event['pid']}")
            print(f"{'MSG':>6}: ", end="")
            messages = db_client.get_messages(event['host'], event['pid'])
            print(indent_list(messages, 8))
            print("-" * 120)
        print(f"Last event processed: {db_end_date}")

    except pymysql.Error as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
