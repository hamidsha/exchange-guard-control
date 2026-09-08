from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from typing import Any

from app.reputation import _mysql_connection


COLUMNS = (
    "EventHash",
    "Timestamp",
    "ClientIp",
    "ClientHostname",
    "ConnectorId",
    "Source",
    "EventId",
    "InternalMessageId",
    "MessageId",
    "NetworkMessageId",
    "Recipients",
    "RecipientStatus",
    "TotalBytes",
    "RecipientCount",
    "MessageSubject",
    "Sender",
    "ReturnPath",
    "Directionality",
    "OriginalClientIp",
    "TransportTrafficType",
)


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _event_hash(row: dict[str, str]) -> str:
    supplied = str(row.get("EventHash") or "").strip().lower()
    if len(supplied) == 64 and all(character in "0123456789abcdef" for character in supplied):
        return supplied
    source = "|".join(str(row.get(column) or "") for column in COLUMNS[1:])
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: import_tracking_csv.py /path/to/message-tracking.csv", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    placeholders = ",".join(["%s"] * len(COLUMNS))
    column_sql = ",".join(f"`{column}`" for column in COLUMNS)
    statement = (
        f"INSERT IGNORE INTO GetMessageTrackingLog ({column_sql}) "
        f"VALUES ({placeholders})"
    )

    rows_read = 0
    rows_inserted = 0
    batch: list[tuple[Any, ...]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle, _mysql_connection() as connection:
        reader = csv.DictReader(handle)
        missing = set(COLUMNS[1:]) - set(reader.fieldnames or [])
        if missing:
            raise RuntimeError(f"CSV is missing columns: {', '.join(sorted(missing))}")
        with connection.cursor() as cursor:
            for row in reader:
                rows_read += 1
                values: dict[str, Any] = dict(row)
                values["EventHash"] = _event_hash(row)
                values["TotalBytes"] = _integer(row.get("TotalBytes"))
                values["RecipientCount"] = _integer(row.get("RecipientCount"))
                batch.append(tuple(values.get(column) or None for column in COLUMNS))
                if len(batch) >= 500:
                    rows_inserted += cursor.executemany(statement, batch)
                    batch.clear()
            if batch:
                rows_inserted += cursor.executemany(statement, batch)

    print({"file": str(path), "rows_read": rows_read, "rows_inserted": rows_inserted})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
