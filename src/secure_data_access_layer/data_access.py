import sqlite3
from pathlib import Path

from .audit import record_access
from .models import Action, AccessRequest
from .policy import evaluate_access


DB_PATH = Path(__file__).resolve().parents[2] / "data" / "abac_demo.db"


class SecureDataAccess:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _initialize_database(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS sales (
                    record_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    customer TEXT NOT NULL,
                    amount REAL NOT NULL
                )
            """)
            connection.executemany(
                """
                INSERT OR IGNORE INTO sales
                    (record_id, tenant_id, customer, amount)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("sale-a1", "tenant-a", "Customer A1", 1250.00),
                    ("sale-a2", "tenant-a", "Customer A2", 840.50),
                    ("sale-b1", "tenant-b", "Customer B1", 2150.00),
                ],
            )

    def get_sales(self, request: AccessRequest) -> list[dict]:
        """Authorize first, record the decision, then return tenant-scoped rows."""
        if request.action != Action.READ:
            reason = "This method only handles read requests."
            record_access(request, False, reason)
            raise PermissionError(reason)

        if request.resource.resource_id != "sales":
            reason = "This method only provides access to sales data."
            record_access(request, False, reason)
            raise PermissionError(reason)

        decision = evaluate_access(request)
        record_access(request, decision.allowed, decision.reason)
        if not decision.allowed:
            raise PermissionError(decision.reason)

        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT record_id, customer, amount
                FROM sales
                WHERE tenant_id = ?
                ORDER BY record_id
                """,
                (request.subject.tenant_id,),
            ).fetchall()

        return [dict(row) for row in rows]
