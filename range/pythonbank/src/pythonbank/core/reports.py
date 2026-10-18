"""Department rollups. Sees VULN-017 (SQL built across a call)."""

from __future__ import annotations


def department_summary(conn, department: str):
    # VULN-017: the filter arrives from the calling route and is concatenated
    # into the SQL here; nothing on the path binds a parameter. The route that
    # supplies it never touches SQL, which is exactly what an intraprocedural
    # pass on the route file cannot see.
    query = (
        "SELECT department, COUNT(*) AS accounts, SUM(balance) AS total "
        "FROM users WHERE department = '" + department + "' GROUP BY department"
    )
    return conn.execute(query).fetchall()
