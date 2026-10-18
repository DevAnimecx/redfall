"""Shared helpers that never see a request object.

`reports.py` is where VULN-017 hides: the SQL string is assembled here from a
value the caller forwards, so the defect is only visible to an interprocedural
taint pass.
"""
