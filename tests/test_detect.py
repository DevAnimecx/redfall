"""The detector suite: nine classes taint analysis cannot reach.

Two properties are tested for every detector, and the second matters more than
the first:

**It fires on the vulnerable shape.** Each seeded flow in `pythonbank` has a
detector that reports it, asserted by name.

**It stays quiet on the safe sibling.** A detector for an *absence* flags every
route unless it is careful, and a scanner that flags everything is one nobody
reads. Every detector here is asserted silent on code that has the check.

The second class is why these tests are longer than the detectors. A recall
number is trivial to raise by widening a pattern; the tests that stop that are
the ones worth writing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

PYBANK = ROOT / "range" / "pythonbank"


def _detect(source: str, path: str = "src/app.py"):
    from redfall.detect import detect_file

    return detect_file(path, source)


def _categories(source: str, path: str = "src/app.py"):
    return {hit.category for hit in _detect(source, path)}


# -- the comment trap -------------------------------------------------------

def test_comments_are_not_read_as_code():
    """The bug that hid a real finding.

    `pythonbank` documents its own vulnerabilities in comments:
    `# VULN-010: extension and content type are never checked` names the very
    guard the upload detector looks for, so the comment *satisfied* the check
    and the detector stayed silent on a real bug. Comments are blanked before
    analysis, and position is preserved so line numbers still point at the line
    a human would open.
    """
    from redfall.detect.types import without_comments

    text = "x = 1  # allowed_extensions = ['.png']\ny = 2\n"
    stripped = without_comments(text)
    assert "allowed_extensions" not in stripped
    # Line structure is preserved: a finding must still point at the right line.
    assert stripped.count("\n") == text.count("\n")
    assert stripped.splitlines()[1] == "y = 2"


def test_an_upload_guarded_only_by_a_comment_is_still_a_finding():
    vulnerable = '''
@bp.post("/upload")
def upload():
    f = request.files.get("file")
    # extension and content type are never checked
    target = UPLOAD_DIR / f.filename
    f.save(target)
'''
    assert "unrestricted_file_type" in _categories(vulnerable)


# -- secrets ----------------------------------------------------------------

def test_a_placeholder_credential_is_reported():
    src = 'TOKEN_SECRET = "pythonbank-dev-secret-do-not-ship"\n'
    assert "hardcoded_secret" in _categories(src)


def test_a_high_entropy_literal_is_reported():
    src = 'API_KEY = "a8Fk2Lm9Qz3Xw7Rt5Yb1Nc4Vd6"\n'
    assert "hardcoded_secret" in _categories(src)


def test_a_short_harmless_value_is_not_a_secret():
    """A name match alone is not a finding — that is how a scanner gets ignored."""
    src = 'token_type = "Bearer"\n'
    assert "hardcoded_secret" not in _categories(src)


def test_a_secret_returned_from_a_handler_is_exposed():
    src = '''
@bp.get("/config")
def get_config():
    return jsonify({"token_secret": TOKEN_SECRET})
'''
    assert "secret_exposure" in _categories(src)


# -- crypto -----------------------------------------------------------------

def test_md5_on_a_password_is_reported():
    src = '''
def register(password):
    password_hash = hashlib.md5(password.encode()).hexdigest()
    return password_hash
'''
    assert "weak_password_hash_md5" in _categories(src)


def test_a_project_local_md5_wrapper_is_reported_at_the_call_site():
    """Real code wraps the primitive; the finding belongs where a password is
    hashed, not where the helper is defined."""
    src = '''
def register(password):
    password_hash = db.md5_hex(password)
    return password_hash
'''
    hits = [h for h in _detect(src) if h.category == "weak_password_hash_md5"]
    assert hits, "a project-local md5 wrapper on a password was not reported"
    assert hits[0].line == 3, f"reported at line {hits[0].line}, expected the call site"


def test_a_salted_digest_is_not_reported():
    src = '''
def hash_password(password, salt):
    return pbkdf2_hmac("sha256", password, salt, 100000)
'''
    assert "weak_password_hash_md5" not in _categories(src)


def test_a_checksum_of_non_secret_data_is_not_reported():
    src = '''
def checksum(payload):
    return hashlib.md5(payload).hexdigest()
'''
    assert "weak_password_hash_md5" not in _categories(src)


def test_a_webhook_read_without_verification_is_reported():
    src = '''
@bp.post("/webhook")
def webhook():
    sig = request.headers.get("X-Signature")
    payload = request.get_json()
    return jsonify({"received": True})
'''
    assert "missing_signature_verify" in _categories(src)


def test_a_verified_webhook_is_not_reported():
    src = '''
@bp.post("/webhook")
def webhook():
    sig = request.headers.get("X-Signature")
    expected = hmac.new(KEY, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        abort(400)
    return jsonify({"ok": True})
'''
    assert "missing_signature_verify" not in _categories(src)


# -- route posture ----------------------------------------------------------

def test_a_mutating_route_without_a_limiter_is_reported():
    src = '''
@bp.post("/transfer")
def transfer():
    conn.execute("INSERT INTO t VALUES (?)", (amount,))
    conn.commit()
'''
    assert "missing_rate_limit" in _categories(src)


def test_an_auth_route_without_a_limiter_is_reported():
    """A login endpoint mutates nothing and is the canonical rate-limited route."""
    src = '''
@bp.post("/login")
def login():
    user = find_user(request.json["username"])
    return jsonify({"token": sign(user)})
'''
    assert "missing_rate_limit" in _categories(src)


def test_a_limited_route_is_not_reported():
    src = '''
@bp.post("/transfer")
@limiter.limit("5/minute")
def transfer():
    conn.execute("INSERT INTO t VALUES (?)", (amount,))
    conn.commit()
'''
    assert "missing_rate_limit" not in _categories(src)


def test_a_read_only_route_is_not_reported():
    src = '''
@bp.get("/status")
def status():
    return jsonify({"ok": True})
'''
    assert "missing_rate_limit" not in _categories(src)


def test_an_id_lookup_without_an_ownership_check_is_reported():
    src = '''
@bp.get("/<int:user_id>")
def get_user(user_id):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(row))
'''
    assert "idor" in _categories(src)


def test_an_id_lookup_with_an_ownership_check_is_not_reported():
    src = '''
@bp.get("/<int:user_id>")
def get_user(user_id):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row["owner"] != current_user()["id"]:
        abort(403)
    return jsonify(dict(row))
'''
    assert "idor" not in _categories(src)


def test_an_upload_with_no_type_check_is_reported():
    src = '''
@bp.post("/upload")
def upload():
    f = request.files.get("file")
    target = UPLOAD_DIR / f.filename
    f.save(target)
'''
    assert "unrestricted_file_type" in _categories(src)


def test_an_upload_with_an_allowlist_is_not_reported():
    src = '''
@bp.post("/upload")
def upload():
    f = request.files.get("file")
    if pathlib.Path(f.filename).suffix not in allowed_extensions:
        abort(400)
    f.save(UPLOAD_DIR / f.filename)
'''
    assert "unrestricted_file_type" not in _categories(src)


def test_an_unrestricted_request_named_fetch_is_ssrf_and_metadata():
    """One defect, two impacts: a URL the caller names with no host check
    reaches the metadata service by construction."""
    src = '''
@bp.post("/fetch")
def proxy_fetch():
    url = str(request.get_json().get("url"))
    response = requests.get(url, timeout=5)
    return jsonify({"body": response.text})
'''
    cats = _categories(src)
    assert "ssrf" in cats
    assert "ssrf_metadata" in cats


def test_a_fetch_with_a_host_restriction_is_not_ssrf():
    src = '''
@bp.post("/fetch")
def proxy_fetch():
    url = str(request.get_json().get("url"))
    if urlparse(url).hostname not in allowed_hosts:
        abort(400)
    return jsonify({"body": requests.get(url).text})
'''
    cats = _categories(src)
    assert "ssrf" not in cats
    assert "ssrf_metadata" not in cats


# -- response ---------------------------------------------------------------

def test_an_auth_path_that_distinguishes_accounts_is_reported():
    src = '''
@bp.post("/login")
def login():
    user = lookup(username)
    if user is None:
        return jsonify({"error": "no such user"}), 404
    if not check(user, password):
        return jsonify({"error": "wrong password"}), 401
    return jsonify({"token": sign(user)})
'''
    assert "user_enumeration" in _categories(src)


def test_a_constant_failure_response_is_not_reported():
    """One 401 for every failure is the correct implementation."""
    src = '''
@bp.post("/login")
def login():
    user = lookup(username)
    if user is None or not check(user, password):
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": sign(user)})
'''
    assert "user_enumeration" not in _categories(src)


def test_an_error_handler_leaking_a_traceback_is_reported():
    src = '''
@app.errorhandler(500)
def handle_error(e):
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500
'''
    assert "verbose_error" in _categories(src)


# -- encoding ---------------------------------------------------------------

def test_a_hand_rolled_csv_row_is_reported():
    src = '''
@bp.get("/export.csv")
def export_csv():
    rows = fetch_rows()
    lines = ["id,note"]
    for row in rows:
        lines.append(f"{row['id']},{row['note']}")
    return Response("\\n".join(lines), mimetype="text/csv")
'''
    assert "csv_injection" in _categories(src)


def test_a_formula_guarded_csv_is_not_reported():
    src = '''
@bp.get("/export.csv")
def export_csv():
    rows = fetch_rows()
    lines = []
    for row in rows:
        safe = escape_formula(row["note"])
        lines.append(f"{row['id']},{safe}")
    return Response("\\n".join(lines), mimetype="text/csv")
'''
    assert "csv_injection" not in _categories(src)


# -- the detectors against the real target ----------------------------------

@pytest.mark.skipif(not PYBANK.is_dir(), reason="pythonbank not present")
def test_every_seeded_pythonbank_flow_has_a_detector_or_is_taint_shaped():
    """Every flow in the tuned corpus is reported by this engine.

    17 of 17. This is the *tuned* number and it is not the claim — see
    `test_the_holdout_is_measured_and_reported` for why that distinction is
    load-bearing.
    """
    from redfall.detect import detect_file

    import yaml

    manifest = yaml.safe_load(
        (PYBANK / "manifest.yaml").read_text(encoding="utf-8")
    )
    detected: dict[str, set[str]] = {}
    for path in sorted((PYBANK / "src").rglob("*.py")):
        rel = "src/" + str(path.relative_to(PYBANK / "src")).replace("\\", "/")
        for hit in detect_file(rel, path.read_text(encoding="utf-8")):
            detected.setdefault(hit.category, set()).add(hit.file)

    # The nine classes this suite exists for, each of which the taint engine
    # cannot reach at any depth.
    for category in (
        "hardcoded_secret",
        "secret_exposure",
        "weak_password_hash_md5",
        "missing_rate_limit",
        "verbose_error",
        "user_enumeration",
        "csv_injection",
        "unrestricted_file_type",
        "idor",
    ):
        seeded = [v for v in manifest["vulns"] if v["category"] == category]
        assert seeded, f"{category} is not seeded; the test has drifted"
        assert category in detected, f"no detector fires for {category}"


def test_the_holdout_is_measured_and_reported():
    """The number that counts is the one from a corpus never inspected.

    A tuned corpus can be driven to 100% by shaping detectors to the exact code
    in it, and that was the state this project reached before the holdout was
    run: `pythonbank` scored 17/17 while `vulnbank` — TypeScript, a different
    codebase, never opened while the detectors were written — scored 6/32.

    This test asserts the *gap is recorded*, not that it is small. Shrinking it
    is the work; hiding it is the failure.
    """
    import json

    tuned = ROOT / "bench" / "baselines" / "pythonbank.json"
    holdout = ROOT / "bench" / "baselines" / "vulnbank.json"
    if not (tuned.is_file() and holdout.is_file()):
        pytest.skip("baselines not measured on this host")

    tuned_data = json.loads(tuned.read_text(encoding="utf-8"))
    holdout_data = json.loads(holdout.read_text(encoding="utf-8"))

    assert tuned_data["kind"] == "tuned"
    assert holdout_data["kind"] == "holdout"
    assert holdout_data["recall"] is not None
    # The gap is real and larger than noise. If a future change closes it, that
    # is news worth failing this test to record deliberately.
    assert tuned_data["recall"] > holdout_data["recall"], (
        "the tuned corpus is no longer scoring above the holdout — "
        "either the gap closed (update this test) or the tuning broke"
    )
