"""
Upload a capture, get a report.

The requested GUI, and the first part of this project a person can use
without a terminal. Three routes: a form, the thing the form posts to, and
the report it produces.

Everything about handling the file assumes the person sending it is not
necessarily the person sitting in front of it.

* **The client's filename is never used.** Not sanitised, not normalised --
  discarded. A name arriving over HTTP is a string chosen by the sender, and
  every path-traversal bug in this class begins with a well-meaning attempt
  to clean one up rather than to ignore it. Uploads are stored under an id
  this service generates, and the original name is kept only as a label to
  show back.

* **The size cap is enforced while reading, not after.** `UploadFile` is a
  stream; checking `content-length` trusts the sender and checking the file
  size afterwards means the disk is already full. Bytes are counted as they
  arrive and the partial file is removed the moment the cap is passed.

* **Parsing happens in `pcapscan.sandbox`**, never in this process. See
  PR-27: a capture the parser cannot digest must cost one subprocess, not
  the service.

The report page renders `cryptomon.analysis.Summary.as_dict()` rather than
walking session records field by field. The summary's shape is stable; the
record's shape gains ALPN, PSK modes, ECH status, JA4 and SSH host keys as
Lane E lands. Rendering the summary means this page picks that up without
being edited.
"""
import json
import pathlib
import secrets
import shutil

from fastapi import (APIRouter, Depends, File, Form, Header, HTTPException,
                     Request, UploadFile, status)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cryptomon.analysis import classify_key_exchange
from fapi.app.retention import describe as describe_retention
from fapi.config import settings
from pcapscan.sandbox import Limits, analyse_capture

router = APIRouter()

TEMPLATES = Jinja2Templates(
    directory=str(pathlib.Path(__file__).resolve().parent / "templates"))

# How the stream is read. Small enough that the cap is noticed promptly,
# large enough that a 200MB capture is not a million syscalls.
CHUNK_BYTES = 1024 * 1024

# An id the service chooses, in a shape that cannot be a path component
# anywhere: 32 hex characters and nothing else. Checked on the way back in
# too, because the id in a URL is as much the sender's choice as the
# filename was.
ID_BYTES = 16
ID_LENGTH = ID_BYTES * 2


def upload_dir():
    """Where uploads and reports live. Created on demand, never guessed."""
    path = pathlib.Path(settings.UPLOAD_DIR).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


async def require_upload_access(x_api_key: str = Header(default=None)):
    """
    Guard the upload routes.

    Deliberately *not* `require_write_access`. An upload writes no document,
    so refusing it because the database is read-only would be answering a
    different question -- and would mean the feature does not work out of the
    box on a default install, which is the install almost everybody has.

    What it does enforce: the feature can be switched off, and when an API
    key is configured it is required here too. The service binds loopback by
    default (PR-10), so the exposure this matters for is a deployment behind
    nginx -- which is exactly where an API key will already be set.
    """
    if not settings.UPLOADS_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Capture upload is disabled. Set UPLOADS_ENABLED=true to "
                   "enable it, and set API_KEY as well if this service is "
                   "reachable from anywhere but localhost.")
    if settings.API_KEY:
        # compare_digest rather than ==, for the same reason as in
        # security.py: equality leaks the key's prefix through timing.
        if not x_api_key or not secrets.compare_digest(str(x_api_key),
                                                       settings.API_KEY):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid X-API-Key header is required to upload.",
                headers={"WWW-Authenticate": "X-API-Key"})


def _valid_id(report_id):
    """A report id is 32 hex characters. Anything else is not one."""
    return (isinstance(report_id, str) and len(report_id) == ID_LENGTH
            and all(c in '0123456789abcdef' for c in report_id))


def _paths(report_id):
    directory = upload_dir()
    return (directory / '{0}.capture'.format(report_id),
            directory / '{0}.json'.format(report_id))


async def _spool(upload, destination, max_bytes):
    """
    Write the stream to disk, stopping the moment it is too big.

    Returns the number of bytes written, or None if the cap was passed --
    in which case the partial file is already gone. The caller never sees a
    half-written capture.
    """
    written = 0
    try:
        with open(destination, 'wb') as handle:
            while True:
                chunk = await upload.read(CHUNK_BYTES)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    handle.close()
                    destination.unlink(missing_ok=True)
                    return None
                handle.write(chunk)
    except OSError:
        destination.unlink(missing_ok=True)
        raise
    return written


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse,
            response_description="The upload form")
async def upload_form(request: Request):
    return TEMPLATES.TemplateResponse(
        request, "upload.html",
        {"max_bytes": settings.MAX_UPLOAD_BYTES,
         "enabled": settings.UPLOADS_ENABLED,
         "key_required": bool(settings.API_KEY),
         # Said before the file is chosen, not afterwards. Somebody deciding
         # whether to upload a capture of their network needs to know how
         # long it will be kept at the moment they are deciding.
         "retention": describe_retention(settings.REPORT_RETENTION_HOURS,
                                         settings.DATA_RETENTION_HOURS)})


@router.post("/", response_description="Analyse an uploaded capture",
             dependencies=[Depends(require_upload_access)])
async def upload_capture(request: Request,
                         capture: UploadFile = File(...),
                         as_json: bool = Form(default=False)):
    """
    Take a capture, analyse it in the sandbox, keep the report.

    Answers a redirect to the report page for a browser, or the report itself
    for `as_json=true`, so the same endpoint serves the form and a script.
    """
    report_id = secrets.token_hex(ID_BYTES)
    capture_path, report_path = _paths(report_id)

    written = await _spool(capture, capture_path,
                           settings.MAX_UPLOAD_BYTES)
    if written is None:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="The capture exceeds the {0}-byte limit. Split it with "
                   "`editcap -c`, or raise MAX_UPLOAD_BYTES.".format(
                       settings.MAX_UPLOAD_BYTES))
    if not written:
        capture_path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The uploaded file is empty.")

    result = analyse_capture(
        capture_path,
        Limits(max_capture_bytes=settings.MAX_UPLOAD_BYTES,
               wall_seconds=settings.ANALYSIS_TIMEOUT_SECONDS))
    # The capture itself is not kept. Everything the report needs is in the
    # report, and a directory of other people's packet captures is a
    # liability nobody asked for -- see PR-29.
    capture_path.unlink(missing_ok=True)

    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"reason": result.reason, "detail": result.detail[:2000],
                    "hint": _HINTS.get(result.reason, '')})

    document = dict(result.document)
    document['meta']['report_id'] = report_id
    # The name the sender chose is shown back as a label and used for nothing
    # else. It has never been part of a path.
    document['meta']['original_filename'] = (capture.filename or '')[:200]
    document['meta']['bytes'] = written
    document['meta']['elapsed_seconds'] = round(result.elapsed, 3)
    report_path.write_text(json.dumps(document), encoding='utf-8')

    if as_json:
        return JSONResponse(document)
    return RedirectResponse(url=request.url_for('report', report_id=report_id),
                            status_code=status.HTTP_303_SEE_OTHER)


_HINTS = {
    'timeout': "The capture took longer than the analysis timeout. Try a "
               "smaller slice with `editcap -r`.",
    'memory': "The analysis ran out of memory. A capture with very many "
              "distinct connections can do this; split it and try again.",
    'cpu': "The analysis used more CPU than it is allowed.",
    'not_a_capture': "That file is not a pcap or pcapng capture.",
    'too_large': "The capture is larger than this service will analyse.",
}


@router.get("/reports/{report_id}", response_class=HTMLResponse, name="report")
async def report(request: Request, report_id: str):
    document = _load(report_id)
    return TEMPLATES.TemplateResponse(
        request, "report.html",
        {"report_id": report_id,
         "meta": document.get('meta', {}),
         "summary": document.get('summary', {}),
         "readiness": (document.get('summary') or {}).get('readiness', {}),
         # The verdict is derived at render time from the shared
         # classification table rather than stored in the report, so an
         # improvement to that table improves an old report too.
         "verdict_of": lambda name: classify_key_exchange(
             None if name == 'none' else name),
         "retention": describe_retention(settings.REPORT_RETENTION_HOURS,
                                         settings.DATA_RETENTION_HOURS),
         "retention_hours": settings.REPORT_RETENTION_HOURS})


@router.get("/reports/{report_id}/json",
            response_description="The report as JSON")
async def report_json(report_id: str):
    return JSONResponse(_load(report_id))


def _load(report_id):
    """
    Read a stored report, or 404.

    The id is validated before it is ever joined to a path. A 404 for a
    malformed id rather than a 500 matters here for the same reason it did
    on `/data/{id}` in PR-06: the id is the sender's choice.
    """
    if not _valid_id(report_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No such report.")
    _capture, report_path = _paths(report_id)
    try:
        return json.loads(report_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No such report. Reports are not kept "
                                   "indefinitely.")


def clear_uploads():
    """Remove every upload and report. Used by the tests and by an operator."""
    directory = pathlib.Path(settings.UPLOAD_DIR).expanduser()
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)


__all__ = ['router', 'clear_uploads', 'upload_dir', 'require_upload_access']
