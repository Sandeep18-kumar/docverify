"""VeriGate API: a local, persistent backend for the React frontend.

The verification analysis in this starter backend is deliberately heuristic. It
validates the upload, records file metadata and a SHA-256 audit hash; it does
not claim to prove that a document is authentic. Replace `analyse_document`
with approved OCR, registry and forensic services for a production deployment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv

try:
    import cv2
    import fitz
    import pytesseract
    from PIL import ExifTags, Image
except ImportError:
    cv2 = fitz = pytesseract = Image = ExifTags = None

APP_DIR = Path(__file__).resolve().parent
load_dotenv(APP_DIR / ".env")
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "verigate.db"
MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_MEDIA_TYPES = {"image/jpeg", "image/png", "application/pdf"}
ALLOWED_SUFFIXES = {".jpg", ".jpeg", ".png", ".pdf"}
SECRET = os.getenv("VERIGATE_SECRET", "development-only-change-me").encode()
TOKEN_TTL_HOURS = 24

app = FastAPI(title="VeriGate API", version="1.0.0")
# Browser Origin headers never include a trailing slash. Normalizing here keeps
# a harmless trailing slash in a host environment variable from breaking every
# browser request with a CORS network error.
origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def setup_database() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verifications (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                document_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                processing_time_ms INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                anchor_hash TEXT NOT NULL UNIQUE,
                result_json TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_verifications_user_date
                ON verifications(user_id, uploaded_at DESC);
            """
        )


@app.on_event("startup")
def startup() -> None:
    setup_database()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        salt_encoded, digest_encoded = stored.split("$", 1)
        actual = password_hash(password, base64.urlsafe_b64decode(salt_encoded)).split("$", 1)[1]
        return hmac.compare_digest(actual, digest_encoded)
    except (ValueError, TypeError):
        return False


def token_for(user_id: str) -> str:
    payload = {"sub": user_id, "exp": int((datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)).timestamp())}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def user_from_token(authorization: str | None = Header(default=None)) -> dict[str, str] | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        encoded, signature = authorization.removeprefix("Bearer ").split(".", 1)
        expected = hmac.new(SECRET, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if payload["exp"] < int(time.time()):
            raise ValueError("expired")
        with db() as connection:
            row = connection.execute("SELECT id, name, email FROM users WHERE id = ?", (payload["sub"],)).fetchone()
        return dict(row) if row else None
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def require_user(user: dict[str, str] | None = Depends(user_from_token)) -> dict[str, str]:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in to use this endpoint.")
    return user


def optional_user_id(user: dict[str, str] | None = Depends(user_from_token)) -> str | None:
    return user["id"] if user else None


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class ReportRequest(BaseModel):
    verification_id: str


def assessment(verdict: str) -> str:
    if verdict == "SUSPICIOUS":
        return "The uploaded bytes or file structure are inconsistent. Do not trust this file without manual review."
    return (
        "The file passed the integrity checks performed locally, but its issuer and contents "
        "were not checked against an authoritative registry. Manual or registry verification is required "
        "to establish authenticity."
    )


def image_structure_check(content: bytes, suffix: str) -> tuple[bool, str]:
    """Perform lightweight structural checks using only the uploaded bytes."""
    if suffix == ".png":
        if len(content) < 24 or content[12:16] != b"IHDR":
            return False, "PNG is missing its required IHDR header."
        width = int.from_bytes(content[16:20], "big")
        height = int.from_bytes(content[20:24], "big")
        if not width or not height:
            return False, "PNG dimensions are invalid."
        return content.rstrip().endswith(b"IEND\xaeB`\x82"), f"PNG dimensions: {width} x {height}."

    # JPEGs are marker based. Header markers end at Start Of Scan (SOS); bytes
    # after SOS are compressed image data and must not be parsed as markers.
    # A valid stream needs a Start Of Frame marker and an End Of Image marker.
    offset, has_frame = 2, False
    while offset + 3 < len(content):
        if content[offset] != 0xFF:
            offset += 1
            continue
        marker = content[offset + 1]
        offset += 2
        if marker == 0xD9:
            break
        if marker == 0xDA:  # Start Of Scan
            if offset + 2 > len(content):
                return False, "JPEG scan header is truncated."
            scan_length = int.from_bytes(content[offset:offset + 2], "big")
            if scan_length < 2 or offset + scan_length > len(content):
                return False, "JPEG scan header is truncated."
            return has_frame and content.rstrip().endswith(b"\xff\xd9"), "JPEG contains image-frame data and an end marker."
        if marker in {0xD8, 0x01} or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(content):
            return False, "JPEG marker length is truncated."
        length = int.from_bytes(content[offset:offset + 2], "big")
        if length < 2 or offset + length > len(content):
            return False, "JPEG segment is truncated."
        if 0xC0 <= marker <= 0xC3 or 0xC5 <= marker <= 0xC7 or 0xC9 <= marker <= 0xCB or 0xCD <= marker <= 0xCF:
            has_frame = True
        offset += length
    return has_frame and content.rstrip().endswith(b"\xff\xd9"), "JPEG contains image-frame data and an end marker."


def document_structure_check(content: bytes, suffix: str) -> tuple[bool, str]:
    if suffix == ".pdf":
        has_eof = content.rstrip().endswith(b"%%EOF")
        has_objects = b"obj" in content and (b"xref" in content or b"/Type /XRef" in content)
        return has_eof and has_objects, "PDF contains its object index and end-of-file marker."
    return image_structure_check(content, suffix)


PAN_PATTERN = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z])\b", re.IGNORECASE)
AADHAAR_PATTERN = re.compile(r"(?<!\d)(\d{4}[ -]?\d{4}[ -]?\d{4})(?!\d)")


def mask_aadhaar(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"XXXX XXXX {digits[-4:]}"


def mask_pan(value: str) -> str:
    return f"{value[:3].upper()}XXXXX{value[-1].upper()}"


def ocr_available() -> bool:
    if not pytesseract:
        return False
    executable = shutil.which("tesseract")
    windows_path = Path(os.getenv("ProgramFiles", "C:/Program Files")) / "Tesseract-OCR" / "tesseract.exe"
    executable = executable or (str(windows_path) if windows_path.exists() else None)
    if not executable:
        return False
    pytesseract.pytesseract.tesseract_cmd = executable
    return True


def extract_document_data(content: bytes, suffix: str) -> dict[str, Any]:
    """Extract observable content. Never claim to identify a logo or watermark without a reference source."""
    text, metadata, qr_payloads = "", {}, []
    warnings: list[str] = []
    image_count = 0
    can_ocr = ocr_available()
    if suffix == ".pdf":
        if not fitz:
            warnings.append("PDF text extraction is unavailable; install backend requirements.")
        else:
            try:
                pdf = fitz.open(stream=content, filetype="pdf")
                text = "\n".join(page.get_text("text") for page in pdf)
                image_count = sum(len(page.get_images(full=True)) for page in pdf)
                metadata = {"creation_date": pdf.metadata.get("creationDate"), "modification_date": pdf.metadata.get("modDate"), "author": pdf.metadata.get("author"), "software": pdf.metadata.get("creator") or pdf.metadata.get("producer")}
                # Scanned PDFs have no text layer. OCR rendered pages only when the local engine exists.
                if not text.strip() and can_ocr:
                    for page in pdf:
                        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                        text += "\n" + pytesseract.image_to_string(Image.open(BytesIO(pix.tobytes("png"))))
                elif not text.strip():
                    warnings.append("This is a scanned PDF. Install Tesseract OCR to read its text.")
            except Exception:
                warnings.append("The PDF could not be read for text or embedded images.")
    elif Image:
        try:
            image = Image.open(BytesIO(content))
            image.verify()
            image = Image.open(BytesIO(content))
            image_count = 1
            metadata = {"software": image.info.get("Software"), "creation_date": image.info.get("DateTime"), "format": image.format, "dimensions": f"{image.width} x {image.height}"}
            if image.getexif():
                exif = {ExifTags.TAGS.get(key, str(key)): str(value) for key, value in image.getexif().items()}
                metadata.update({"creation_date": exif.get("DateTimeOriginal") or metadata.get("creation_date"), "software": exif.get("Software") or metadata.get("software")})
            if can_ocr:
                text = pytesseract.image_to_string(image)
            else:
                warnings.append("Install Tesseract OCR to read text from this image.")
            if cv2:
                detector = cv2.QRCodeDetector()
                payload, _, _ = detector.detectAndDecode(cv2.imdecode(__import__("numpy").frombuffer(content, dtype=__import__("numpy").uint8), cv2.IMREAD_COLOR))
                if payload:
                    qr_payloads.append(payload)
        except Exception:
            warnings.append("The image could not be decoded for OCR or metadata.")

    fields: list[dict[str, str]] = []
    for match in dict.fromkeys(AADHAAR_PATTERN.findall(text)):
        fields.append({"field": "Aadhaar number", "value": mask_aadhaar(match), "verification": "Format detected; issuer not verified"})
    for match in dict.fromkeys(PAN_PATTERN.findall(text)):
        fields.append({"field": "PAN number", "value": mask_pan(match), "verification": "Format detected; issuer not verified"})
    for payload in qr_payloads:
        fields.append({"field": "QR code", "value": payload[:500], "verification": "Payload decoded; issuer not verified"})
    return {
        "text": text.strip() or None,
        "fields": fields or None,
        "metadata": metadata,
        "image_count": image_count,
        "qr_codes": qr_payloads,
        "warnings": warnings,
        "ocr_used": can_ocr,
        # Generic logo/watermark identification needs issuer-specific reference
        # templates. Report that limitation instead of guessing from pixels.
        "visual_marks": {
            "embedded_images": image_count,
            "logo_or_watermark": "Reference comparison unavailable",
        },
    }


def analyse_document(content: bytes, upload: UploadFile, verification_id: str) -> dict[str, Any]:
    """Return measured file-integrity results; this does not establish issuer authenticity."""
    suffix = Path(upload.filename or "").suffix.lower()
    media_type = upload.content_type or "application/octet-stream"
    file_hash = hashlib.sha256(content).hexdigest()
    signature_ok = (
        (suffix in {".jpg", ".jpeg"} and content.startswith(b"\xff\xd8\xff"))
        or (suffix == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"))
        or (suffix == ".pdf" and content.startswith(b"%PDF-"))
    )
    structure_ok, structure_detail = document_structure_check(content, suffix) if signature_ok else (False, "Structure check skipped because the file signature is invalid.")
    extracted = extract_document_data(content, suffix) if signature_ok else {
        "text": None,
        "fields": None,
        "metadata": {},
        "image_count": 0,
        "qr_codes": [],
        "warnings": ["Content extraction was skipped because the file signature is invalid."],
        "ocr_used": False,
        "visual_marks": {"embedded_images": 0, "logo_or_watermark": "Not analyzed"},
    }
    with db() as connection:
        duplicate = connection.execute("SELECT id FROM verifications WHERE checksum = ? LIMIT 1", (file_hash,)).fetchone()

    indicators: list[dict[str, Any]] = [
        {
            "label": "File signature",
            "passed": signature_ok,
            "severity": "info" if signature_ok else "high",
            "description": "The binary signature matches the uploaded file extension." if signature_ok else "The file signature does not match its extension.",
        },
        {
            "label": "Integrity hash",
            "passed": True,
            "severity": "info",
            "description": "A SHA-256 hash was recorded for this uploaded file.",
        },
        {
            "label": "File structure",
            "passed": structure_ok,
            "severity": "info" if structure_ok else "high",
            "description": structure_detail if structure_ok else f"{structure_detail} The file may be incomplete or malformed.",
        },
        {
            "label": "Duplicate upload",
            "passed": duplicate is None,
            "severity": "info" if duplicate is None else "medium",
            "description": f"This exact file was previously uploaded as verification {duplicate['id']}." if duplicate else "No identical file hash exists in this local verification history.",
        },
        {
            "label": "Content extraction",
            "passed": bool(extracted["text"] or extracted["fields"] or extracted["qr_codes"]),
            "severity": "info" if extracted["text"] or extracted["fields"] or extracted["qr_codes"] else "medium",
            "description": "OCR, document identifiers, and QR payloads were scanned." if extracted["text"] or extracted["fields"] or extracted["qr_codes"] else "No readable text or machine-readable identifiers were found.",
        },
    ]
    # This score is derived from the checks above for this upload. It is an
    # integrity score, deliberately not a made-up probability of authenticity.
    integrity_score = 100 if signature_ok and structure_ok else 40 if signature_ok else 0
    verdict = "NEEDS_REVIEW" if signature_ok and structure_ok else "SUSPICIOUS"
    authentication_level = "Not authenticated"
    if not signature_ok or not structure_ok:
        authentication_level = "Low confidence"
    elif duplicate:
        authentication_level = "Review required"
    else:
        authentication_level = "Medium confidence"
    anchor_hash = "0x" + hashlib.sha256(f"{verification_id}:{file_hash}".encode()).hexdigest()
    document_type = "PDF document" if suffix == ".pdf" else "Image document"
    return {
        "id": verification_id,
        "verdict": verdict,
        "integrity_score": integrity_score,
        # Kept for older clients that still consume this field.
        "authenticity_score": integrity_score,
        "authentication_level": authentication_level,
        "document_type": document_type,
        "processing_time_ms": 0,
        "validation_checks": indicators,
        "checksum_result": {"passed": signature_ok, "algorithm": "SHA-256", "hash": file_hash},
        "cross_check_result": None,
        "analysis": {"File signature": 100 if signature_ok else 0, "File structure": 100 if structure_ok else 0},
        "extracted_text": extracted["text"],
        "extracted_fields": extracted["fields"],
        "metadata": {**extracted["metadata"], "content_type": media_type, "extension": suffix or "Not available", "sha256": file_hash, "byte_size": len(content), "ocr_used": extracted["ocr_used"], "embedded_image_count": extracted["image_count"], "qr_codes": extracted["qr_codes"], "visual_marks": extracted["visual_marks"], "warnings": extracted["warnings"]},
        "blockchain_anchor": {"tx_hash": anchor_hash, "network": "local audit ledger", "anchored_at": now()},
        "assessment": assessment(verdict),
        "verification_scope": {"issuer_registry": "not_connected", "content_claims": "not_checked"},
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> dict[str, Any]:
    user_id = str(uuid.uuid4())
    user = {"id": user_id, "name": payload.name.strip(), "email": str(payload.email).lower()}
    try:
        with db() as connection:
            connection.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", (user_id, user["name"], user["email"], password_hash(payload.password), now()))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with this email already exists.") from exc
    return {"token": token_for(user_id), "user": user}


@app.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT id, name, email, password_hash FROM users WHERE email = ?", (str(payload.email).lower(),)).fetchone()
    if not row or not password_matches(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    user = {"id": row["id"], "name": row["name"], "email": row["email"]}
    return {"token": token_for(user["id"]), "user": user}


@app.get("/auth/me")
def me(user: dict[str, str] = Depends(require_user)) -> dict[str, str]:
    return user


@app.post("/extract-and-validate")
async def extract_and_validate(file: UploadFile = File(...), document_type: str | None = Form(default=None), user_id: str | None = Depends(optional_user_id)) -> dict[str, Any]:
    suffix = Path(file.filename or "").suffix.lower()
    if file.content_type not in ALLOWED_MEDIA_TYPES and suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=415, detail="Upload a JPG, PNG, or PDF file.")
    content = await file.read(MAX_FILE_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB limit.")
    started = time.perf_counter()
    verification_id = str(uuid.uuid4())
    result = analyse_document(content, file, verification_id)
    if document_type and document_type.strip():
        result["document_type"] = document_type.strip()
    result["processing_time_ms"] = round((time.perf_counter() - started) * 1000)
    stored = {**result, "file_name": file.filename, "file_size": len(content), "uploaded_at": now()}
    with db() as connection:
        connection.execute(
            "INSERT INTO verifications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (verification_id, user_id, file.filename or "document", len(content), stored["uploaded_at"], result["document_type"], result["verdict"], result["authenticity_score"], result["processing_time_ms"], result["checksum_result"]["hash"], result["blockchain_anchor"]["tx_hash"], json.dumps(stored)),
        )
    return result


def result_for_row(row: sqlite3.Row) -> dict[str, Any]:
    return json.loads(row["result_json"])


@app.get("/verification/history")
def verification_history(user: dict[str, str] = Depends(require_user)) -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM verifications WHERE user_id = ? ORDER BY uploaded_at DESC", (user["id"],)).fetchall()
    return [result_for_row(row) for row in rows]


@app.get("/verification/{verification_id}")
def get_verification(verification_id: str, user: dict[str, str] = Depends(require_user)) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM verifications WHERE id = ? AND user_id = ?", (verification_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Verification not found.")
    return result_for_row(row)


@app.get("/dashboard/stats")
def dashboard_stats(user: dict[str, str] = Depends(require_user)) -> dict[str, Any]:
    records = verification_history(user)
    counts = {"total": len(records), "valid": 0, "suspicious": 0, "invalid": 0, "unknown": 0}
    mapping = {"AUTHENTIC": "valid", "SUSPICIOUS": "suspicious", "FAKE": "invalid"}
    for record in records:
        counts[mapping.get(record["verdict"], "unknown")] += 1
    return {**counts, "recent": records[:8]}


@app.get("/verify-blockchain-anchor/{identifier}")
def verify_anchor(identifier: str) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT id, anchor_hash, checksum, uploaded_at FROM verifications WHERE anchor_hash = ?", (identifier,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Audit anchor was not found.")
    return {"verified": True, "verification_id": row["id"], "anchor": row["anchor_hash"], "sha256": row["checksum"], "recorded_at": row["uploaded_at"], "network": "local audit ledger"}


def pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def simple_pdf(lines: list[str]) -> bytes:
    content = "BT\n/F1 12 Tf\n50 760 Td\n" + "\n".join(f"({pdf_escape(line)}) Tj\n0 -20 Td" for line in lines) + "\nET"
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", f"<< /Length {len(content.encode())} >>\nstream\n{content}\nendstream", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    output = "%PDF-1.4\n"
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output.encode()))
        output += f"{index} 0 obj\n{obj}\nendobj\n"
    xref = len(output.encode())
    output += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n" + "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    output += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return output.encode()


@app.post("/generate-audit-report")
def generate_audit_report(payload: ReportRequest, user: dict[str, str] = Depends(require_user)) -> Response:
    with db() as connection:
        row = connection.execute("SELECT * FROM verifications WHERE id = ? AND user_id = ?", (payload.verification_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Verification not found.")
    record = result_for_row(row)
    lines = ["VeriGate verification report", f"Verification ID: {record['id']}", f"File: {row['file_name']}", f"Verdict: {record['verdict']}", f"File integrity score: {record['authenticity_score']}%", f"SHA-256: {row['checksum']}", f"Audit anchor: {row['anchor_hash']}", "The issuer registry was not checked; this is not proof of authenticity."]
    return Response(content=simple_pdf(lines), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="verigate-report-{record["id"]}.pdf"'})
