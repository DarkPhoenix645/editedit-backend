from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import ForensicCase, ForensicHypothesis, HotColdTrace, HypothesisEvidenceMap
from app.services.sealing_service import verify_sealed_block


@dataclass
class DossierArtifact:
    job_id: str
    created_at: datetime
    case_id: UUID
    payload: dict[str, Any]
    pdf_bytes: bytes


def _to_pdf_text_bytes(lines: list[str]) -> bytes:
    # Minimal single-page PDF writer (ASCII text only), enough for MVP artifact.
    escaped = [ln.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for ln in lines]
    text_ops = ["BT /F1 10 Tf 40 800 Td 14 TL"]
    for ln in escaped:
        text_ops.append(f"({ln[:160]}) Tj T*")
    text_ops.append("ET")
    stream = "\n".join(text_ops).encode("ascii", errors="ignore")

    objs = []
    objs.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objs.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj")
    objs.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj"
    )
    objs.append(b"4 0 obj << /Length " + str(len(stream)).encode() + b" >> stream\n" + stream + b"\nendstream endobj")
    objs.append(b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj")

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objs:
        offsets.append(out.tell())
        out.write(obj + b"\n")
    xref_start = out.tell()
    out.write(f"xref\n0 {len(offsets)}\n".encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(
        f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode()
    )
    return out.getvalue()


def build_case_dossier(db: Session, case_id: UUID) -> dict[str, Any]:
    case_row = db.get(ForensicCase, case_id)
    if case_row is None:
        raise ValueError("Case not found")
    hyps = (
        db.query(ForensicHypothesis)
        .filter(ForensicHypothesis.case_id == case_id)
        .order_by(ForensicHypothesis.created_at.asc())
        .all()
    )
    sections: list[dict[str, Any]] = []
    seen_block_ids: set[str] = set()
    crypto_verification: list[dict[str, Any]] = []
    for h in hyps:
        ev_count = (
            db.query(HypothesisEvidenceMap).filter(HypothesisEvidenceMap.hypothesis_id == h.id).count()
        )
        sections.append(
            {
                "hypothesis_id": str(h.id),
                "hypothesis_uid": h.hypothesis_uid,
                "scenario_id": h.scenario_id,
                "title": h.title or h.hypotheses or "Untitled",
                "confidence_score": float(h.confidence_score or 0.0),
                "severity": "CRITICAL"
                if (h.confidence_score or 0.0) >= 0.7
                else "HIGH"
                if (h.confidence_score or 0.0) >= 0.5
                else "MEDIUM"
                if (h.confidence_score or 0.0) >= 0.3
                else "LOW",
                "mitre": {
                    "id": h.mitre_technique_id,
                    "name": h.mitre_technique_name,
                    "tactic": h.mitre_tactic,
                },
                "reasoning_chain": list(h.neuro_symbolic_reasoning_chain or []),
                "cryptographic_evidence_snippet": h.cryptographic_evidence_snippet,
                "evidence_count": int(ev_count),
                "created_at": (h.created_at or datetime.now(timezone.utc)).isoformat(),
            }
        )
        links = db.query(HypothesisEvidenceMap).filter(HypothesisEvidenceMap.hypothesis_id == h.id).all()
        for link in links:
            fp = link.event_fingerprint or link.elastic_event_id
            if not fp:
                continue
            trace = db.query(HotColdTrace).filter(HotColdTrace.event_fingerprint == fp).first()
            if not trace:
                continue
            bid = str(trace.block_id)
            if bid in seen_block_ids:
                continue
            seen_block_ids.add(bid)
            vr = verify_sealed_block(db, trace.block_id)
            crypto_verification.append(
                {
                    "block_id": bid,
                    "verified": bool(vr.get("verified")),
                    "message": str(vr.get("message", "")),
                }
            )
    return {
        "case": {
            "id": str(case_row.id),
            "name": case_row.case_name,
            "description": case_row.description,
            "status": case_row.status,
            "origin": case_row.origin,
            "auto_generated": bool(case_row.auto_generated),
            "created_at": case_row.created_at.isoformat() if case_row.created_at else None,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hypotheses": sections,
        "crypto_verification": crypto_verification,
    }


def build_case_dossier_pdf(payload: dict[str, Any]) -> bytes:
    lines: list[str] = []
    case = payload.get("case", {})
    lines.append("Forensic Investigation Dossier")
    lines.append(f"Case: {case.get('name')} [{case.get('id')}]")
    lines.append(f"Status: {case.get('status')}  Origin: {case.get('origin')}")
    lines.append(f"Generated: {payload.get('generated_at')}")
    lines.append(" ")
    for idx, hyp in enumerate(payload.get("hypotheses", []), start=1):
        lines.append(f"{idx}. {hyp.get('title')} (Scenario {hyp.get('scenario_id')})")
        lines.append(
            f"   confidence={hyp.get('confidence_score')} severity={hyp.get('severity')} evidence={hyp.get('evidence_count')}"
        )
        mitre = hyp.get("mitre") or {}
        lines.append(f"   MITRE: {mitre.get('id')} {mitre.get('name')} / {mitre.get('tactic')}")
        snippet = hyp.get("cryptographic_evidence_snippet")
        if snippet:
            lines.append(f"   Crypto: {snippet}")
    lines.append(" ")
    lines.append("Block Verification:")
    for vr in payload.get("crypto_verification", []):
        lines.append(
            f"- block={vr.get('block_id')} verified={vr.get('verified')} msg={vr.get('message')}"
        )
    return _to_pdf_text_bytes(lines)
