"""Recording and replaying Claude's review responses.

The harness hands llm.review() a stand-in client, so the app's own prompt
building, parsing, quote verification and merge all run unchanged. The
stand-in either calls the real API and saves what came back (live), or returns
a saved response (offline). Each recording carries a hash of the exact request
(model, system prompt, documents, rules, output schema). If the prompt or the
rules change, old recordings no longer match and are reported as stale rather
than silently scored against a prompt they were not produced by."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app.llm import Review

RECORDINGS_DIR = Path(__file__).resolve().parent / "recordings"


class StaleRecording(LookupError):
    pass


class MissingRecording(LookupError):
    pass


class RecordedError(RuntimeError):
    """The live call failed when it was recorded; replayed as a failure."""


def request_hash(kwargs: dict) -> str:
    material = {
        "model": kwargs.get("model"),
        "system": kwargs.get("system"),
        "messages": kwargs.get("messages"),
        "max_tokens": kwargs.get("max_tokens"),
        "output_config": kwargs.get("output_config"),
        "schema": Review.model_json_schema(),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()[:20]


def recording_path(root: Path, case_id: str, trial: int) -> Path:
    return root / f"{case_id}__t{trial}.json"


class _Messages:
    def __init__(self, owner: "EvalClient"):
        self.parse = owner._parse


class EvalClient:
    """Duck-types the part of anthropic.Anthropic that llm.review() uses.

    mode "live":   forward to the real client and write a recording.
    mode "replay": serve the recording for (case, trial); never touches the network.
    A response is cached in memory per request hash, so asking twice in one run
    (once for the raw model layer, once through analysis.analyze) costs one call."""

    def __init__(self, mode: str, root: Path, *, real=None, allow_stale: bool = False):
        assert mode in ("live", "replay")
        if mode == "live" and real is None:
            raise ValueError("live mode needs a real anthropic client")
        self.mode, self.root, self.real, self.allow_stale = mode, root, real, allow_stale
        self.case_id, self.trial = "", 1
        self._cache: dict[str, object] = {}
        self.last: dict = {}
        self.beta = SimpleNamespace(messages=_Messages(self))

    def use(self, case_id: str, trial: int = 1):
        self.case_id, self.trial = case_id, trial
        self.last = {}

    # -- the one call llm.review makes --
    def _parse(self, **kwargs):
        h = request_hash(kwargs)
        key = f"{self.case_id}/{self.trial}/{h}"
        if key in self._cache:
            return self._cache[key]
        resp = self._live(kwargs, h) if self.mode == "live" else self._replay(kwargs, h)
        self._cache[key] = resp
        return resp

    def _live(self, kwargs: dict, h: str):
        started = time.monotonic()
        rec = {
            "case_id": self.case_id, "trial": self.trial, "request_hash": h,
            "requested_model": kwargs.get("model"), "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": "live",
        }
        try:
            resp = self.real.beta.messages.parse(**kwargs)
        except Exception as exc:
            rec.update(error=type(exc).__name__, seconds=round(time.monotonic() - started, 2))
            self._write(rec)
            self.last = rec
            raise
        parsed = resp.parsed_output
        usage = getattr(resp, "usage", None)
        rec.update(
            served_model=getattr(resp, "model", None),
            stop_reason=resp.stop_reason,
            seconds=round(time.monotonic() - started, 2),
            usage={k: getattr(usage, k, None) for k in ("input_tokens", "output_tokens")} if usage else None,
            parsed_output=parsed.model_dump() if parsed is not None else None,
        )
        self._write(rec)
        self.last = rec
        return resp

    def _replay(self, kwargs: dict, h: str):
        p = recording_path(self.root, self.case_id, self.trial)
        if not p.is_file():
            raise MissingRecording(p.name)
        rec = json.loads(p.read_text(encoding="utf-8"))
        if rec.get("request_hash") != h and not self.allow_stale:
            raise StaleRecording(f"{p.name} was recorded for request {rec.get('request_hash')}, the app now sends {h}")
        self.last = rec
        if rec.get("error"):
            raise RecordedError(rec["error"])
        parsed = Review.model_validate(rec["parsed_output"]) if rec.get("parsed_output") is not None else None
        return SimpleNamespace(stop_reason=rec.get("stop_reason"), parsed_output=parsed, model=rec.get("served_model"))

    def _write(self, rec: dict):
        self.root.mkdir(parents=True, exist_ok=True)
        recording_path(self.root, rec["case_id"], rec["trial"]).write_text(json.dumps(rec, indent=1) + "\n", encoding="utf-8")
