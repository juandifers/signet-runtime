"""Voice intake (Spec 04 Part 3) — push-to-talk, a SECOND front-end to `select_scope`.

This is never a separate authority path: voice only produces the same free-text *request*
that typing does (Part 1), which `select_scope` still maps to a frozen menu key under the
ceiling. Flag-gated (`SIGNET_VOICE=1`), OFF by default.

PUSH-TO-TALK, not realtime: ENTER to start recording, speak, ENTER to stop. We capture mic
audio to a temp wav (sounddevice) and transcribe with ElevenLabs
`speech_to_text.convert(model_id="scribe_v2")`. No VAD / streaming — too fragile for a live demo.

GRACEFUL DEGRADATION IS THE WHOLE POINT: any failure (SDK/mic libs missing, no
ELEVENLABS_API_KEY, mic open error, empty audio, network/STT error) returns None and prints a
one-line reason. The caller (operator.acquire_operator_request) then falls back to the typed
prompt. The run must never crash or hang because voice failed.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import wave
from pathlib import Path
from typing import Optional

_SAMPLE_RATE = 16000


def voice_enabled() -> bool:
    return bool(os.environ.get("SIGNET_VOICE"))


async def capture_voice_request() -> Optional[str]:
    """Push-to-talk capture + transcribe. Returns the transcript, or None on ANY failure
    (caller falls back to typing). Never raises."""
    try:
        import sounddevice as sd          # noqa: F401  (heavy import; only when voice is on)
        import numpy as np
    except Exception as e:
        print(f"[voice] mic/audio libs unavailable ({e}); falling back to typing.")
        return None

    loop = asyncio.get_event_loop()
    print(">>> [operator/voice] press ENTER to START recording (or just type instead): ",
          end="", flush=True)
    # A non-empty first line means the operator chose to type — bail to the typed path.
    first = await loop.run_in_executor(None, sys.stdin.readline)
    if first.strip():
        print(f"[voice] typed input detected; using it: {first.strip()!r}")
        return first.strip()

    frames = []

    def _cb(indata, _n, _t, _status):
        frames.append(indata.copy())

    try:
        stream = sd.InputStream(samplerate=_SAMPLE_RATE, channels=1, dtype="int16", callback=_cb)
        stream.start()
    except Exception as e:
        print(f"[voice] cannot open microphone ({e}); falling back to typing.")
        return None

    print("    🎙️  recording… press ENTER to STOP.", flush=True)
    await loop.run_in_executor(None, sys.stdin.readline)
    try:
        stream.stop(); stream.close()
    except Exception:
        pass

    if not frames:
        print("[voice] no audio captured; falling back to typing.")
        return None

    audio = np.concatenate(frames, axis=0)
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".wav", prefix="signet_voice_")
        os.close(fd)
        with wave.open(path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)              # int16
            w.setframerate(_SAMPLE_RATE)
            w.writeframes(audio.tobytes())
        return _transcribe(path)
    except Exception as e:
        print(f"[voice] capture/encode failed ({e}); falling back to typing.")
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def _transcribe(path: str) -> Optional[str]:
    """ElevenLabs scribe_v2 STT. Returns stripped text, or None on any failure."""
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        print("[voice] ELEVENLABS_API_KEY not set; falling back to typing.")
        return None
    try:
        from elevenlabs.client import ElevenLabs
        client = ElevenLabs(api_key=key)
        with open(path, "rb") as f:
            resp = client.speech_to_text.convert(file=f, model_id="scribe_v2")
        text = (getattr(resp, "text", None) or "").strip()
        if not text:
            print("[voice] transcript empty; falling back to typing.")
            return None
        return text
    except Exception as e:
        print(f"[voice] STT failed ({e}); falling back to typing.")
        return None
