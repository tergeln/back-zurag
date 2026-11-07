"""Calls the worker-only database functions through Supabase's REST API, using the secret key."""

import httpx

from .config import Settings


class Db:
    def __init__(self, s: Settings):
        self.http = httpx.Client(
            base_url=f"{s.supabase_url}/rest/v1",
            headers={"apikey": s.supabase_secret_key, "Content-Type": "application/json"},
            timeout=30,
        )

    def _rpc(self, name: str, args: dict):
        res = self.http.post(f"/rpc/{name}", json=args)
        res.raise_for_status()
        return res.json() if res.content else None

    def claim(self, limit: int) -> list[dict]:
        return self._rpc("claim_photos_for_processing", {"p_limit": limit}) or []

    def complete(self, photo_id: str, preview_key: str, thumb_key: str, width: int, height: int) -> None:
        self._rpc("complete_photo_processing", {
            "p_photo_id": photo_id, "p_preview_key": preview_key, "p_thumb_key": thumb_key,
            "p_width": width, "p_height": height,
        })

    def fail(self, photo_id: str, error: str) -> None:
        self._rpc("fail_photo_processing", {"p_photo_id": photo_id, "p_error": error})
