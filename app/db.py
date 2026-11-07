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

    # ---- faces

    def claim_faces(self, limit: int) -> list[dict]:
        return self._rpc("claim_photos_for_faces", {"p_limit": limit}) or []

    def save_faces(self, photo_id: str, model: str, faces: list[dict]) -> int:
        return int(self._rpc("save_photo_faces", {"p_photo_id": photo_id, "p_model": model, "p_faces": faces}) or 0)

    def fail_faces(self, photo_id: str, error: str) -> None:
        self._rpc("fail_photo_faces", {"p_photo_id": photo_id, "p_error": error})

    # ---- maintenance

    def mark_abandoned_uploads(self) -> int:
        return int(self._rpc("mark_abandoned_uploads", {}) or 0)

    def expire_face_data(self) -> int:
        return int(self._rpc("expire_face_data", {}) or 0)

    def deletable_photo_files(self, limit: int) -> list[dict]:
        return self._rpc("list_deletable_photo_files", {"p_limit": limit}) or []

    def mark_photo_files_deleted(self, photo_ids: list[str]) -> int:
        return int(self._rpc("mark_photo_files_deleted", {"p_photo_ids": photo_ids}) or 0)

    def search(self, event_id: str, embedding: str, threshold: float, limit: int) -> list[dict]:
        """Raises httpx.HTTPStatusError; a disabled event comes back as message 'search_disabled'."""
        return self._rpc("search_event_faces", {
            "p_event_id": event_id, "p_embedding": embedding, "p_threshold": threshold, "p_limit": limit,
        }) or []
