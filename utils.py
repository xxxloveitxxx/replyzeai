# utils.py
from requests import post
import os

def callAIML_from_flask(prompt: str) -> str:
    GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
    MODELS = os.environ.get("GH_MODELS", "openai/gpt-4o-mini").split(",")
    for model in MODELS:
        resp = post(
            "https://models.github.ai/inference/chat/completions",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json"
            },
            json={
                "model": model.strip(),
                "messages": [
                    {"role": "system", "content": "You are a professional real estate agent."},
                    {"role": "user",   "content": prompt}
                ],
                "temperature": 0.7,
                "top_p": 0.7,
                "max_tokens": 512
            },
            timeout=300
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        if resp.status_code in (404, 429):
            continue
        resp.raise_for_status()
    raise RuntimeError("All models failed or were rate‑limited")
