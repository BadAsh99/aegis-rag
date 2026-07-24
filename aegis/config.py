"""Runtime config — swap mock <-> real via environment flags. See .env.example.

The whole point of AEGIS: the pipeline is identical whether it runs on the
MockProtector (today, offline) or Protegrity Developer Edition (once access
lands). Only these flags change.
"""
import os


def _env(name, default):
    return os.getenv(name, default)


# mock | protegrity   -- which data-protection backend
PROTECTOR = _env("AEGIS_PROTECTOR", "mock")

# hash | minilm       -- hash = zero-dep (numpy only), minilm = sentence-transformers
EMBEDDER = _env("AEGIS_EMBEDDER", "hash")
MINILM_MODEL = _env("AEGIS_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

# mock | openai | anthropic
LLM_PROVIDER = _env("AEGIS_LLM", "mock")
LLM_MODEL = _env("AEGIS_LLM_MODEL", "")

TOP_K = int(_env("AEGIS_TOP_K", "3"))
DATA_PATH = _env("AEGIS_DATA", "data/sample_records.json")
