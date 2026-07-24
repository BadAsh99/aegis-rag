"""AEGIS — a RAG pipeline where sensitive data is never exposed in raw form.

Sensitive fields are tokenized on ingest (Protegrity Developer Edition), stay
protected through embedding, vector storage, retrieval, and LLM inference, and
are detokenized only for policy-authorized output. Breach the vector store or
dump the prompt logs and you get tokens, not people.

Built for the 2026 Protegrity AI Pipeline Security Hackathon — track:
"Architect AI without exposure."  handle: BadAsh99
"""
__version__ = "0.1.0"
