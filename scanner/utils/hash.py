
from typing import Callable
import hashlib

HASH_CHUNK_SIZE = 4096


def calculate_hash(file_path: str, hash_method: Callable) -> str:
    hash_obj = hash_method()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()