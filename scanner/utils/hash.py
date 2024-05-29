
from typing import Callable
import hashlib

HASH_CHUNK_SIZE = 8192


def calculate_hash(file_path: str, hash_method: Callable) -> str:
    hash_obj = hash_method()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def get_file_digest(full_path: str, *hash_names) -> dict[str, str]:
    hash_methods = {name: getattr(hashlib, name)() for name in hash_names if hasattr(hashlib, name)}
    with open(full_path, 'rb') as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            for hash_obj in hash_methods.values():
                hash_obj.update(chunk)
    return {name: hash_obj.hexdigest() for name, hash_obj in hash_methods.items()}
