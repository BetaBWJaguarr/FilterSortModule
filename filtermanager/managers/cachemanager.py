import hashlib
from datetime import datetime, timedelta
import json

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class CacheManager(metaclass=Singleton):
    def __init__(self):
        self.cache = {}

    def _generate_cache_key(self, *args, **kwargs):
        key_parts = [json.dumps(arg, sort_keys=True) for arg in args]
        key_parts.append(json.dumps(kwargs, sort_keys=True))
        key_string = ''.join(key_parts)
        hash_object = hashlib.sha256(key_string.encode())
        hex_dig = hash_object.hexdigest()
        print(f"Generated cache key {hex_dig} for args {args} and kwargs {kwargs}")
        return hex_dig

    def _get_from_cache(self, cache_key):
        cached_data = self.cache.get(cache_key, None)
        if cached_data:
            data, expiry_time = cached_data
            if datetime.now() < expiry_time:
                return data
            else:
                self.cache.pop(cache_key)
        return None

    def set(self, data, ttl_seconds=300, *args, **kwargs):
        cache_key = self._generate_cache_key(*args, **kwargs)
        self._set_to_cache(cache_key, data, ttl_seconds)

    def _set_to_cache(self, cache_key, data, ttl_seconds=300):
        if cache_key in self.cache:
            print(f"Warning: Overwriting data in cache for key {cache_key}")
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        self.cache[cache_key] = (data, expiry_time)
        print(f"Data set to cache with key {cache_key}. Expiry time: {expiry_time}")
        self.print_cache()
        self.clear_expired()

    def clear(self):
        self.cache = {}
        print("Cache cleared.")

    def clear_expired(self):
        expired_keys = [key for key, (_, expiry_time) in self.cache.items() if datetime.now() > expiry_time]
        for key in expired_keys:
            self.cache.pop(key)
        print(f"Cleared {len(expired_keys)} expired items from cache.")

    def print_cache(self):
        print(self.cache)
