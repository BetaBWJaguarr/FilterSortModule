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
    def __init__(self, default_ttl_seconds=300, expiry_callback=None):
        self.cache = {}
        self.default_ttl_seconds = default_ttl_seconds
        self.expiry_callback = expiry_callback
        self.hits = 0
        self.misses = 0

    def _generate_cache_key(self, *args, **kwargs):
        key_parts = [json.dumps(arg, sort_keys=True) for arg in args]
        key_parts.append(json.dumps(kwargs, sort_keys=True))
        key_string = ''.join(key_parts)
        hash_object = hashlib.sha256(key_string.encode())
        hex_dig = hash_object.hexdigest()
        print(f"Generated cache key {hex_dig} for args {args} and kwargs {kwargs}".encode('utf-8'))
        return hex_dig

    def _get_from_cache(self, cache_key):
        cached_data = self.cache.get(cache_key, None)
        if cached_data:
            data, expiry_time, hit_count = cached_data
            if datetime.now() < expiry_time:
                self.cache[cache_key] = (data, expiry_time, hit_count + 1)
                self.hits += 1
                return data
            else:
                self._handle_expiry(cache_key)
        self.misses += 1
        return None

    def _handle_expiry(self, cache_key):
        if self.expiry_callback:
            self.expiry_callback(cache_key, self.cache[cache_key][0])
        self.cache.pop(cache_key)

    def get(self, *args, **kwargs):
        cache_key = self._generate_cache_key(*args, **kwargs)
        return self._get_from_cache(cache_key)

    def set(self, data, ttl_seconds=None, *args, **kwargs):
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl_seconds
        cache_key = self._generate_cache_key(*args, **kwargs)
        self._set_to_cache(cache_key, data, ttl_seconds)

    def _set_to_cache(self, cache_key, data, ttl_seconds):
        if cache_key in self.cache:
            print(f"Warning: Overwriting data in cache for key {cache_key}")
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        self.cache[cache_key] = (data, expiry_time, 0)
        print(f"Data set to cache with key {cache_key}. Expiry time: {expiry_time}")
        self.print_cache()
        self.clear_expired()

    def clear(self):
        self.cache = {}
        print("Cache cleared.")

    def clear_expired(self):
        expired_keys = [key for key, (_, expiry_time, _) in self.cache.items() if datetime.now() > expiry_time]
        for key in expired_keys:
            self._handle_expiry(key)
        if expired_keys:
            print(f"Cleared {len(expired_keys)} expired items from cache.")
        else:
            print("No expired items in the cache.")

    def get_all_keys(self):
        return list(self.cache.keys())

    def get_statistics(self):
        return {
            "total_items": len(self.cache),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0
        }

    def print_cache(self):
        try:
            print(self.cache)
        except UnicodeEncodeError:
            print(self.cache.encode('utf-8'))
