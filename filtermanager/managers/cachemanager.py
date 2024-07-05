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
        return hash(tuple(key_parts))

    def _get_from_cache(self, cache_key):
        cached_data = self.cache.get(cache_key, None)
        if cached_data:
            data, expiry_time = cached_data
            if datetime.now() < expiry_time:
                return data
            else:
                self.cache.pop(cache_key)
        return None

    def _set_to_cache(self, cache_key, data, ttl_seconds=300):
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        self.cache[cache_key] = (data, expiry_time)
        print(f"Data set to cache with key {cache_key}.")
        self.print_cache()

    def print_cache(self):
        print(self.cache)
