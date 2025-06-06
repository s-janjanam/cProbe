import json
import threading

class JSONSettings:
    def __init__(self, filename):
        self.filename = filename
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        with self._lock:
            try:
                with open(self.filename, 'r') as f:
                    self._data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self._data = {}

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        with self._lock:
            self._data[key] = value
            with open(self.filename, 'w') as f:
                json.dump(self._data, f, indent=2)

    def as_dict(self):
        return dict(self._data)
