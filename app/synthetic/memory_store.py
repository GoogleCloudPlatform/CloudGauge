# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""An in-memory stand-in for the results bucket's ``storage.Client``.

``memory_results_store()`` returns the real :class:`GcsResultsStore` wired to
this client, so the offline harness and the tests exercise the store's actual
code (object names, JSON encoding, listing order, cleanup) without Cloud
Storage. Only the methods the store uses are implemented. Thread-safe: the
runner's check threads write findings concurrently.

The client also counts operations (``writes``, ``reads``, ``lists``,
``deletes``, ``bytes_written``): one finding is one object in the real bucket,
so these numbers are the GCS write load a scan of that size would generate.
"""
import threading
from collections import Counter

from google.api_core.exceptions import PreconditionFailed

from app.services.results_store import GcsResultsStore

DEFAULT_BUCKET = "synthetic-results"


class MemoryBlob:
    def __init__(self, bucket, name):
        self._bucket, self.name = bucket, name

    def upload_from_string(self, data, content_type=None, if_generation_match=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        with self._bucket._lock:
            if if_generation_match == 0 and self.name in self._bucket._objects:
                raise PreconditionFailed(f"412 object {self.name} already exists")
            self._bucket._objects[self.name] = (data, content_type)
            self._bucket.stats["writes"] += 1
            self._bucket.stats["bytes_written"] += len(data)

    def download_as_text(self):
        with self._bucket._lock:
            self._bucket.stats["reads"] += 1
            data, _ = self._bucket._objects[self.name]
        return data.decode("utf-8")

    def exists(self):
        with self._bucket._lock:
            return self.name in self._bucket._objects


class MemoryBucket:
    def __init__(self, name):
        self.name = name
        self._objects = {}  # insertion-ordered, like the fakes used by the test suite
        self._lock = threading.Lock()
        self.stats = Counter()

    def blob(self, name):
        return MemoryBlob(self, name)

    def list_blobs(self, prefix=""):
        with self._lock:
            self.stats["lists"] += 1
            names = [name for name in self._objects if name.startswith(prefix)]
        return [MemoryBlob(self, name) for name in names]

    def delete_blobs(self, blobs):
        with self._lock:
            for blob in blobs:
                if self._objects.pop(blob.name, None) is not None:
                    self.stats["deletes"] += 1

    def object_names(self, prefix=""):
        with self._lock:
            return [name for name in self._objects if name.startswith(prefix)]

    def size_of(self, name):
        with self._lock:
            return len(self._objects[name][0])


class MemoryStorageClient:
    """``storage.Client`` for ``GcsResultsStore``: ``bucket(name)`` and nothing else."""

    def __init__(self):
        self._buckets = {}
        self._lock = threading.Lock()

    def bucket(self, name):
        with self._lock:
            return self._buckets.setdefault(name, MemoryBucket(name))

    def stats(self):
        """Operation counts summed over every bucket."""
        total = Counter()
        for bucket in self._buckets.values():
            total.update(bucket.stats)
        return dict(total)


def memory_results_store(bucket_name=DEFAULT_BUCKET):
    """A :class:`GcsResultsStore` on a fresh :class:`MemoryStorageClient`."""
    return GcsResultsStore(bucket_name, client=MemoryStorageClient())
