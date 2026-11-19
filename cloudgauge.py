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
"""Entrypoint: ``gunicorn cloudgauge:app`` (the Dockerfile) or ``python cloudgauge.py``.

The application lives in the ``app`` package; see ``app.create_app``. This
module keeps the upstream entrypoint name, so existing deploy commands still
work. It builds the app in the production profile. For local development, use
``python run.py`` instead.
"""
import os

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))