# Step 1: Use an official, slim Python base image for a smaller footprint
FROM python:3.11-slim

# Step 2: Set environment variables
# Prevents Python from writing pyc files to disc
# Ensures Python output is sent straight to the terminal without buffering
# PORT: Cloud Run always sets it; 8080 is the default for a plain `docker run`
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Step 3: Set the working directory inside the container
WORKDIR /app

# Step 4: Copy the requirements file and install dependencies
# This is done in a separate step to leverage Docker's layer caching.
# The dependencies will only be re-installed if requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the application: the Flask package (code and templates) and the
# cloudgauge.py entrypoint shim. Tests, run.py, and dev files stay out of the image.
COPY app ./app
COPY cloudgauge.py .

# Step 6: Run as an unprivileged user. It needs a home directory: gunicorn's
# control server keeps its socket under $HOME.
RUN useradd --system --uid 10001 --create-home cloudgauge
USER cloudgauge

# Step 7: Define the command to run your application
# Gunicorn (a production-grade WSGI server, not Flask's built-in server) serves
# the app that cloudgauge.py builds with create_app(). The shell form expands
# $PORT; `exec` replaces the shell, so gunicorn is PID 1 and receives Cloud
# Run's SIGTERM for a graceful shutdown. One worker with 8 threads: scans run in
# threads, and --timeout 0 leaves request time limits to Cloud Run.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 cloudgauge:app
