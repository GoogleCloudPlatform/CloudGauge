# Step 1: Use an official, slim Python base image for a smaller footprint
FROM python:3.11-slim

# Step 2: Set environment variables
# Prevents Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE 1
# Ensures Python output is sent straight to the terminal without buffering
ENV PYTHONUNBUFFERED 1

# Step 3: Set the working directory inside the container
WORKDIR /app

# Step 4: Copy the requirements file and install dependencies
# This is done in a separate step to leverage Docker's layer caching.
# The dependencies will only be re-installed if requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the rest of your application code into the container
COPY . .

# Step 6: Define the command to run your application
# Use Gunicorn as a production-grade WSGI server, not Flask's built-in server.
# It will listen on the port defined by the PORT environment variable, which Cloud Run sets automatically.
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "0", "cloudgauge_beta_v25:app"]
