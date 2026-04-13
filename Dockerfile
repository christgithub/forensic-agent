# Use Python 3.11 slim image
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 procps && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir watchdog watchfiles python-magic

# Create watched directory
RUN mkdir -p watched_directory

# Run the application
CMD ["python", "main.py"]
