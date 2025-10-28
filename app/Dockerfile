# app/Dockerfile
FROM python:3.14-slim

# Create work dir
WORKDIR /app

# Install Flask (you can add more libs later)
RUN pip install --no-cache-dir flask cryptography

# Copy your app file into the image
COPY main.py /app/main.py

# Expose the app port (the proxy will talk to this)
EXPOSE 8000

# Start the Flask app
CMD ["python", "/app/main.py"]
