FROM python:3.11-slim
WORKDIR /app

# (Optional but recommended) system build deps for crypto libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential python3-dev libffi-dev libsodium-dev \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies from requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY . .

EXPOSE 8001
CMD ["python","-u","main.py"]
