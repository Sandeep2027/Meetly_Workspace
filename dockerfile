# Use the official Python runtime
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the application source code directly into the container
COPY . /app

# Install FastAPI and Uvicorn packages required to execute the framework
RUN pip install --no-cache-dir fastapi uvicorn

# Expose a default fallback port documentation-wise
EXPOSE 10000

# Execute uvicorn using the requested command style with Render environment requirements
CMD ["sh", "-c", "uvicorn main:app --reload --host 0.0.0.0 --port ${PORT:-10000}"]
