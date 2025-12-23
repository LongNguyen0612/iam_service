FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install uv

# Copy service files
COPY . /app

# Install dependencies
RUN uv sync

CMD ["uv", "run", "api.py"]
