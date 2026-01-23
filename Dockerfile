# Build Stage for Katana
FROM projectdiscovery/katana:latest AS builder

# Final Stage
FROM python:3.9-alpine

# Install system dependencies
# whois: for whois module
# git: often needed for some python deps
RUN apk add --no-cache \
    whois \
    git

# Copy Katana from builder
COPY --from=builder /usr/local/bin/katana /usr/local/bin/katana

# Make sure it's executable
RUN chmod +x /usr/local/bin/katana

# Verify it's in path
RUN which katana

# Set working directory
WORKDIR /app

# Copy requirements first to leverage cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create Results directory
RUN mkdir -p Results reports

# Set entrypoint
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
