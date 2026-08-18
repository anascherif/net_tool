# ERREETOOL Docker Image
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whatweb \
    gobuster \
    sqlmap \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei from GitHub releases
ENV NUCLEI_VERSION=v3.3.7
RUN wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/ \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml .
COPY requirements.txt .
COPY erreetool/ ./erreetool/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 erreetool && chown -R erreetool:erreetool /app
USER erreetool

# Set entrypoint
ENTRYPOINT ["erreetool"]
CMD ["--help"]