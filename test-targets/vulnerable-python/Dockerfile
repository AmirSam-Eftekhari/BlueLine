FROM python:latest
ADD https://example.invalid/installer.sh /tmp/installer.sh
RUN chmod +x /tmp/installer.sh
USER root
COPY . /app
WORKDIR /app
CMD ["python", "app_vuln.py"]
