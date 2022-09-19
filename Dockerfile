FROM python:3-alpine

WORKDIR /usr/src/app
ENV DNS_ZONE_TEMPLATE_PATH=/usr/src/app/templates

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "/usr/src/app/dns-zone.py" ]