from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import requests
import validators
import whois
import ssl
import socket
from OpenSSL import crypto
from datetime import datetime
from urllib.parse import urlparse

app = FastAPI()

class DomainRequest(BaseModel):
    domain: HttpUrl

def get_domain_name(domain:HttpUrl)->str:
    domain = str(domain)
    parsed_url = urlparse(domain)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")

    domain_name = parsed_url.netloc
    return domain_name



def get_ssl_certificate_info(domain_name: str):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain_name, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                issuer = cert.get_issuer().O
                expiry_date = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                return issuer, expiry_date
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SSL Error: {str(e)}")


def check_domain_expiration(domain_name: str):
    try:
        domain_info = whois.whois(domain_name)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return expiration_date
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"WHOIS Error: {str(e)}")



@app.post("/check_domain")
def check_domain(request: DomainRequest):
    # explicitly convert to string

    domain_name = get_domain_name(request.domain)

    try:
        response = requests.get(domain_name, timeout=10)
        status_code = response.status_code
        availability = status_code == 200
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Request error: {str(e)}")

    issuer, cert_expiry = get_ssl_certificate_info(domain_name)
    domain_expiry = check_domain_expiration(domain_name)
    days_until_expiry = (domain_expiry - datetime.now()).days
    expiration_soon = days_until_expiry <= 30

    return {
        "domain": domain_name,
        "availability": availability,
        "status_code": status_code,
        "ssl_certificate_issuer": issuer,
        "ssl_certificate_expiry": cert_expiry.strftime('%Y-%m-%d %H:%M:%S'),
        "domain_expiration_date": domain_expiry.strftime('%Y-%m-%d %H:%M:%S'),
        "expiration_soon": expiration_soon,
    }


@app.post("/fast_page_check")
def fast_page_check(request: DomainRequest):
    domain = str(request.domain)
    try:
        response = requests.get(domain, timeout=10)
        status_code = response.status_code
        availability = status_code == 200
        return {"domain": domain, "availability": availability, "status_code": status_code}
    except requests.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Request error: {str(e)}")


@app.post("/ssl_certificate_info")
def ssl_certificate_info(request: DomainRequest):
    domain = str(request.domain)
    domain_name = domain.split('//')[1].split('/')[0]
    issuer, cert_expiry = get_ssl_certificate_info(domain_name)
    return {
        "domain": domain_name,
        "ssl_certificate_issuer": issuer,
        "ssl_certificate_expiry": cert_expiry.strftime('%Y-%m-%d %H:%M:%S')
    }


@app.post("/domain_expiration")
def domain_expiration(request: DomainRequest):
    domain = str(request.domain)
    domain_name = domain.split('//')[1].split('/')[0]
    domain_expiry = check_domain_expiration(domain_name)
    days_until_expiry = (domain_expiry - datetime.now()).days
    expiration_soon = days_until_expiry <= 30
    return {
        "domain": domain_name,
        "domain_expiration_date": domain_expiry.strftime('%Y-%m-%d %H:%M:%S'),
        "expiration_soon": expiration_soon
    }
