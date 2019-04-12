from urllib.parse import urlparse
import datetime
import re
import whois
import math

trusted_cert = ["Comodo SSL", "Digicert", "Entrust Datacard", "Geotrust", "GlobalSign", "GoDaddy", "Network Solutions",
                "RapidSSL", "SSL.com", "Thawte", "Name.com, Inc."]


def feature_find_ip(url):
    return re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is not None


def feature_find_at(url):
    return url.find('@') >= 0


def feature_find_prefix(url):
    parsed_uri = urlparse(url)
    result = '{uri.netloc}'.format(uri=parsed_uri)
    return result.find('-') >= 0


def feature_long_url(url):
    if 54 <= len(url) <= 75:
        return -1
    else:
        return len(url) >= 54


def feature_sub_domains(url):
    parsed_uri = urlparse(url)
    result = '{uri.netloc}'.format(uri=parsed_uri).count('.')
    if result is 2:
        return -1
    else:
        return result != 1


def feature_redirection(url):
    return url.find("//", 7) != -1


def feature_check_cert(url):
    parsed_uri = urlparse(url)
    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

    try:
        if whois.whois(result).registrar in trusted_cert:
            return 0
        elif '{uri.scheme}'.format(uri=parsed_uri) is "https":
            return -1
    except Exception:
        return -1
    return 1


def feature_check_cert_expiration(url):
    parsed_uri = urlparse(url)
    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    try:
        exp = whois.whois(result).expiration_date
    except Exception:
        return -1

    if exp is None or type(exp) is not datetime.datetime:
        return 1
    if (exp - datetime.datetime.now()).days < 365:
        return 1
    return 0


def feature_check_port(url):
    parsed_uri = urlparse(url)
    result = '{uri.port}'.format(uri=parsed_uri)

    if result == 'None':
        return -1
    return result != 80
