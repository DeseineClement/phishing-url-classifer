from urllib.parse import urlparse
import datetime
import re
import whois


def feature_find_ip(url):
    return re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is not None


def feature_find_at(url):
    return url.find('@') >= 0


def feature_long_url(url):
    return len(url) >= 54


def feature_redirection(url):
    return url.find("//", 7) != -1


trusted_cert = ["Comodo SSL", "Digicert", "Entrust Datacard", "Geotrust", "GlobalSign", "GoDaddy", "Network Solutions",
                "RapidSSL", "SSL.com", "Thawte", "Name.com, Inc."]


def feature_check_cert(url):
    parsed_uri = urlparse(url)
    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

    try:
        if whois.whois(result).registrar in trusted_cert:
            return 0
    except Exception:
        return 1
    return 1


def feature_ckeck_cert_expiration(url):
    parsed_uri = urlparse(url)
    result= '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    try:
        exp = whois.whois(result).expiration_date
    except Exception:
        return 1

    print(exp)
    if exp is None or type(exp) is not datetime.datetime:
        return 1
    if ((exp - datetime.datetime.now()).days < 365):
        return 1
    return 0





#print(feature_check_cert("https://stackoverflow.com/questions/9626535/get-protocol-host-name-from-url"))
#print(feature_ckeck_cert_expiration("https://stackoverflow.com/questions/9626535/get-protocol-host-name-from-url"))
