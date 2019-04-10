import re


def feature_find_ip(url):
    return len(re.findall(r'[0-9]+(?:\.[0-9]+){3}', url)) > 0


def feature_find_at(url):
    return url.find('@') >= 0


def feature_long_url(url):
    return len(url) >= 54


def feature_redirection(url):
    return url.find("//", 7) != -1
