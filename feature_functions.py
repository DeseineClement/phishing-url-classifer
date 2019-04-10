import re


def feature_find_ip(url):
    if len(re.findall(r'[0-9]+(?:\.[0-9]+){3}', url)) > 0:
        return 0
    return 1


def feature_find_at(url):
    if url.find('@') >= 0:
        return 0
    return 1


def feature_long_url(url):
    if len(url) >= 54:
        return 0
    return 1


def feature_redirection(url):
    if url.find("//", 7) != -1:
        return 0
    return 1