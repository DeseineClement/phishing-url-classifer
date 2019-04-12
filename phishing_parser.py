import random as rd
import pandas as pd
import feature_functions as ff

import threading


def merge_dict(dict1, dict2):
    result = dict1.copy()
    result.update(dict2)
    return result


def analysing_url(url, is_phising=False, result=None):
    if result is None:
        result = []

    func = {
        "has_ip_address": ff.feature_find_ip,
        "has_at": ff.feature_find_at,
        "has_multiple_subdomains": ff.feature_sub_domains,
        "has_prefix": ff.feature_find_prefix,
        "long_url": ff.feature_long_url,
        "redirection": ff.feature_redirection,
        "cert_origin": ff.feature_check_cert,
        "cert_expiration": ff.feature_check_cert_expiration,
        "unusual_port": ff.feature_check_port
    }

    result += [merge_dict(
             {'phishing': int(is_phising)},
             {key: int(f(url)) for key, f in func.items()}
    )]


def parse_url_file(path, is_phising=False, result=None, threads=None):
    if threads is None:
        threads = []

    print('>> analyzing ' + path)
    new_threads = list(map(
        lambda url: threading.Thread(target=analysing_url, args=(url, is_phising, result)),
        pd.read_csv(path).pop('url').values
    ))

    for thread in new_threads:
        thread.start()

    threads += new_threads


def generate_training_file(data, path='data/training.csv'):
    print('>> generating training file. (' + path + ')')
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    print('>> ' + path + ' created. ' + str(df['has_ip_address'].count()) + ' urls analyzed')


def main():
    files = [
        {
            'path': 'data/benign_urls.csv',
            'is_phising': False
        },
        {
            'path': 'data/phishing_urls.csv',
            'is_phising': True
        }
    ]

    parsed_data = []
    threads = []
    for file in files:
        parse_url_file(file['path'], file['is_phising'], parsed_data, threads)

    for thread in threads:
        thread.join()

    generate_training_file(parsed_data)


if __name__ == '__main__':
    main()
