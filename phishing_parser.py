from functools import reduce

import random as rd
import pandas as pd
import feature_functions as ff


def merge_dict(dict1, dict2):
    result = dict1.copy()
    result.update(dict2)
    return result


def parse_url_file(path, is_phising=False):
    func = {
        "has_ip_address": ff.feature_find_ip,
        "has_at": ff.feature_find_at,
        "long_url": ff.feature_long_url,
        "redirection": ff.feature_redirection
    }

    print('>> analyzing ' + path + '.')
    return [
        merge_dict(
            {'phishing': int(is_phising)},
            {key: int(f(url)) for key, f in func.items()})
        for url in pd.read_csv(path).pop('url').values
    ]


def generate_training_file(data, path='data/training.csv'):
    print('>> generating training file. (' + path + ')')
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    print('>> ' + path + ' created. ' + str(df['has_ip_address'].count()) + ' urls analyzed')


def main():
    files = [
        {
            'path': 'data/begnin_urls.csv',
            'is_phising': False
        },
        {
            'path': 'data/phishing_urls.csv',
            'is_phising': True
        }
    ]

    parsed_data = list(reduce(
        lambda result, file: result + parse_url_file(file['path'], file['is_phising']),
        files,
        []
    ))
    rd.shuffle(parsed_data)
    generate_training_file(parsed_data)


if __name__ == '__main__':
    main()
