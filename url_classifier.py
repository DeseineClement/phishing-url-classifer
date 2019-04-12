from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import GaussianNB

import pandas as pb
import numpy as np


def parse_training_file(path='data/training.csv', label_row='phishing'):
    parsed_data = pb.read_csv(path)

    label_values = parsed_data.pop(label_row).values
    feature_names = parsed_data.keys()
    feature_values = parsed_data.values

    return label_values, feature_names, feature_values


def main():
    print_header()
    label_values, feature_names, feature_values = parse_training_file()
    test_size = 0.33

    print_parameters(feature_names, feature_values, test_size)

    train_values, test_values, train_labels, test_labels = train_test_split(feature_values,
                                                                            label_values,
                                                                            test_size=test_size,
                                                                            random_state=42)

    gnb = GaussianNB()
    gnb.fit(train_values, train_labels)
    predictions = gnb.predict(test_values)

    label_counts = np.unique(test_labels, return_counts=True)
    pred_counts = np.unique(predictions, return_counts=True)

    print_output(label_counts, pred_counts, predictions, test_labels)


def print_header():
    print('\n _____  _     _     _     _               _    _ _____  _             _               _  __ _')
    print('|  __ \| |   (_)   | |   (_)             | |  | |  __ \| |           | |             (_)/ _(_) ')
    print('| |__) | |__  _ ___| |__  _ _ __   __ _  | |  | | |__) | |        ___| | __ _ ___ ___ _| |_ _  ___ _ __ ')
    print(
        '|  ___/| \'_ \| / __| \'_ \| | \'_ \ / _` | | |  | |  _  /| |       / __| |/ _` / __/ __| |  _| |/ _ \ \'__|')
    print('| |    | | | | \__ \ | | | | | | | (_| | | |__| | | \ \| |____  | (__| | (_| \__ \__ \ | | | |  __/ |')
    print('|_|    |_| |_|_|___/_| |_|_|_| |_|\__, |  \____/|_|  \_\______|  \___|_|\__,_|___/___/_|_| |_|\___|_|')
    print('                                   __/ |')
    print('                                  |___/')


def print_parameters(feature_names, feature_values, test_size):
    print("\n-----------------------------------------------------------\nparameters:\n")
    print(">> number of urls: ", len(feature_values))
    print("\t| used for test\t\t: ", round(test_size * len(feature_values)))
    print("\t| used for train\t: ", len(feature_values) - round(test_size * len(feature_values)), '\n')
    print(">> features tested: ")
    for feature_name in feature_names:
        print("\t| ", feature_name)


def print_output(label_counts, pred_counts, predictions, test_labels):
    print("\n-----------------------------------------------------------\nresults:\n")
    print(">> number of benign urls: ")
    print("\t| real      :\t", label_counts[1][0])
    print("\t| predicted :\t", pred_counts[1][0], '\n')
    print(">> number of phishing urls: ")
    print("\t| real      :\t", label_counts[1][1])
    print("\t| predicted :\t", pred_counts[1][1], '\n')
    print(">> the accuracy score is:", str(round(accuracy_score(test_labels, predictions) * 100, 2)) + '%\n')


if __name__ == "__main__":
    main()
