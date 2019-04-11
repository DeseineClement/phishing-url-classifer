from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
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
    label_names = np.array(['benign', 'phishing'], np.str)
    label_values, feature_names, feature_values = parse_training_file()

    train_values, test_values, train_labels, test_labels = train_test_split(feature_values,
                                                                            label_values,
                                                                            test_size=0.33,
                                                                            random_state=42)

    gnb = GaussianNB()
    model = gnb.fit(train_values, train_labels)
    preds = gnb.predict(test_values)

    print(preds)
    print(accuracy_score(test_labels, preds))


if __name__ == "__main__":
    main()
