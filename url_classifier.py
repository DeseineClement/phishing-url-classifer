from numpy.random import seed
seed(1)
from tensorflow import set_random_seed
set_random_seed(1)

from keras import layers
#from keras import regularizers
from keras.models import Sequential
from sklearn.model_selection import train_test_split

import pandas as pb
import numpy as np


def parse_training_file(path='data/training.csv', label_row='phishing'):
    parsed_data = pb.read_csv(path)

    label_values = parsed_data.pop(label_row).values
    feature_names = parsed_data.keys()
    feature_values = parsed_data.values

    return label_values, feature_names, feature_values

def create_baseline():
    model = Sequential()

    model.add(layers.Dense(5, activation='tanh'))
    model.add(layers.Dropout(0.6))
    model.add(layers.Dense(5, activation='tanh'))
    model.add(layers.Dropout(0.5))
    model.add(layers.Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

def main():
    print_header()
    label_values, feature_names, feature_values = parse_training_file()
    test_size = 0.25

    print_parameters(feature_names, feature_values, test_size)

    train_values, test_values, train_labels, test_labels = train_test_split(feature_values,
                                                                            label_values,
                                                                            test_size=test_size,
                                                                            random_state=42)

    # gnb = GaussianNB()
    # gnb.fit(train_values, train_labels)
    # predictions = gnb.predict(test_values)

    nb_iterations = 8

    # evaluate model with standardized dataset
    model = create_baseline()
    model.compile(optimizer='adagrad',loss='mse',metrics=['accuracy'])
    #model.fit(train_values,train_labels,epochs=nb_iterations)

    predictions = []
    probas = model.predict(test_values)
    for prediction in probas:
        if (prediction >= 0.5):
            predictions.append(0)
        else:
            predictions.append(1)
    label_counts = np.unique(test_labels, return_counts=True)
    pred_counts = np.unique(predictions, return_counts=True)

    print("lab")
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
    print("label_counts :", label_counts)
    print("pred_counts :", pred_counts)
    print(">> number of benign urls: ")
    print("\t| real      :\t", label_counts[1][0])
    print("\t| predicted :\t", pred_counts[1][0], '\n')
    print(">> number of phishing urls: ")
    print("\t| real      :\t", label_counts[1][1])
    print("\t| predicted :\t", pred_counts[1][1], '\n')
    total = label_counts[1][0] + label_counts[1][1]
    print(">> the accuracy score is:", str(100 - round((abs(label_counts[1][0] - pred_counts[1][0]) + (abs(label_counts[1][1] - pred_counts[1][1])) * 100) / total,
                                                 2)) + '%\n')


if __name__ == "__main__":
    main()
