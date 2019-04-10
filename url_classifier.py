from functools import reduce
import pandas as pb


def parse_training_file(path='data/training.csv', label_row='phishing'):
    parsed_data = pb.read_csv(path)

    label_values = parsed_data.pop(label_row).values
    feature_names = list(parsed_data.keys())
    feature_values = list(reduce(
        lambda result, data: [item + [data[key]] for key, item in enumerate(result)],
        parsed_data.values,
        [[]] * len(feature_names)
    ))

    return label_values, feature_names, feature_values


def main():
    label_names = ['begnin', 'phishing']
    label_values, feature_names, feature_values = parse_training_file()

    print(label_names)
    print(label_values[0])
    print(feature_names[0])
    print(feature_values[0])


if __name__ == "__main__":
    main()
