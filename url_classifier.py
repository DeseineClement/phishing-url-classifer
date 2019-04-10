import pandas as pb


def parse_training_file(path='data/training.csv', label_row='phishing'):

    parsed_data = pb.read_csv(path)
    return parsed_data.pop(label_row).values, list(parsed_data.keys()), parsed_data.values


def main():
    label_names = ['begnin', 'phishing']
    label_values, feature_names, feature_values = parse_training_file()

    print(label_names, label_values, feature_names, feature_values)


if __name__ == "__main__":
    main()
