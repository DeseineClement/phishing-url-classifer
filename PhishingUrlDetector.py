import re
import csv
import sklearn
import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split


def featureFindIP(url):
    if len(re.findall(r'[0-9]+(?:\.[0-9]+){3}', url)) > 0:
        return 0
    return 1


def featureFindAt(url):
    if url.find('@') >= 0:
        return 0
    return 1


def featureLongUrl(url):
    if len(url) >= 54:
        return 0
    return 1


def featureRedirection(url):
    if url.find("//", 7) != -1:
        return 0
    return 1


data = dict()

label_names = ["phishing", "benign"]
data['label_names'] = label_names

labels = []

feature_names = ["LongUrl", "Redirection", "HasAt", "IsIPAddress"]
data['feature_names'] = feature_names

features = [[]]*4
print(features)
p_data = csv.reader(open("data/phishing_urls.csv"))

for row, in p_data:
    features[0].append(featureLongUrl(row))
    features[1].append(featureRedirection(row))
    features[2].append(featureFindAt(row))
    features[3].append(featureFindIP(row))
    labels.append(0)


print(len(features[1]))
print(len(labels))
train, test, train_labels, test_labels = train_test_split(features,
                                                          labels,
                                                          test_size=0.33,
                                                          random_state=42)

#gnb = GaussianNB()
#model = gnb.fit(train, train_labels)
#preds = gnb.predict(test)
#print(preds)
