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

#labels = [0, 1]

feature_names = ["LongUrl", "Redirection", "HasAt", "IsIPAddress"]
data['feature_names'] = feature_names

features = [[], [], [], []]

p_data = csv.DictReader(open("data/phishing_urls.csv"))

for row in p_data:
    features[0].append(featureLongUrl(row[0]))
    features[1].append(featureRedirection(row[0]))
    features[2].append(featureFindAt(row[0]))
    features[3].append(featureFindIP(row[0]))

#train, test, train_labels, test_labels = train_test_split(features,
#                                                          labels,
#                                                          test_size=0.33,
#                                                          random_state=42)

#gnb = GaussianNB()
#model = gnb.fit(train, train_labels)
#preds = gnb.predict(test)
#print(preds)
