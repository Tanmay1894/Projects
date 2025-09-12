import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import pickle


df = pd.read_csv('C:/Users/patil/PycharmProjects/Sentiment Analysis/data2.csv')
df = df.dropna()


vectorizer = CountVectorizer(ngram_range=(1, 2), stop_words='english', min_df=3)
X = vectorizer.fit_transform(df['text'])  # Ensure correct column name
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=0)

# Logistic Regression
lr_model = LogisticRegression(max_iter=1000)
lr_model.fit(X_train, y_train)
lr_y_pred = lr_model.predict(X_test)
lr_accuracy = accuracy_score(y_test, lr_y_pred)
print(f"Logistic Regression Model Accuracy: {lr_accuracy * 100:.2f}%")

# XGBoost
xgb_model = XGBClassifier()
xgb_model.fit(X_train, y_train)
xgb_y_pred = xgb_model.predict(X_test)
xgb_accuracy = accuracy_score(y_test, xgb_y_pred)
print(f"XGBoost Model Accuracy: {xgb_accuracy * 100:.2f}%")

# SVM
# svm_model = SVC(kernel='linear')  # Using linear kernel for text classification
# svm_model.fit(X_train, y_train)
# svm_y_pred = svm_model.predict(X_test)
# svm_accuracy = accuracy_score(y_test, svm_y_pred)
# print(f"SVM Model Accuracy: {svm_accuracy * 100:.2f}%")


pickle.dump(lr_model, open('logistic_regression_model.pkl', 'wb'))
pickle.dump(xgb_model, open('xgb_model.pkl', 'wb'))
# pickle.dump(svm_model, open('svm_model.pkl', 'wb'))
pickle.dump(vectorizer, open('vectorizer.pkl', 'wb'))
