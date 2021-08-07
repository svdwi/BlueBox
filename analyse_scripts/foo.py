from functools import wraps
from flask import Flask
from flask import request, Response
from subprocess import call
from flask import render_template

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import random
from sklearn.feature_extraction.text import TfidfVectorizer
import sys
import os
from sklearn.linear_model import LogisticRegression
import json
import math
from collections import Counter

class malicious_url_ML():

    def __init__(self,path):
        self.path = path
        



    def entropy(self,s):
        p, lns = Counter(s), float(len(s))
        return -sum( count/lns * math.log(count/lns, 2) for count in p.values())
        

    def run(self):
        vectorizer, lgs ,score  = self.TL()
        X_predict = []
        X_predict.append(str(self.path))
        X_predict = vectorizer.transform(X_predict)
        y_Predict = lgs.predict(X_predict)
        score = str((score*100))
        results={}
        y_Predict = str(y_Predict).replace("['","").replace("']","").upper()
        results = {
            "path":self.path,
            "etat":y_Predict,
            "score":score[0:4],
           }
        return(results)


    def getTokens(self ,input):
        tokensBySlash = str(input.encode('utf-8')).split('/')	#get tokens after splitting by slash
        allTokens = []
        for i in tokensBySlash:
            tokens = str(i).split('-')	#get tokens after splitting by dash
            tokensByDot = []
            for j in range(0,len(tokens)):
                tempTokens = str(tokens[j]).split('.')	#get tokens after splitting by dot
                tokensByDot = tokensByDot + tempTokens
            allTokens = allTokens + tokens + tokensByDot
        allTokens = list(set(allTokens))	#remove redundant tokens
        if 'com' in allTokens:
            allTokens.remove('com')	#removing .com since it occurs a lot of times and it should not be included in our features
        #print(allTokens)
        return allTokens

    def TL(self):
        allurls = './data/data.csv'	#path to our all urls file
        allurlscsv = pd.read_csv(allurls,',',error_bad_lines=False)	#reading file
        allurlsdata = pd.DataFrame(allurlscsv)	#converting to a dataframe

        allurlsdata = np.array(allurlsdata)	#converting it into an array
        random.shuffle(allurlsdata)	#shuffling

        y = [d[1] for d in allurlsdata]	#all labels 
        corpus = [d[0] for d in allurlsdata]	#all urls corresponding to a label (either good or bad)
        vectorizer = TfidfVectorizer(tokenizer= self.getTokens)	#get a vector for each url but use our customized tokenizer
        X = vectorizer.fit_transform(corpus)	#get the X vector

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)	#split into training and testing set 80/20 ratio

        lgs = LogisticRegression(solver='lbfgs', max_iter=1000)	#using logistic regression
        lgs.fit(X_train, y_train)
        score = lgs.score(X_test, y_test)	#pring the score. It comes out to be 98%
        return vectorizer, lgs , score


 
