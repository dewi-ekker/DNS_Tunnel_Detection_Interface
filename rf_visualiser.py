#!/usr/bin/env python
# coding: utf-8

import pandas as pd


# updating the datastores for model training with new data:
    
from pcap_feature_parser import *
def update_datastore(path, label):
    old = pd.read_csv('DNS_datastore.csv', index_col=0)

    if 'source_file' in old.columns and path in list(old['source_file']):
        raise('Error: A file with this path already exists in the datastore.')
    else:
        pcap = read_pcap(path)
        append = parse_features(pcap, label)
        
        new = pd.concat([old, append], axis=0)
        new = new.reset_index()
        new = new.drop(columns='index')
        new.to_csv('DNS_datastore.csv')
        
        return(new)


# erasing all samples from selected source from the datastores:

def erase_datastores(path):
    if path == 'ALL':
        pd.DataFrame().to_csv('DNS_datastore.csv')
    else:
        sources = pd.read_csv('DNS_datastore.csv', usecols=['source path'], squeeze=True)
        erase_rows = list(sources[sources == path].index)
        
        new = pd.read_csv('DNS_datastore.csv', index_col=0)
        new.drop(labels = erase_rows, axis=0, inplace = True)
        new = new.reset_index()
        new = new.drop(columns='index')
        new.to_csv('DNS_datastore.csv')


        
# training the Random Forest algorithm:

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from joblib import dump

def train_rf(x, y, features):
    # add some Gaussian noise for increased robustness
    mu = 0
    sigma = 0.1 * x.mean()
    noise = np.random.normal(mu, sigma, x.shape)

    x = x + noise
    
    # build the model with the 'best' parameters as found in hypertuning with GridSearchCV
    rf = RandomForestClassifier(n_estimators=10,
                                max_features=None,
                                max_depth=4,
                                n_jobs=-1,
                                random_state=None)
    # train the model and save to file
    rf.fit(x, y)
    dump(rf, 'trained_rf.joblib')
    return rf



# plotting feature importances:

import matplotlib.pyplot as plt
import seaborn as sb

def plot_fi(rf, features):
    importances = pd.DataFrame(rf.feature_importances_, columns=['fi'], index=features)
    importances['std'] = np.std([tree.feature_importances_ for tree in rf.estimators_], axis=0, ddof=1)
    importances.sort_values('fi', ascending=False, inplace=True)
    fig, ax = plt.subplots(figsize=(18,10))
    importances.plot.bar(yerr='std', ax=ax, error_kw=dict(capsize=5, lw=0.5, capthick=0.5), color='lightskyblue', ecolor='navy')
    ax.set_title("Feature Importances")
    ax.set_ylabel("Mean decrease in impurity")
    fig.tight_layout()
    fig.savefig('Model_Metrics/Feature_Importances.png', dpi=300)
    plt.close()



# plotting confusion matrix and calculating evaluation metrics:

from sklearn.metrics import confusion_matrix

def plot_cm(rf, x, y):
    y_predict = rf.predict(x)
    cm = confusion_matrix(y, y_predict)
    names = ['TN','FP','FN','TP']
    counts = ['{0:0.0f}'.format(value) for value in cm.flatten()]
    percents = ['{0:.2%}'.format(value) for value in cm.flatten()/np.sum(cm)]
    labels = [f'{v1}\n{v2}\n{v3}' for v1, v2, v3 in zip(names, counts, percents)]
    labels = np.asarray(labels).reshape(2,2)
    plt.title('Confusion Matrix')
    fig = sb.heatmap(cm, annot=labels, fmt='', cmap='Blues', cbar=False).get_figure()
    fig.savefig('Model_Metrics/Confusion_Matrix.png', dpi=300)
    plt.close()
    get_metrics(cm)
    
def get_metrics(cm):
    TN, FP, FN, TP =  [int(x) for x in np.asarray(cm).reshape(-1)]
    recall = TP/(TN+FN)
    precision = TP/(TP+FP)
    metrics = pd.DataFrame(columns=['other names','Equation','Value'])
    metrics.loc['Accuracy',:] = ['', 'TN+TP/total', '%.2f%%' %((TN+TP)/(TN+TP+FN+FP)*100)]
    metrics.loc['True Positive Rate',:] = ['Sensitivity, Recall', 'TP/(TN+FN)', '%.2f%%' %(recall*100)]
    metrics.loc['True Negative Rate',:] = ['Specificity', 'TN/(TN+FN)', '%.2f%%' %(TN/(TN+FN)*100)]
    metrics.loc['False Positive Rate',:] = ['Fall-Out', 'FP/(TN+FN)', '%.2f%%' %(FP/(TN+FN)*100)]
    metrics.loc['False Negative Rate',:] = ['Miss Rate', 'TN/(FN+TP)', '%.2f%%' %(FN/(FN+TP)*100)]
    metrics.loc['Positive Predictive Value',:] = ['Precision', 'TP/(TP+FP)', '%.2f%%' %(precision*100)]
    metrics.loc['False Discovery Rate',:] = ['', 'FP/(FP+TP)', '%.2f%%' %(FP/(FP+TP)*100)]
    metrics.loc['F-1 Score',:] = ['', '2*(Recall*Precision) /(Recall+Precision)', \
                                  '%.2f%%' %(2*(recall*precision)/(recall+precision)*100)]
    html = metrics.to_html()
    file = open('Model_Metrics/Evaluation_Metrics.html', 'w')
    file.write(html)
    file.close()
    
    
    
# creating the Decision Tree images:

from dtreeviz.trees import dtreeviz

def vizdtrees(rf, x, y, features):
    images = []
    
    colors={'classes':[None,None,['#0080c9','#ffb1b1']],
            'class_boundary' : '#0c499c',
            'highlight': '#0080c9'}
    
    for i in range(rf.n_estimators):
        viz = dtreeviz(rf.estimators_[i], x, y,
                       target_name="Data Classification",
                       feature_names=features,
                       class_names=['benign','malicious'],
                       title="Tree "+str(i+1),
                       histtype='bar', # default:'barstacked'
                       colors=colors)
    #save the trees
        img = "DecisionTrees/dtreeviz_{:02d}.svg".format(i+1)
        viz.save(img)


def singletree(rf, features, packet, tree):
    colors={'classes':[None,None,['#0080c9','#ffb1b1']],
            'class_boundary' : '#0c499c',
            'highlight': '#0080c9'
           }
    df = pd.read_csv('DNS_datastore.csv', index_col=0)
    y = df['label']
    x = df[features].fillna(0)

    viz = dtreeviz(rf.estimators_[tree-1],
                   x, y,
                   target_name='anomaly detection',
                   feature_names=features,
                   title='',
                   class_names=['Benign','Malicious'],
                   colors=colors,
                   histtype='bar',
                   X=packet)
    return viz

