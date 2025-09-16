import re
import os
import joblib
import tldextract
import validators
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix

IP_RE = re.compile(r'^(?:http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}')

def url_has_ip(url: str) -> int:
    return 1 if IP_RE.search(url) else 0

def count_chars(s: str, ch: str) -> int:
    return s.count(ch)

def domain_and_tld(url: str):
    ex = tldextract.extract(url)
    return ex.domain or '', ex.suffix or '', ex.subdomain or ''

def extract_url_features(url: str):
    url = url.strip()
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = count_chars(url, '.')
    features['num_hyphens'] = count_chars(url, '-')
    features['num_at'] = count_chars(url, '@')
    features['num_q'] = count_chars(url, '?')
    features['num_equals'] = count_chars(url, '=')
    features['num_underscores'] = count_chars(url, '_')
    features['has_https'] = 1 if url.lower().startswith('https://') else 0
    features['has_http'] = 1 if url.lower().startswith('http://') else 0
    features['has_ip'] = url_has_ip(url)
    features['is_valid_url'] = 1 if validators.url(url) else 0
    domain, tld, subdomain = domain_and_tld(url)
    features['domain_len'] = len(domain)
    features['tld_len'] = len(tld)
    features['subdomain_len'] = len(subdomain)
    kw = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'confirm', 'signin', 'support']
    features['suspicious_keyword_count'] = sum(1 for k in kw if k in url.lower())
    try:
        path = re.sub(r'https?://', '', url, flags=re.I)
        path = path.split('/', 1)[1] if '/' in path else ''
        features['path_len_ratio'] = len(path) / (len(url) + 1e-6)
    except Exception:
        features['path_len_ratio'] = 0.0
    return features

def build_demo_url_dataset(n_legit=400, n_phish=400, random_state=42):
    np.random.seed(random_state)
    rows = []
    legit_domains = ['google.com', 'github.com', 'wikipedia.org', 'amazon.in', 'apple.com',
                     'stackoverflow.com', 'microsoft.com', 'linkedin.com', 'paypal.com']
    for _ in range(n_legit):
        d = np.random.choice(legit_domains)
        sub = '' if np.random.rand() > 0.3 else 'www.'
        path = '' if np.random.rand() > 0.5 else '/' + ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), size=np.random.randint(3, 12)))
        url = f'https://{sub}{d}{path}'
        rows.append((url, 0))
    phish_templates = [
        'http://{domain}-{word}.com/{p}',
        'http://{word}.{domain}.info/{p}',
        'https://{domain}.{tld}/{p}?r={r}',
        'http://{ip}/{p}',
        'https://secure-{domain}/{p}',
        'http://{domain}.signin-{word}.com/{p}',
    ]
    words = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'confirm', 'signin']
    tlds = ['com', 'net', 'info', 'xyz', 'online']
    for _ in range(n_phish):
        template = np.random.choice(phish_templates)
        word = np.random.choice(words)
        domain = np.random.choice(legit_domains).replace('.com', '').replace('.org', '').replace('.in', '')
        tld = np.random.choice(tlds)
        ip = '.'.join(str(np.random.randint(1, 255)) for _ in range(4))
        p = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), size=np.random.randint(5, 18)))
        r = ''.join(np.random.choice(list('abcdef0123456789'), size=8))
        url = template.format(domain=domain, word=word, p=p, ip=ip, tld=tld, r=r)
        rows.append((url, 1))
    df = pd.DataFrame(rows, columns=['url', 'label'])
    return df.sample(frac=1, random_state=random_state).reset_index(drop=True)

def prepare_features(df_urls: pd.DataFrame):
    feat_list = [extract_url_features(u) for u in df_urls['url']]
    feat_df = pd.DataFrame(feat_list).fillna(0)
    return feat_df.values.astype(float), df_urls['label'].values.astype(int), feat_df.columns.tolist()

def train_and_save_model(save_path='models'):
    os.makedirs(save_path, exist_ok=True)
    df = build_demo_url_dataset()
    X, y, feature_names = prepare_features(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("ROC-AUC:", roc_auc_score(y_test, y_prob))
    print("Classification report:")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    joblib.dump({'model': clf, 'feature_names': feature_names}, os.path.join(save_path, 'url_rf.joblib'))
    return clf, feature_names

def load_model(model_path='models/url_rf.joblib'):
    obj = joblib.load(model_path)
    return obj['model'], obj['feature_names']

def predict_url(url: str, model=None, feature_names=None):
    if model is None or feature_names is None:
        model, feature_names = load_model()
    feats = extract_url_features(url)
    arr = np.array([feats[name] for name in feature_names]).reshape(1, -1).astype(float)
    pred = model.predict(arr)[0]
    score = float(model.predict_proba(arr)[0, 1])
    return {'url': url, 'prediction': int(pred), 'phish_probability': score, 'features': feats}

if __name__ == '__main__':
    clf, feat_names = train_and_save_model()
    tests = [
        'https://www.google.com/',
        'http://123.45.67.89/login/confirm',
        'http://paypal-login.secure-update.com/verify',
        'https://github.com/tanmay',
        'http://secure-amazon.com/signin?user=abc'
    ]
    for t in tests:
        r = predict_url(t, model=clf, feature_names=feat_names)
        label = 'PHISH' if r['prediction'] == 1 else 'LEGIT'
        print(f"{t}  --> {label} (prob={r['phish_probability']})")
