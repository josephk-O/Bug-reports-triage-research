import pandas as pd
import re
import string
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

lemmatizer = WordNetLemmatizer()
stop_words = set(stopwords.words('english'))


# List of exceptions to preserve during preprocessing
exceptions = ["xss", "SQLi", "crsf", "rce", "rxss"]  

def preprocess(df):
    df = df.drop_duplicates()
    df = df[df['title'].apply(lambda x: isinstance(x, str))]
    df['title'] = df['title'].apply(lambda text: " ".join([word if word in exceptions else lemmatizer.lemmatize(word.lower()) for word in word_tokenize(str(text)) if not word.lower() in stop_words and word not in string.punctuation]))
    df['title'] = df['title'].str.lstrip()
    df['title'] = df['title'].apply(lambda s: re.sub(r'\[.*?\]', '', s))
    df['title'] = df['title'].apply(lambda s: re.sub(r"(?i)cve[-_\s]?\d{4}[-_\s]?\d{1,5}\*?'?\)?", '', s))
    df['title'] = df['title'].apply(lambda s: re.sub(r'^-', '', s).strip())
    df['title'] = df['title'].apply(lambda s: re.sub(r'^:', '', s).strip())
    df['title'] = df['title'].apply(lambda s: re.sub(r'\s\(GHSL-\d{4}-\d{3}\)', '', s))

    df = df.applymap(lambda s: s.lower() if type(s) == str else s)

    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    domain_pattern = r'(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])'
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    erroneous_pattern = r'https?://[â–ˆ/]+'
    slash_error_pattern = r'/?â–ˆ+/?'
    pattern = f'({url_pattern})|({domain_pattern})|({cve_pattern})|({erroneous_pattern})|({slash_error_pattern})'
    df['title'] = df['title'].astype(str).apply(lambda x: re.sub(pattern, '', x))
    
    return df

def preprocess_file(file_path, columns_to_check, output_file):
    df = pd.read_excel(file_path)
    df = df.dropna(subset=columns_to_check)
    df = preprocess(df)
    df.to_excel(output_file, index=False)
    
    
    
    return df

def preprocess_testing(text):
    # lowercase and rem punctuation
    text = " ".join([word if word in exceptions else word.lower() for word in word_tokenize(text) if not word.lower() in stop_words and word not in string.punctuation])
  
    # tokenize and lemmatize
    word_tokens = word_tokenize(text)
    filtered_text = [lemmatizer.lemmatize(w) for w in word_tokens if not w in stop_words]
    return " ".join(filtered_text)

def main():
    file_path = input("Enter the input file path: ")
    output_file = input("Please enter the output file path: ")

    if re.search(r'base\.xlsx$', file_path):
        columns_to_check = ['title', 'vuln_type', 'severity_rating']
    else:
        columns_to_check = ['title', 'vuln_type', 'severity_rating', 'score', 'vector']

    df = preprocess_file(file_path, columns_to_check, output_file)

if __name__ == "__main__":
    main()