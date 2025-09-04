"""
Threat Detection System - Data Preprocessing Module
Handles loading, cleaning, and preprocessing of all threat detection datasets
"""

import pandas as pd
import numpy as np
import json
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import re
import logging
from tqdm import tqdm

from config import *

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

warnings.filterwarnings('ignore')

class ThreatDataPreprocessor:
    """
    Comprehensive data preprocessing for threat detection datasets
    """
    
    def __init__(self):
        self.scalers = {}
        self.encoders = {}
        self.tfidf_vectorizers = {}
        self.feature_columns = {}
        
        # Download NLTK data if needed
        try:
            nltk.data.find('tokenizers/punkt')
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('punkt')
            nltk.download('stopwords')
        
        self.stop_words = set(stopwords.words('english'))
    
    def load_emails_dataset(self) -> pd.DataFrame:
        """Load and preprocess email dataset for phishing detection"""
        logger.info("Loading emails dataset...")
        
        try:
            # Read in chunks for large files
            chunk_size = 10000
            chunks = []
            total_processed = 0
            
            for chunk in pd.read_csv(DATASET_PATHS['emails'], chunksize=chunk_size):
                # Limit to first 50,000 records for faster processing
                if total_processed >= 50000:
                    logger.info(f"Limiting email dataset to {total_processed} records for efficiency")
                    break
                
                chunks.append(chunk)
                total_processed += len(chunk)
                logger.info(f"Processed {total_processed} email records...")
            
            if not chunks:
                logger.warning("No email data chunks loaded")
                return pd.DataFrame()
            
            df = pd.concat(chunks, ignore_index=True)
            logger.info(f"Loaded {len(df)} email records (limited for efficiency)")
            
            # Ensure required columns exist
            if 'label' not in df.columns:
                # If no label column, create one based on common patterns
                if 'spam' in df.columns:
                    df['label'] = df['spam'].apply(lambda x: 'SPAM' if x == 1 else 'BENIGN')
                elif 'target' in df.columns:
                    df['label'] = df['target'].apply(lambda x: 'PHISHING' if x == 1 else 'BENIGN')
                else:
                    # Default assumption - first half benign, second half malicious
                    df['label'] = ['BENIGN'] * (len(df)//2) + ['PHISHING'] * (len(df) - len(df)//2)
            
            # Clean text data
            text_columns = [col for col in df.columns if df[col].dtype == 'object' and col != 'label']
            if text_columns:
                df['combined_text'] = df[text_columns].fillna('').agg(' '.join, axis=1)
            else:
                df['combined_text'] = df.iloc[:, 0].fillna('').astype(str)
            
            # Limit text length for efficiency
            df['combined_text'] = df['combined_text'].str[:1000]  # Limit to 1000 chars
            df['cleaned_text'] = df['combined_text'].apply(self._clean_text)
            df['attack_type'] = df['label'].map({'BENIGN': 0, 'SPAM': 17, 'PHISHING': 16})
            df['dataset_source'] = 'emails'
            
            return df[['cleaned_text', 'attack_type', 'dataset_source', 'label']]
            
        except Exception as e:
            logger.error(f"Error loading emails dataset: {e}")
            return pd.DataFrame()
    
    def load_malware_dataset(self) -> pd.DataFrame:
        """Load and preprocess malware dataset"""
        logger.info("Loading malware dataset...")
        
        try:
            df = pd.read_csv(DATASET_PATHS['malware'])
            logger.info(f"Loaded {len(df)} malware records")
            
            # Handle missing values
            df = df.fillna(0)
            
            # Create binary classification for malware
            if 'Class' in df.columns:
                df['attack_type'] = df['Class'].apply(lambda x: 15 if x == 'Malware' else 0)
                df['label'] = df['Class'].apply(lambda x: 'MALWARE' if x == 'Malware' else 'BENIGN')
            elif 'label' in df.columns:
                df['attack_type'] = df['label'].apply(lambda x: 15 if x == 1 else 0)
                df['label'] = df['label'].apply(lambda x: 'MALWARE' if x == 1 else 'BENIGN')
            else:
                # Assume binary classification in last column
                last_col = df.columns[-1]
                df['attack_type'] = df[last_col].apply(lambda x: 15 if x == 1 else 0)
                df['label'] = df[last_col].apply(lambda x: 'MALWARE' if x == 1 else 'BENIGN')
            
            # Select numerical features
            numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'attack_type' in numerical_cols:
                numerical_cols.remove('attack_type')
            
            df['dataset_source'] = 'malware'
            
            return df[numerical_cols + ['attack_type', 'dataset_source', 'label']]
            
        except Exception as e:
            logger.error(f"Error loading malware dataset: {e}")
            return pd.DataFrame()
    
    def load_ddos_datasets(self) -> pd.DataFrame:
        """Load and preprocess DDoS datasets"""
        logger.info("Loading DDoS datasets...")
        
        datasets = []
        
        # Load balanced DDoS dataset
        try:
            df_balanced = pd.read_csv(DATASET_PATHS['ddos_balanced'])
            df_balanced['dataset_source'] = 'ddos_balanced'
            datasets.append(df_balanced)
            logger.info(f"Loaded {len(df_balanced)} balanced DDoS records")
        except Exception as e:
            logger.error(f"Error loading balanced DDoS dataset: {e}")
        
        # Load imbalanced DDoS dataset
        try:
            df_imbalanced = pd.read_csv(DATASET_PATHS['ddos_imbalanced'])
            df_imbalanced['dataset_source'] = 'ddos_imbalanced'
            datasets.append(df_imbalanced)
            logger.info(f"Loaded {len(df_imbalanced)} imbalanced DDoS records")
        except Exception as e:
            logger.error(f"Error loading imbalanced DDoS dataset: {e}")
        
        if not datasets:
            return pd.DataFrame()
        
        # Combine datasets
        df = pd.concat(datasets, ignore_index=True)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Create attack type mapping
        if 'Label' in df.columns:
            df['attack_type'] = df['Label'].apply(lambda x: 1 if 'DDoS' in str(x) or 'DDOS' in str(x) else 0)
            df['label'] = df['Label'].apply(lambda x: 'DDoS' if 'DDoS' in str(x) or 'DDOS' in str(x) else 'BENIGN')
        elif 'label' in df.columns:
            df['attack_type'] = df['label'].apply(lambda x: 1 if x == 1 else 0)
            df['label'] = df['label'].apply(lambda x: 'DDoS' if x == 1 else 'BENIGN')
        
        # Select numerical features
        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude_cols = ['attack_type']
        numerical_cols = [col for col in numerical_cols if col not in exclude_cols]
        
        return df[numerical_cols + ['attack_type', 'dataset_source', 'label']]
    
    def load_cicids_datasets(self) -> pd.DataFrame:
        """Load and preprocess CICIDS2017 datasets"""
        logger.info("Loading CICIDS2017 datasets...")
        
        datasets = []
        max_rows_per_file = 20000  # Limit rows per file for efficiency
        
        for file_path in DATASET_PATHS['cicids_files']:
            try:
                if file_path.exists():
                    # Read in chunks and limit size
                    df = pd.read_csv(file_path, nrows=max_rows_per_file)
                    df['dataset_source'] = file_path.stem
                    datasets.append(df)
                    logger.info(f"Loaded {len(df)} records from {file_path.name}")
            except Exception as e:
                logger.error(f"Error loading {file_path.name}: {e}")
        
        if not datasets:
            return pd.DataFrame()
        
        # Combine all CICIDS datasets
        df = pd.concat(datasets, ignore_index=True)
        logger.info(f"Combined CICIDS datasets: {len(df)} total records")
        
        # Handle missing values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Standardize label column
        label_columns = ['Label', 'label', ' Label']
        label_col = None
        for col in label_columns:
            if col in df.columns:
                label_col = col
                break
        
        if label_col:
            df['label'] = df[label_col].astype(str).str.strip()
            df['attack_type'] = df['label'].map(ATTACK_TYPES).fillna(0).astype(int)
        else:
            # Default to benign if no label found
            df['label'] = 'BENIGN'
            df['attack_type'] = 0
        
        # Select numerical features (limit to prevent memory issues)
        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude_cols = ['attack_type']
        numerical_cols = [col for col in numerical_cols if col not in exclude_cols]
        
        # Limit to top 50 features if too many
        if len(numerical_cols) > 50:
            numerical_cols = numerical_cols[:50]
            logger.info(f"Limited to {len(numerical_cols)} numerical features")
        
        return df[numerical_cols + ['attack_type', 'dataset_source', 'label']]
    
    def load_brute_force_dataset(self) -> pd.DataFrame:
        """Load and preprocess brute force dataset"""
        logger.info("Loading brute force dataset...")
        
        try:
            with open(DATASET_PATHS['brute_force'], 'r') as f:
                data = json.load(f)
            
            # Convert JSON to DataFrame
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = pd.DataFrame([data])
            
            logger.info(f"Loaded {len(df)} brute force records")
            
            # Create attack type mapping
            if 'attack_type' not in df.columns:
                df['attack_type'] = 8  # FTP-Patator
                df['label'] = 'FTP-Patator'
            
            df['dataset_source'] = 'brute_force'
            
            # Select numerical columns
            numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'attack_type' in numerical_cols:
                numerical_cols.remove('attack_type')
            
            return df[numerical_cols + ['attack_type', 'dataset_source', 'label']]
            
        except Exception as e:
            logger.error(f"Error loading brute force dataset: {e}")
            return pd.DataFrame()
    
    def _clean_text(self, text: str) -> str:
        """Clean text data for NLP processing"""
        if pd.isna(text):
            return ""
        
        # Convert to lowercase
        text = str(text).lower()
        
        # Remove special characters and digits
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Tokenize and remove stopwords
        try:
            tokens = word_tokenize(text)
            tokens = [token for token in tokens if token not in self.stop_words and len(token) > 2]
            return ' '.join(tokens)
        except:
            return text
    
    def preprocess_features(self, df: pd.DataFrame, dataset_type: str) -> pd.DataFrame:
        """Preprocess features based on dataset type"""
        
        if dataset_type == 'emails':
            # TF-IDF vectorization for text data
            if 'cleaned_text' in df.columns:
                if dataset_type not in self.tfidf_vectorizers:
                    self.tfidf_vectorizers[dataset_type] = TfidfVectorizer(
                        max_features=FEATURE_CONFIG['max_features_tfidf'],
                        ngram_range=FEATURE_CONFIG['ngram_range'],
                        stop_words='english'
                    )
                    tfidf_features = self.tfidf_vectorizers[dataset_type].fit_transform(df['cleaned_text'])
                else:
                    tfidf_features = self.tfidf_vectorizers[dataset_type].transform(df['cleaned_text'])
                
                # Convert to DataFrame
                feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
                tfidf_df = pd.DataFrame(tfidf_features.toarray(), columns=feature_names, index=df.index)
                
                # Combine with original features
                df = pd.concat([df.drop('cleaned_text', axis=1), tfidf_df], axis=1)
        
        # Scale numerical features
        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude_cols = ['attack_type']
        numerical_cols = [col for col in numerical_cols if col not in exclude_cols]
        
        if numerical_cols:
            if dataset_type not in self.scalers:
                self.scalers[dataset_type] = StandardScaler()
                df[numerical_cols] = self.scalers[dataset_type].fit_transform(df[numerical_cols])
            else:
                df[numerical_cols] = self.scalers[dataset_type].transform(df[numerical_cols])
        
        return df
    
    def process_all_datasets(self) -> Dict[str, pd.DataFrame]:
        """Process all datasets and return a dictionary of processed DataFrames"""
        logger.info("Starting comprehensive data preprocessing...")
        
        processed_datasets = {}
        
        # Load and preprocess each dataset
        datasets_loaders = {
            'emails': self.load_emails_dataset,
            'malware': self.load_malware_dataset,
            'ddos': self.load_ddos_datasets,
            'cicids': self.load_cicids_datasets,
            'brute_force': self.load_brute_force_dataset
        }
        
        for name, loader in datasets_loaders.items():
            try:
                df = loader()
                if not df.empty:
                    df = self.preprocess_features(df, name)
                    processed_datasets[name] = df
                    logger.info(f"Processed {name} dataset: {len(df)} records")
                    
                    # Save processed dataset
                    output_path = PROCESSED_DATA_DIR / f"{name}_processed.csv"
                    df.to_csv(output_path, index=False)
                    logger.info(f"Saved processed {name} dataset to {output_path}")
                else:
                    logger.warning(f"No data loaded for {name} dataset")
            except Exception as e:
                logger.error(f"Error processing {name} dataset: {e}")
        
        return processed_datasets
    
    def create_unified_dataset(self, processed_datasets: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Create a unified dataset from all processed datasets"""
        logger.info("Creating unified dataset...")
        
        if not processed_datasets:
            logger.error("No processed datasets available")
            return pd.DataFrame()
        
        # Find common columns across all datasets
        all_columns = set()
        for df in processed_datasets.values():
            all_columns.update(df.columns)
        
        # Identify essential columns
        essential_cols = ['attack_type', 'dataset_source', 'label']
        
        # Align datasets to have same columns
        aligned_datasets = []
        for name, df in processed_datasets.items():
            # Add missing columns with default values
            for col in all_columns:
                if col not in df.columns:
                    if col in essential_cols:
                        continue
                    df[col] = 0  # Default value for missing features
            
            # Ensure essential columns exist
            if 'attack_type' not in df.columns:
                df['attack_type'] = 0
            if 'dataset_source' not in df.columns:
                df['dataset_source'] = name
            if 'label' not in df.columns:
                df['label'] = 'BENIGN'
            
            aligned_datasets.append(df)
        
        # Combine all datasets
        unified_df = pd.concat(aligned_datasets, ignore_index=True, sort=False)
        
        # Handle any remaining missing values
        unified_df = unified_df.fillna(0)
        
        logger.info(f"Created unified dataset with {len(unified_df)} records and {len(unified_df.columns)} features")
        
        # Save unified dataset
        output_path = PROCESSED_DATA_DIR / "unified_dataset.csv"
        unified_df.to_csv(output_path, index=False)
        logger.info(f"Saved unified dataset to {output_path}")
        
        return unified_df

def main():
    """Main preprocessing function"""
    preprocessor = ThreatDataPreprocessor()
    
    # Process all datasets
    processed_datasets = preprocessor.process_all_datasets()
    
    # Create unified dataset
    unified_dataset = preprocessor.create_unified_dataset(processed_datasets)
    
    # Print summary statistics
    print("\n" + "="*50)
    print("DATASET PREPROCESSING SUMMARY")
    print("="*50)
    
    for name, df in processed_datasets.items():
        print(f"\n{name.upper()} Dataset:")
        print(f"  Records: {len(df):,}")
        print(f"  Features: {len(df.columns):,}")
        print(f"  Attack Types: {df['attack_type'].nunique()}")
        print(f"  Attack Distribution:")
        attack_dist = df['label'].value_counts()
        for attack, count in attack_dist.items():
            print(f"    {attack}: {count:,} ({count/len(df)*100:.1f}%)")
    
    print(f"\nUNIFIED Dataset:")
    print(f"  Total Records: {len(unified_dataset):,}")
    print(f"  Total Features: {len(unified_dataset.columns):,}")
    print(f"  Attack Types: {unified_dataset['attack_type'].nunique()}")
    
    print("\nPreprocessing completed successfully!")
    return processed_datasets, unified_dataset

if __name__ == "__main__":
    main()
