"""
Quick Test Script - Run preprocessing only with progress monitoring
"""

import time
from preprocessing import ThreatDataPreprocessor
from config import *

def main():
    print("🛡️ Quick Test - Threat Detection Preprocessing")
    print("="*60)
    
    start_time = time.time()
    
    preprocessor = ThreatDataPreprocessor()
    
    print("Step 1: Loading and processing datasets...")
    processed_datasets = preprocessor.process_all_datasets()
    
    if processed_datasets:
        print(f"\n✅ Successfully processed {len(processed_datasets)} datasets")
        
        for name, df in processed_datasets.items():
            print(f"  {name}: {len(df)} records, {len(df.columns)} features")
        
        print("\nStep 2: Creating unified dataset...")
        unified_dataset = preprocessor.create_unified_dataset(processed_datasets)
        
        if not unified_dataset.empty:
            print(f"✅ Unified dataset created: {len(unified_dataset)} records")
            
            # Show attack distribution
            print("\nAttack Distribution:")
            attack_dist = unified_dataset['label'].value_counts()
            for attack, count in attack_dist.head(10).items():
                print(f"  {attack}: {count:,}")
        else:
            print("❌ Failed to create unified dataset")
    else:
        print("❌ No datasets were processed")
    
    end_time = time.time()
    print(f"\nTotal processing time: {end_time - start_time:.1f} seconds")
    print("Preprocessing test completed!")

if __name__ == "__main__":
    main()
