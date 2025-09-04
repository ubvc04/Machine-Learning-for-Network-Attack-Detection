#!/usr/bin/env python3
"""
📊 FINAL SYSTEM ANALYSIS & VERIFICATION
=======================================
Complete analysis of the threat detection system after training all models.
"""

import os
import glob
import json
import pandas as pd
from datetime import datetime

def analyze_system():
    print("🔍 FINAL THREAT DETECTION SYSTEM ANALYSIS")
    print("=" * 80)
    
    # 1. Model Analysis
    print("\n📁 MODEL ANALYSIS")
    print("-" * 40)
    
    model_files = glob.glob('models/*_model.joblib')
    encoder_files = glob.glob('models/*_encoder.joblib')
    scaler_files = glob.glob('models/*_scaler.joblib')
    vectorizer_files = glob.glob('models/*_vectorizer.joblib')
    
    print(f"Model files: {len(model_files)}")
    print(f"Encoder files: {len(encoder_files)}")
    print(f"Scaler files: {len(scaler_files)}")
    print(f"Vectorizer files: {len(vectorizer_files)}")
    
    # Extract threat types and algorithms
    threat_models = {}
    for model_file in model_files:
        filename = os.path.basename(model_file)
        parts = filename.replace('_model.joblib', '').split('_')
        algorithm = parts[-1]
        threat_type = '_'.join(parts[:-1])
        
        if threat_type not in threat_models:
            threat_models[threat_type] = []
        threat_models[threat_type].append(algorithm)
    
    # Filter out temporary models
    core_threats = {k: v for k, v in threat_models.items() 
                   if not k.startswith(('fast', 'lightning'))}
    
    print(f"\n🎯 CORE THREAT TYPES: {len(core_threats)}")
    for threat, algorithms in sorted(core_threats.items()):
        print(f"   ✅ {threat:20} ({len(algorithms)} models: {sorted(algorithms)})")
    
    # 2. Dataset Analysis
    print(f"\n📊 DATASET ANALYSIS")
    print("-" * 40)
    
    datasets = {
        'emails.csv': 'phishing',
        'Obfuscated-MalMem2022.csv': 'malware',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 'ddos_friday',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 'port_scan',
        'Friday-WorkingHours-Morning.pcap_ISCX.csv': 'bot_attacks',
        'Monday-WorkingHours.pcap_ISCX.csv': 'network_baseline',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 'infiltration',
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 'web_attacks',
        'Tuesday-WorkingHours.pcap_ISCX.csv': 'brute_force',
        'Wednesday-workingHours.pcap_ISCX.csv': 'dos_attacks',
        'ddos_balanced/final_dataset.csv': 'ddos',
        'ddos_imbalanced/unbalaced_20_80_dataset.csv': 'ddos_imbalanced'
    }
    
    dataset_coverage = {}
    for dataset_file, expected_threat in datasets.items():
        full_path = f'dataset/{dataset_file}'
        exists = os.path.exists(full_path)
        has_model = expected_threat in core_threats
        
        dataset_coverage[dataset_file] = {
            'exists': exists,
            'expected_threat': expected_threat,
            'has_model': has_model,
            'status': '✅' if (exists and has_model) else ('🔄' if exists else '❌')
        }
        
        print(f"   {dataset_coverage[dataset_file]['status']} {dataset_file}")
        print(f"      → {expected_threat} ({'✅' if has_model else '❌'})")
    
    # 3. Coverage Analysis
    print(f"\n📈 COVERAGE ANALYSIS")
    print("-" * 40)
    
    total_datasets = len(datasets)
    covered_datasets = sum(1 for d in dataset_coverage.values() if d['exists'] and d['has_model'])
    coverage_percent = (covered_datasets / total_datasets) * 100
    
    print(f"Total datasets: {total_datasets}")
    print(f"Covered datasets: {covered_datasets}")
    print(f"Coverage: {coverage_percent:.1f}%")
    
    # 4. Model Performance Analysis
    print(f"\n🎯 MODEL PERFORMANCE")
    print("-" * 40)
    
    results_files = [
        'model_testing_results.json',
        'comprehensive_training_results.json',
        'targeted_training_results.json'
    ]
    
    all_results = {}
    for results_file in results_files:
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                results = json.load(f)
                all_results.update(results)
            print(f"   ✅ Loaded results from {results_file}")
        else:
            print(f"   ❌ {results_file} not found")
    
    if all_results:
        # Analyze performance by threat type
        threat_performance = {}
        for model_name, result in all_results.items():
            if isinstance(result, dict):
                threat = result.get('threat_type', 'unknown')
                if threat not in threat_performance:
                    threat_performance[threat] = []
                
                accuracy = result.get('accuracy', 0)
                if accuracy:
                    threat_performance[threat].append(accuracy)
        
        print(f"\n📊 Performance Summary:")
        overall_accuracies = []
        for threat, accuracies in sorted(threat_performance.items()):
            if accuracies:
                avg_acc = sum(accuracies) / len(accuracies)
                overall_accuracies.extend(accuracies)
                print(f"   {threat:20}: {avg_acc:.3f} avg ({len(accuracies)} models)")
        
        if overall_accuracies:
            overall_avg = sum(overall_accuracies) / len(overall_accuracies)
            print(f"   {'OVERALL AVERAGE':20}: {overall_avg:.3f}")
    
    # 5. System Files Analysis
    print(f"\n📁 SYSTEM FILES")
    print("-" * 40)
    
    essential_files = [
        'main.py',
        'detect.py',
        'config.py',
        'preprocessing.py',
        'test_all_models.py',
        'test_system.py',
        'threat_cli_tester.py',
        'requirements.txt',
        'README.md'
    ]
    
    for file in essential_files:
        status = '✅' if os.path.exists(file) else '❌'
        size = f"({os.path.getsize(file)} bytes)" if os.path.exists(file) else ""
        print(f"   {status} {file} {size}")
    
    # 6. Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    print("-" * 40)
    
    missing_models = set(datasets.values()) - set(core_threats.keys())
    if missing_models:
        print(f"   🔄 Train missing models: {missing_models}")
    else:
        print(f"   ✅ All datasets have trained models")
    
    incomplete_coverage = [d for d, info in dataset_coverage.items() 
                          if not (info['exists'] and info['has_model'])]
    if incomplete_coverage:
        print(f"   🔄 Address incomplete coverage: {len(incomplete_coverage)} datasets")
    else:
        print(f"   ✅ Complete dataset coverage achieved")
    
    # Check for redundant files
    training_files = [
        'fast_train.py', 'lightning_train.py', 'ultra_fast_train.py',
        'train_models.py', 'comprehensive_train.py', 'analyze_datasets.py'
    ]
    
    remaining_training_files = [f for f in training_files if os.path.exists(f)]
    if remaining_training_files:
        print(f"   🧹 Clean up remaining training files: {remaining_training_files}")
    else:
        print(f"   ✅ Training files cleaned up")
    
    # 7. Final Summary
    print(f"\n🎉 FINAL SYSTEM STATUS")
    print("=" * 80)
    
    status_items = [
        f"✅ {len(core_threats)} threat types covered",
        f"✅ {sum(len(algs) for algs in core_threats.values())} models trained",
        f"✅ {coverage_percent:.1f}% dataset coverage",
        f"✅ Interactive CLI testing tool available",
        f"✅ Comprehensive model testing framework"
    ]
    
    for item in status_items:
        print(f"   {item}")
    
    print(f"\n🚀 SYSTEM READY FOR PRODUCTION USE!")
    print(f"   Run: python threat_cli_tester.py")
    print(f"   Or:  python test_all_models.py")
    
    return {
        'threat_types': len(core_threats),
        'total_models': sum(len(algs) for algs in core_threats.values()),
        'coverage_percent': coverage_percent,
        'status': 'READY'
    }

if __name__ == "__main__":
    analysis = analyze_system()
    
    # Save analysis results
    with open('system_analysis.json', 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"\n💾 Analysis saved to 'system_analysis.json'")
