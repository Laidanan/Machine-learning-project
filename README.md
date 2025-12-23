# Network Intrusion Detection System (NIDS)
## Hierarchical 2-Stage Classification on CIC-IDS2017

A machine learning-based intrusion detection system using a hierarchical two-stage classification approach to detect and categorize network attacks from the CIC-IDS2017 dataset.

---

## Overview

This project implements a production-oriented IDS that mirrors real-world security workflows:

- **Stage 1**: Binary classification (BENIGN vs ATTACK) — *"Is this traffic malicious?"*
- **Stage 2**: Multi-class classification (14 attack types) — *"What kind of attack is it?"*

This hierarchical approach is aligned with current research standards and handles the extreme class imbalance inherent in network traffic data.

---

## Dataset

**CIC-IDS2017** — Canadian Institute for Cybersecurity Intrusion Detection Dataset

| Attribute | Value |
|-----------|-------|
| Total samples | ~2.8 million |
| Features | 78 network flow features |
| Classes | 15 (1 benign + 14 attack types) |
| Class imbalance | Up to 200,000:1 ratio |

### Attack Types
- **DoS/DDoS**: Hulk, Slowloris, Slowhttptest, GoldenEye, DDoS
- **Brute Force**: FTP-Patator, SSH-Patator
- **Web Attacks**: Brute Force, XSS, SQL Injection
- **Other**: Bot, PortScan, Infiltration, Heartbleed

---

## Methodology

### Preprocessing Pipeline (10 Phases)

1. **Load & Clean** — Load 8 CSV files, standardize column names
2. **Feature Reduction** — Drop 37 columns (identifiers, constants, redundant features)
3. **Data Cleaning** — Fix integer overflow, infinite values, negative timestamps
4. **Smart Sampling** — Stratified sampling preserving rare classes (100% rare, 5% common)
5. **Feature Selection** — Top 20 discriminating features by combined score
6. **Feature Engineering** — 7 new features (TCP handshake indicators, ratios, cleaned sentinels)
7. **Target Preparation** — Binary and multi-class labels
8. **Train/Test Split** — 80/20 stratified split
9. **Scaling** — Log1p + StandardScaler on continuous features
10. **SMOTE** — Synthetic oversampling for rare attack classes

### Final Feature Set (27 features)

**Top discriminators identified through EDA:**
- `Init_Win_bytes_backward` (0.945 score) — TCP window size, key attack indicator
- `Min Packet Length`, `Fwd Packet Length Min/Mean/Max`
- `Bwd Packet Length Std/Min/Mean`
- `Flow IAT Std/Max`, `Fwd IAT Std/Max`
- `PSH Flag Count`, `Idle Max`, `Bwd Packets/s`

**Engineered features:**
- `has_tcp_handshake`, `is_zero_window`, `is_zero_duration`
- `init_win_bwd_clean`, `init_win_fwd_clean`
- `fwd_bwd_packet_ratio`, `fwd_bwd_bytes_ratio`

---

## Results

### Stage 1: Binary Classification

| Metric | Test Score |
|--------|------------|
| Accuracy | 99.7% |
| BENIGN F1 | 1.00 |
| ATTACK F1 | 0.99 |
| ROC-AUC | 0.998 |

### Stage 2: Attack Classification

| Attack Type | Test F1 | Support |
|-------------|---------|---------|
| DoS Hulk | 1.00 | 2,311 |
| DDoS | 1.00 | 1,280 |
| PortScan | 1.00 | 1,589 |
| Bot | 1.00 | 393 |
| FTP-Patator | 1.00 | 79 |
| SSH-Patator | 0.99 | 59 |
| DoS Slowloris | 0.98 | 58 |
| DoS Slowhttptest | 0.98 | 55 |
| DoS GoldenEye | 0.99 | 103 |
| Heartbleed | 1.00 | 2 |
| Infiltration | 0.92 | 7 |
| Web Attack - Brute Force | 0.90 | 15 |
| Web Attack - SQL Injection | 0.75 | 4 |
| Web Attack - XSS | 0.71 | 7 |

**Macro Average F1: 0.94**

### 2-Stage Pipeline (End-to-End)

| Category | F1 Score | Status |
|----------|----------|--------|
| Volumetric attacks (DoS/DDoS/Bot) | 95-100% | ✅ Production-ready |
| Brute force attacks | 98-100% | ✅ Production-ready |
| Web application attacks | 17-86% | ⚠️ Limited by flow data |

**Overall Accuracy: 99.6%**

---

## Repository Structure

```
├── data/                          # CIC-IDS2017 CSV files (not included)
├── 01_data_health.ipynb           # EDA Phase 1: Data quality assessment
├── 02_feature_analysis.ipynb      # EDA Phase 2-3: Feature distributions
├── 03_target_analysis.ipynb       # EDA Phase 4: Class imbalance analysis
├── 04_correlations_semantic.ipynb # EDA Phase 5-6: Correlations & grouping
├── 05_final_preprocessing.ipynb   # EDA Phase 7: Final feature selection
├── 06_preprocessing_2stage_model.ipynb  # Full pipeline & modeling
└── README.md
```

---

## Installation & Usage

### Requirements

```bash
pip install pandas numpy scikit-learn xgboost imbalanced-learn matplotlib seaborn
```

### Data Setup

1. Download CIC-IDS2017 dataset from [UNB](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place CSV files in `data/` directory

### Run Pipeline

```python
# Open and run the main notebook
jupyter notebook 06_preprocessing_2stage_model.ipynb
```

### Inference

```python
import pickle
import pandas as pd

# Load models
with open('model_artifacts/model_stage1.pkl', 'rb') as f:
    model_s1 = pickle.load(f)
with open('model_artifacts/model_stage2.pkl', 'rb') as f:
    model_s2 = pickle.load(f)
with open('model_artifacts/label_encoder_stage2.pkl', 'rb') as f:
    label_encoder = pickle.load(f)

def predict(X):
    """2-stage prediction pipeline"""
    pred_s1 = model_s1.predict(X)
    results = ['BENIGN'] * len(X)
    
    attack_mask = pred_s1 == 1
    if attack_mask.sum() > 0:
        pred_s2 = model_s2.predict(X[attack_mask])
        attack_labels = label_encoder.inverse_transform(pred_s2)
        for i, idx in enumerate(attack_mask.nonzero()[0]):
            results[idx] = attack_labels[i]
    
    return results
```

---

## Limitations & Future Work

### Current Limitations

1. **Web application attacks** — Network flow features capture packet sizes and timing, not payload content. SQL injection and XSS look like normal HTTP requests at the flow level.

2. **Extreme class rarity** — Some attacks have <10 test samples, making evaluation statistically unreliable.

3. **Cascade errors** — Stage 1 misclassifications propagate to Stage 2.

### Potential Improvements

| Improvement | Expected Impact |
|-------------|-----------------|
| Tune Stage 1 threshold for higher recall | Fewer missed attacks |
| More aggressive SMOTE/augmentation | Better rare class detection |
| Deep packet inspection features | Detect content-based attacks |
| Ensemble methods | Reduce variance on rare classes |
| Cost-sensitive learning | Prioritize attack detection over precision |

---

## Key Findings

1. **`Init_Win_bytes_backward` is the strongest discriminator** — TCP window size behavior cleanly separates attack traffic from benign.

2. **Hierarchical architecture handles imbalance** — Separating binary detection from attack classification improves overall performance.

3. **Network flow data has fundamental limits** — Application-layer attacks require deeper inspection beyond flow statistics.

4. **SMOTE works for extremely rare classes** — Heartbleed went from 11 samples to 100% detection with synthetic oversampling.

---

## Acknowledgments

- **Dataset**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick
- **Reference**: Sharafaldin, I., Lashkari, A.H., & Ghorbani, A.A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.

---

## License

MIT License
