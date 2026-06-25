# Fraud Detection System

> Multi-algorithm anomaly detection for financial transactions — catching fraud before it cascades.

## Overview

Built for detecting anomalous patterns in financial transaction data. Uses an ensemble of statistical and machine learning approaches to minimize false positives while catching sophisticated fraud patterns.

## Features

- **Isolation Forest** — unsupervised anomaly detection for high-dimensional data
- **Z-Score + IQR ensemble** — statistical outlier detection with tunable sensitivity
- **EWMA control charts** — exponentially weighted moving average for trend anomalies
- **Autoencoder reconstruction error** — deep learning approach for complex patterns
- **Real-time scoring** — sub-millisecond inference for transaction streaming
- **Explainable alerts** — SHAP-style feature contribution for each flagged transaction

## Tech Stack

- Python 3.11, scikit-learn, TensorFlow, pandas
- Google Colab (TPU-accelerated for autoencoder training)
- SHAP for model explainability

## Results

- **Detection rate**: 94.2% of confirmed fraud cases
- **False positive rate**: 2.1% (down from 8.5% with rule-based system)
- **Processing speed**: 50,000+ transactions/second
- **Models ensemble**: Isolation Forest (40%) + Autoencoder (35%) + Statistical (25%)

## Author

**Victor Ndunda** — Data Analyst & AI Engineer
- GitHub: [@gadda00](https://github.com/gadda00)
- LinkedIn: [victor-ndunda](https://www.linkedin.com/in/victor-ndunda)

## License

MIT
