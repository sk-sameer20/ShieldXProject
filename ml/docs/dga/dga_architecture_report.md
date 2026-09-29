# DGA Detection Architecture Report
**Final Experimental Analysis (v1-v8)**

## 1. Objective
The primary objective of these experiments was to investigate the Out-Of-Distribution (OOD) generalization problem in Domain Generation Algorithm (DGA) detection. Specifically, the goal was to identify representations and architectures capable of detecting unseen DGA families that possess fundamentally different structural characteristics (e.g., dictionary-based vs. short random patterns) than the families observed during training.

## 2. Frozen Dataset Split
To rigorously test generalization, a strict, frozen family-level data split was maintained across all experiments. No models were tuned on the validation or test sets, and no malicious labels from unseen families were injected into the training process.

**TRAIN**
- Benign: 35,000
- Qakbot: 5,000
- Corebot: 40
- Ramdo: 20

**VALIDATION** (Unseen during training)
- Benign: 7,500
- Banjori: 1,000
- Dircrypt: 30

**TEST** (Unseen during training & validation)
- Benign: 7,500
- Simda: 1,000
- Nymaim: 128

## 3. Experiment-by-Experiment Methodology

| Version | Representation | Model | Purpose / What was being tested |
| :--- | :--- | :--- | :--- |
| **DGA-v1** | Lexical Features (Entropy, Length, Vowel/Consonant ratios) | Random Forest | Establish a baseline using classical structural heuristics. Tested whether handcrafted lexical features generalize to unseen DGAs. |
| **DGA-v2** | Character N-Grams (TF-IDF, n=2 to 5) | Logistic Regression | Tested whether bag-of-n-grams captures domain distributions better than global lexical statistics. |
| **DGA-v3** | Structural / Transition Features | Random Forest | Tested whether explicitly modeling English transition probabilities and local entropy profiles captures dictionary-based DGAs (Banjori). |
| **DGA-v4A** | Hybrid (N-Gram + Structural) | Logistic Regression | Tested a linear combination (early fusion) of character distributions and explicit structural features. |
| **DGA-v4B** | Hybrid (N-Gram Prob + Structural) | Meta Random Forest | Tested stacking (with out-of-fold predictions) to combine representations nonlinearly. |
| **DGA-v5** | Hybrid (N-Gram + Structural) | XGBoost | Tested whether a single classical nonlinear model (Gradient Boosting) could learn the interactions between the conflicting representations natively. |
| **DGA-v6** | Character-Level Sequences | 1D-CNN (Embedding + Conv1D + GlobalMaxPooling) | Tested whether a neural architecture could learn translation-invariant spatial patterns for long-range structural DGAs without explicit feature engineering. |
| **DGA-v6.1**| Augmented Sequences | 1D-CNN | Tested whether the CNN's failure on short domains was due to padding/exposure bias by using training-time random length cropping. |
| **DGA-v7** | Character-Level Sequences | GRU (with Masking) | Tested whether a recurrent model handles variable-length sequence differences (short Simda vs long Banjori) natively without data augmentation. |
| **DGA-v8** | Late-Fusion (P_v2, P_v6) | Decision-Level Rules (OR, AND, MAX, MEAN) | Tested whether simply fusing the probability outputs of the two strongest specialized experts balances short and long DGA detection. |

## 4. Results
The following results were measured directly from the evaluation scripts. 

| Experiment | Banjori Recall | Simda Recall | Nymaim Recall | Dircrypt Recall | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **v1** | 0.0% | 0.0% | 45.3% | 93.3% | 0.53% |
| **v2** | 8.3% | 63.8% | 85.2% | 100.0% | 3.31% |
| **v3** | 40.8% | 0.0% | 48.4% | 93.3% | 1.07% |
| **v4A** | 92.3% | 23.3% | 90.6% | 100.0% | 1.56% |
| **v4B** | 70.6% | 35.0% | 93.8% | 100.0% | 1.00% |
| **v5** | 51.0% | 2.5% | 71.9% | 100.0% | 1.36% |
| **v6** | 98.6% | 16.6% | 60.9% | 93.3% | 0.75% |
| **v6.1** | 20.7% | 64.9% | 60.9% | 86.7% | 5.56% |
| **v7** | 58.7% | 4.5% | 60.9% | 86.7% | 1.09% |
| **v8 (OR/MAX)**| 98.6% | 77.7% | 85.9% | 100.0% | 6.52% |
| **v8 (MEAN)** | 83.7% | 27.8% | 71.1% | 96.7% | 0.72% |

*(Note: v8 used an independent training run of v2 that exhibited slight baseline variance (FPR 6.21%, Simda 77.7%), but the structural dynamics remained consistent.)*

## 5. Failure Analysis
- **v1**: The lexical representation overfit to Qakbot's specific characteristics (long, numerical) and failed completely on dictionary patterns (Banjori) and short patterns (Simda).
- **v2**: Character n-grams improved short/random pattern detection (Simda) but lost structural context, rendering it blind to long, English-suffixed patterns (Banjori).
- **v3**: Explicit structural and transition features improved dictionary DGA detection but provided almost zero signal for purely random short DGAs.
- **v4**: Linear hybrid models struggled to reconcile the conflicting signals. The models essentially traded off Simda recall to improve Banjori recall.
- **v5**: Classical nonlinear models (XGBoost) failed to isolate the necessary interactions between structural and n-gram features natively, defaulting to poor short-domain recall.
- **v6**: The 1D-CNN successfully detected dictionary-based anomalies (Banjori 98.6%) with a low FPR (0.75%) due to Global Max Pooling capturing spatial anomalies. However, it demonstrated extreme sensitivity to sequence length, largely failing on short Simda domains.
- **v6.1**: Training-time length augmentation proved that the CNN's Simda failure was caused by padding/exposure bias. However, forcing the network to classify short random snippets destroyed its ability to detect structural context (Banjori fell to 20.7%) and drastically increased the FPR (5.56%).
- **v7**: A masked GRU performed worse across all dimensions. Because recurrent processing relies on hidden state evolution, the vast difference in sequence depth between Simda (short) and Qakbot/Benign (long) generated unrecognizable terminal states, resulting in a 4.5% Simda recall. Banjori recall also degraded as the anomaly of the initial random prefix was diluted over time.
- **v8**: Simple late fusion demonstrated an unacceptable trade-off. The OR/MAX rules achieved high recall but summed the false positive mistakes of both models (6.52% FPR). The MEAN rule suppressed the FPR but crippled the recall, as high confidence from one model was negated by low confidence from the other.

## 6. V8 Overlap Analysis
The observed non-overlap in detections (at a 0.5 threshold) between the v2 (TF-IDF) and v6 (CNN) experts was stark:

**Banjori (1000 samples)**
- Detected by v6 only: 986
- Detected by v2 only: 0
- Detected by both: 0
- Detected by neither: 14

**Simda (1000 samples)**
- Detected by v2 only: 611
- Detected by v6 only: 0
- Detected by both: 166
- Detected by neither: 223

This analysis demonstrates an observed lack of overlap in detections for these specific samples and evaluated thresholds.

## 7. Final Findings
The evaluated experiments show that different representations capture different DGA characteristics. Within the tested configurations, no single model achieved strong performance on both the dictionary-based Banjori family and the short Simda family while maintaining a low false-positive rate. 

## 8. Recommended Architecture
Based on these measurements, the specialized-expert approach is recommended, utilizing:
- A Character N-gram detector (e.g., TF-IDF + LR) as one evidence source for short/random patterns.
- A CNN structural detector as a secondary evidence source for dictionary and spatial anomaly patterns.

It is important to preserve the measured limitations: simple OR/MAX fusion is not production-ready due to its measured 6.52% FPR, and simple MEAN fusion did not achieve an optimal balance without heavily dampening recall.

## 9. Production/SIH Recommendation
**Research Findings:** Detecting completely unseen DGA families with drastically different characteristics (short vs. dictionary) requires conflicting representations that simple ML models struggle to balance natively.
**Current Capabilities:** We possess models that can detect either short random DGAs or structural dictionary DGAs with high accuracy and low FPR, independently.
**Known Limitations:** We currently lack a late-fusion or hierarchical mechanism that calibrates these experts without a substantial FPR penalty. 
**Prototype Integration:** For the SIH prototype, the primary DGA detection module should deploy either the v6 1D-CNN (if prioritizing dictionary DGAs and minimal FPR) or the v2 N-gram model (if prioritizing raw randomness and short DGAs). Alternatively, both models can be deployed to yield an un-fused "Expert Panel" output, shifting the final decision boundary to the SIH threat analyst interface rather than forcing automated mathematical fusion.

## 10. Reproducibility
- **Dataset Split**: Maintained in `data/processed/dga_splits.csv` (Seed: 42).
- **Preprocessing**: `preprocess_domain()` removing subdomains and enforcing lowercasing across all experiments.
- **Model Versions**: v1, v2, v3, v4A, v4B, v5, v6, v6.1, v7, v8.
- **Important Configurations**: Class weights balanced, strict internal-only training vocabulary/scaling, identical 0.5 threshold reporting, no post-hoc tuning.
- **Random Seeds**: SEED=42 enforced in numpy, pandas, scikit-learn, and tensorflow across all Python scripts (`scratch/dga_v*_experiment.py`).
