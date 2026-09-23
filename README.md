# AI Cybersecurity Scanner

AI Cybersecurity Scanner is a full-stack machine-learning project for detecting phishing URLs and Windows PE malware. It combines reproducible data pipelines, three tree-based model families, read-only static PE analysis, explainable inference, FastAPI endpoints, a React dashboard, and SQLite scan history.

The repository does not contain fabricated models, predictions, or metrics. Dataset files and trained artifacts are intentionally excluded from Git. Until real artifacts are trained, inference endpoints return HTTP `503`.

## 1. Project Overview

The application provides two independent detection workflows:

- **Phishing detection:** converts an HTTP(S) URL into offline lexical features and estimates its phishing probability.
- **Malware detection:** validates an uploaded `.exe`, extracts static PE and EMBER-compatible features without executing the file, and estimates its malware probability.

Successful scans receive a risk score, local model explanation, database record, and dashboard representation. The frontend includes Dashboard, Phishing Scanner, Malware Scanner, Scan History, and Model Metrics navigation.

## 2. Problem Statement

Phishing links and malicious Windows executables remain common attack vectors. Manual inspection is slow, inconsistent, and unsuitable for large volumes. A useful academic prototype must provide reproducible ML experiments and practical inference while avoiding unsafe behavior such as visiting submitted URLs or executing uploaded binaries.

This project addresses that problem with offline URL analysis and read-only PE static analysis. Model verdicts come exclusively from trained artifacts; heuristic features and explanations never replace the ML prediction.

## 3. Objectives

- Prepare and validate phishing URL datasets from heterogeneous CSV schemas.
- Prepare balanced, supervised EMBER/BODMAS feature datasets.
- Train and compare Random Forest, XGBoost, and LightGBM.
- Prevent test-set leakage with fixed stratified train/validation/test splits.
- Report Accuracy, Precision, Recall, F1, ROC-AUC, confusion matrix, false positives, and false negatives where relevant.
- Serve phishing and malware inference through FastAPI.
- Perform PE analysis without executing, importing, or launching uploaded files.
- Explain individual predictions using SHAP or an explicitly identified approximation.
- Persist scan history and visualize operational statistics.
- Fail closed when datasets, models, preprocessors, metadata, or schemas are unavailable or inconsistent.

## 4. Architecture

```text
USER
  |
  v
React + Vite
  |
  v
FastAPI
  |
  +-----------------------------+
  |                             |
  v                             v
Phishing Module             Malware Module
  |                             |
  v                             v
URL Features                PE Static Features
  |                             |
  v                             v
Phishing ML Model           Malware ML Model
  |                             |
  +--------------+--------------+
                 |
                 v
             Risk Engine
                 |
                 v
          SQLite Scan History
                 |
                 v
              Dashboard
```

Inference flow:

```text
Input -> validation -> feature extraction -> saved preprocessor
      -> saved model.predict_proba -> risk mapping -> explanation
      -> SQLite -> API response -> React UI
```

## 5. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Recharts |
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Database | SQLite |
| Machine learning | scikit-learn, LightGBM, XGBoost, joblib |
| Data processing | pandas, NumPy |
| PE static analysis | pefile |
| Explainable AI | SHAP with feature-ablation fallback |
| Testing and audit | pytest, FastAPI TestClient, pip-audit, npm audit |

## 6. Folder Structure

```text
ai-cybersecurity-scanner/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── dashboard.py
│   │   │   ├── history.py
│   │   │   ├── malware.py
│   │   │   └── phishing.py
│   │   ├── database/
│   │   │   ├── database.py
│   │   │   └── models.py
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── artifact_validation.py
│   │   │   ├── explainability.py
│   │   │   ├── malware_detector.py
│   │   │   ├── pe_feature_extractor.py
│   │   │   ├── phishing_detector.py
│   │   │   └── risk_engine.py
│   │   ├── utils/
│   │   └── main.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/api.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── ml/
│   ├── phishing/
│   │   ├── features.py
│   │   ├── preprocessing.py
│   │   ├── prepare_dataset.py
│   │   └── train.py
│   └── malware/
│       ├── features.py
│       ├── preprocessing.py
│       ├── prepare_dataset.py
│       └── train.py
├── data/
│   ├── raw/
│   └── processed/
├── models/
├── tests/
├── .gitignore
└── README.md
```

Raw/processed datasets, malware model artifacts, SQLite databases, virtual environments, frontend dependencies, and build output are ignored by Git. The trained phishing model, its preprocessor, and metadata are included; the large model file is stored with Git LFS. BODMAS model artifacts are left local because the dataset provider restricts redistribution; a fresh clone needs an authorized BODMAS dataset and local malware training before malware inference is available.

## 7. Dataset

### Phishing

The preparation pipeline accepts raw-URL CSV datasets such as:

- PhiUSIIL
- PhishVN
- a UCI-derived dataset that retains the original URL
- equivalent datasets with URL and binary label columns

Labels are normalized to:

```text
0 = legitimate
1 = phishing
```

The classic feature-only UCI dataset cannot reconstruct lexical URL features because it does not contain raw URLs.

### Malware

Preferred input is [EMBER](https://github.com/elastic/ember), using its vectorized `X_train.dat` and `y_train.dat` files. [BODMAS](https://whyisyoung.github.io/BODMAS/) `bodmas.npz` is also supported.

Labels are:

```text
0  = benign
1  = malware
-1 = unlabeled EMBER sample, excluded from supervised output
```

EMBER v1 uses 2,351 features. EMBER v2 and BODMAS use 2,381 features. For constrained machines, the CLI can create a deterministic balanced subset, for example 50,000 benign and 50,000 malware samples.

Dataset licenses and access conditions remain the responsibility of the user. Do not commit datasets or malware binaries to this repository.

## 8. Phishing ML Pipeline

The phishing pipeline performs no HTTP request, DNS lookup, page download, or reputation lookup. It extracts 18 lexical inputs:

```text
url_length                    domain_length
path_length                   query_length
num_dots                      num_hyphens
num_underscores               num_slashes
num_digits                    num_special_characters
num_subdomains                uses_https
contains_ip_address           contains_at_symbol
contains_suspicious_port      num_parameters
url_entropy                   suspicious_keyword_count
```

Suspicious keyword counts are model inputs only and never produce a rule-based verdict. Preprocessing validates missing values, duplicate URLs, URL format, label values, and column detection. The prepared output is:

```text
data/processed/phishing.csv
```

Training compares Random Forest, XGBoost, and LightGBM using a stratified `70/15/15` train/validation/test split with seed `42`. Selection uses validation F1, ROC-AUC, Recall, Precision, then Accuracy. The selected family is refit on train + validation and evaluated once on the untouched test set.

## 9. Malware ML Pipeline

Phase 5 preparation reads pre-extracted numeric feature datasets only. It does not open the original malware samples. Compressed NPZ was chosen over CSV for the 2,381-dimensional representation:

```text
data/processed/malware_features.npz
├── X
├── y
├── feature_names
└── metadata
```

Training uses the same reproducible `70/15/15` strategy and compares all three model families. Selection prioritizes validation F1, Recall, ROC-AUC, Precision, then Accuracy. LightGBM is the final metric tie-breaker for datasets with at least 1,000 features. False positives and false negatives are reported explicitly.

At inference time, `pefile` reads the uploaded PE and produces:

- human-readable header, import, export, section, and entropy information;
- byte and byte-entropy histograms;
- string statistics;
- an ordered 2,381-position EMBER v2-compatible vector.

Schema validation rejects missing, unexpected, or reordered features. Optional structures that are genuinely absent use the zero-valued block defined by the EMBER representation; required missing fields fail explicitly.

## 10. Installation

Requirements:

- Python 3.11 or newer recommended
- Node.js with npm
- PowerShell commands below assume Windows
- sufficient memory and storage for the selected malware subset

Clone or open the project root, then install backend dependencies:

```powershell
cd D:\VScode\ai-cybersecurity-scanner
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
```

Install frontend dependencies:

```powershell
cd frontend
npm ci
cd ..
```

The backend must be launched from the project root so both `backend` and `ml` are importable.

## 11. Dataset Preparation

### Prepare phishing data

```powershell
python -m ml.phishing.prepare_dataset `
  --input data/raw/phishing.csv `
  --label-scheme phiusiil
```

For non-standard columns:

```powershell
python -m ml.phishing.prepare_dataset `
  --input data/raw/phishing.csv `
  --url-column raw_url `
  --label-column target `
  --label-scheme zero-one
```

Use `--label-scheme phiusiil` for the official PhiUSIIL convention `1 = legitimate`, `0 = phishing`. Use `--label-scheme uci` for numeric UCI-style `-1 = phishing`, `1 = legitimate` data.

### Prepare EMBER data

Place these files in `data/raw/ember/`:

```text
X_train.dat
y_train.dat
```

Then run:

```powershell
python -m ml.malware.prepare_dataset `
  --dataset ember `
  --sample-size 100000
```

### Prepare BODMAS data

```powershell
python -m ml.malware.prepare_dataset `
  --dataset bodmas `
  --input D:\datasets\bodmas.npz `
  --sample-size 100000
```

Each CLI prints total samples, class counts, excluded unlabeled rows, feature count, missing values, and class distribution. Dataset preparation does not train a model.

## 12. Training

Train and compare all phishing models:

```powershell
python -m ml.phishing.train --model all --dataset-name PhiUSIIL
```

Train and compare all malware models:

```powershell
python -m ml.malware.train --model all --dataset-name EMBER
```

Train one family when required:

```powershell
python -m ml.phishing.train --model random_forest
python -m ml.phishing.train --model xgboost
python -m ml.phishing.train --model lightgbm

python -m ml.malware.train --model random_forest
python -m ml.malware.train --model xgboost
python -m ml.malware.train --model lightgbm
```

Successful training creates:

```text
models/
├── phishing_model.joblib
├── phishing_preprocessor.joblib
├── phishing_model_metadata.json
├── malware_model.joblib
├── malware_preprocessor.joblib
└── malware_model_metadata.json
```

Metadata includes real held-out metrics, confusion matrix, split sizes, seed, feature order, dataset hash, library versions, artifact filenames, and SHA-256 hashes of the model and preprocessor. No metric is hard-coded.

The current phishing artifacts are tracked in this repository for a ready-to-demo phishing API. The phishing model is stored through Git LFS because it exceeds GitHub's regular per-file limit. Malware artifacts trained from BODMAS are kept local; users should follow the dataset provider's access and redistribution conditions, prepare an authorized local dataset, and train their own malware model.

## 13. Backend

Start FastAPI from the project root:

```powershell
.\backend\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Services:

- API: <http://127.0.0.1:8000>
- OpenAPI/Swagger: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>
- SQLite file: `backend/scanner.db`, created automatically

Successful scans are stored in the `scans` table with type, target, optional SHA-256, prediction, probability, risk score, risk level, and timestamp.

## 14. Frontend

In a second terminal:

```powershell
cd D:\VScode\ai-cybersecurity-scanner\frontend
npm run dev
```

Open <http://localhost:5173>.

The Vite development proxy forwards application API calls to FastAPI. The UI provides:

- dashboard counters, four charts, and recent scans;
- URL input with phishing results and local explanations;
- drag-and-drop `.exe` upload with PE details and local explanations;
- server-side history search, filters, sorting, and pagination;
- responsive layouts and error/loading states.

For a classroom demo, start the backend first, then the frontend. Confirm `/health`, show the model metadata, scan a known benign URL/file and a controlled labeled test example, then review Dashboard and Scan History. Never use an unknown live executable for the demonstration.

## 15. API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| POST | `/api/phishing/analyze` | Analyze one HTTP(S) URL |
| POST | `/api/malware/analyze` | Analyze one multipart `.exe` upload |
| GET | `/api/dashboard` | Aggregates, charts, and recent scans |
| GET | `/api/history` | Paginated and filtered scan history |

### Phishing request

```http
POST /api/phishing/analyze
Content-Type: application/json

{"url":"https://example.com"}
```

### Malware request

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/malware/analyze `
  -F "file=@C:\safe-test-files\sample.exe"
```

### Risk levels

```text
0-29   LOW
30-59  MEDIUM
60-79  HIGH
80-100 CRITICAL
```

### History query parameters

```text
page=1
page_size=20
scan_type=PHISHING|MALWARE
risk_level=LOW|MEDIUM|HIGH|CRITICAL
search=target-or-sha256
sort_order=asc|desc
```

Important failure responses:

| Status | Meaning |
|---|---|
| 400 | Invalid filename, extension, or empty upload |
| 413 | Upload exceeds 25 MB |
| 422 | Invalid URL, MZ/PE structure, or feature schema |
| 503 | Required trained artifacts are unavailable or invalid |
| 500 | Generic internal error; no traceback is returned |

## 16. Testing

Run the complete suite:

```powershell
cd D:\VScode\ai-cybersecurity-scanner
.\backend\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp
```

Current verification baseline:

```text
63 passed
0 skipped
```

The suite covers health, phishing features and API, invalid URLs, PE extraction, malware API, fake executables, oversized uploads, missing models, risk boundaries, SQLite migration/query behavior, CORS, cleanup, generic errors, explainability, data splits, feature order, artifact round trips, and metadata integrity.

Additional checks:

```powershell
.\backend\.venv\Scripts\python.exe -m pip check
.\backend\.venv\Scripts\python.exe -m pip_audit

cd frontend
npm audit
npm run build
```

Last verified results:

```text
pip check:  no broken requirements
pip-audit:  no known vulnerabilities
npm audit:  0 vulnerabilities
Vite build: successful
```

## 17. Security Considerations

- URLs are parsed locally; the phishing module never visits the submitted site.
- Malware analysis is static and read-only. The application never executes, imports, launches, or dynamically loads uploaded code.
- Only plain `.exe` filenames are accepted; path components, control characters, bidi controls, other extensions, invalid MZ signatures, malformed PE structures, and files above 25 MB are rejected.
- Uploads are streamed into a random temporary directory, hashed during transfer, closed, and deleted on both success and failure.
- The backend recalculates SHA-256 during PE extraction to detect changes during analysis.
- CORS permits only `http://localhost:5173` and `http://127.0.0.1:5173`.
- Unexpected exceptions return only `{"detail":"Internal server error."}`; tracebacks remain in server logs.
- SQL filters are parameterized, sort values are allow-listed, and SQLite columns include validation constraints.
- Artifact loading is fail-closed. Metadata must match model family, class name, binary classes, input dimensions, feature names/order, artifact filenames, and artifact SHA-256 hashes.
- Artifact hashes are verified before `joblib.load`. Joblib artifacts must still come from a trusted training environment because joblib is not a safe format for untrusted files.
- There is no random prediction, dummy model, hard-coded metric, or heuristic verdict fallback.

## 18. Limitations

- Dataset and model quality determine detection quality. This is an academic prototype, not a replacement for an enterprise security product.
- No datasets or production models are bundled. Inference returns `503` until both pipelines are trained with real data.
- Phishing detection uses URL lexical features only; it does not inspect page content, certificates, DNS, redirects, or domain reputation.
- Malware detection is static. Packed, encrypted, obfuscated, fileless, or behavior-dependent malware may evade it.
- EMBER reference features were originally produced with LIEF. The `pefile` extractor preserves the 2,381-position schema, but parser-specific categorical differences may affect hashed bins.
- SHAP values describe model behavior for one sample and are not causal explanations. Feature ablation is an approximation and may not capture interactions.
- SQLite is suitable for a local single-instance demo, not a high-concurrency distributed deployment.
- Authentication, authorization, rate limiting, CSRF strategy for deployed environments, and per-user history are not implemented.
- The upload limit is fixed at 25 MB and only `.exe` is supported; DLL support is intentionally disabled.
- The Model Metrics page is currently a UI placeholder; authoritative metrics are stored in the generated metadata JSON files.

## 19. Future Development

- Add authenticated users, roles, per-user scan history, rate limits, and audit logging.
- Move production persistence to PostgreSQL and introduce schema migrations.
- Add a background job queue for large-file analysis and progress reporting.
- Add controlled `.dll` support with the same validation and cleanup guarantees.
- Evaluate richer phishing signals such as DNS, certificate, page, redirect, and reputation data through isolated services.
- Add temporal malware evaluation, calibration, drift monitoring, threshold tuning, and false-negative-focused alert policies.
- Add model registry/versioning, signed artifact manifests, reproducible containers, CI/CD, and automated retraining gates.
- Connect the Model Metrics page to metadata and experiment history.
- Add deployment profiles for Docker, reverse proxy TLS, secrets management, centralized logging, and monitoring.
- Keep dynamic analysis outside this process; if introduced, use a dedicated isolated sandbox rather than the FastAPI host.

### Clean-machine end-to-end command sequence

Replace `<REPOSITORY_URL>` and dataset source paths with real values. These commands never create synthetic training data or fake metrics.

```powershell
# 1. Clone
git clone <REPOSITORY_URL> ai-cybersecurity-scanner
cd ai-cybersecurity-scanner

# 2. Install backend and frontend dependencies
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt

cd frontend
npm ci
cd ..

# 3. Supply and prepare a real phishing dataset
Copy-Item D:\datasets\phishing.csv data\raw\phishing.csv
python -m ml.phishing.prepare_dataset `
  --input data\raw\phishing.csv `
  --label-scheme phiusiil

# 4. Train real phishing models and save the selected artifact
python -m ml.phishing.train `
  --model all `
  --dataset-name PhiUSIIL

# 5. Supply and prepare real EMBER vectorized features
Copy-Item D:\datasets\ember\X_train.dat data\raw\ember\X_train.dat
Copy-Item D:\datasets\ember\y_train.dat data\raw\ember\y_train.dat
python -m ml.malware.prepare_dataset `
  --dataset ember `
  --sample-size 100000

# Alternative BODMAS preparation:
# python -m ml.malware.prepare_dataset `
#   --dataset bodmas `
#   --input D:\datasets\bodmas.npz `
#   --sample-size 100000

# 6. Train real malware models and save the selected artifact
python -m ml.malware.train `
  --model all `
  --dataset-name EMBER

# 7. Start backend in terminal 1, from the project root
python -m uvicorn backend.app.main:app `
  --reload `
  --host 127.0.0.1 `
  --port 8000
```

Open a second PowerShell terminal:

```powershell
# 8. Start frontend
cd path\to\ai-cybersecurity-scanner\frontend
npm run dev
```

With both servers running, use a third terminal:

```powershell
cd path\to\ai-cybersecurity-scanner

# Verify health
Invoke-RestMethod http://127.0.0.1:8000/health

# 9. Scan a URL
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/phishing/analyze `
  -ContentType 'application/json' `
  -Body '{"url":"https://example.com"}'

# 10. Scan the benign Python launcher from this virtual environment
curl.exe -X POST http://127.0.0.1:8000/api/malware/analyze `
  -F "file=@backend/.venv/Scripts/python.exe;filename=python.exe"

# 11. Dashboard data
Invoke-RestMethod http://127.0.0.1:8000/api/dashboard

# 12. Scan history data
Invoke-RestMethod 'http://127.0.0.1:8000/api/history?page=1&page_size=20'

# 13. Full verification
.\backend\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp
.\backend\.venv\Scripts\python.exe -m pip check
.\backend\.venv\Scripts\python.exe -m pip_audit

cd frontend
npm audit
npm run build
```

Open the UI at <http://localhost:5173> to demonstrate the scanners, Dashboard, and Scan History. If training artifacts do not exist, both scan endpoints intentionally return HTTP `503` with a clear “Train model first” message.

---

For a submission package, include this repository, dataset citations/licenses, generated metadata JSON files, screenshots of the five UI pages, and a short report describing the real training results. Do not include malware binaries, private datasets, virtual environments, `node_modules`, or temporary upload files.
