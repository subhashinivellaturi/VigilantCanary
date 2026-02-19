# Web Vulnerability Detection Using Hybrid ML

Vigilant Canary is a full-stack security analytics project that blends Isolation Forest anomaly detection with a LightGBM classifier to flag vulnerable web requests before attackers can weaponize them. The system exposes an opinionated FastAPI backend, a modern React + Vite frontend, and reproducible ML workflows that mirror the IV B.Tech (CIC) Project Team 15 brief.

## Extensions Based on Research Papers

This project implements extensions from two base research papers:

1. **Adaptive Hybrid Learning for Websites Vulnerability** - Implements clustering-based anomaly detection and enhanced feature engineering.
2. **Vulnerability Prediction Models for JavaScript Functions Using Static Source Code Metrics** - Adds static code metrics and synthetic data generation.

### Key Extensions Implemented:

- **Clustering-Enhanced Anomaly Detection**: Uses K-means clustering before applying Isolation Forest per cluster, improving anomaly detection accuracy.
- **Advanced Feature Engineering**: Incorporates Halstead metrics, cyclomatic complexity, and textual features for better vulnerability prediction.
- **Synthetic Data Generation**: Generates adversarial examples to overcome data quality and quantity limitations.
- **Incremental Learning**: Supports real-time model updates to adapt to evolving threats.

## Feature Highlights
- **Hybrid modeling pipeline**: K-means clustering + Isolation Forest enriches feature vectors with anomaly scores before LightGBM performs supervised classification, reaching ~96% accuracy and ~0.90 precision on the vulnerable class with the bundled 5K real attack trace corpus.
- **Actionable insights**: Every scan responds with severity buckets, anomaly deltas, top contributing features, and curated remediation playbooks.
- **Analyst-friendly UI**: A bespoke dashboard (Space Grotesk typography, teal/sunset palette) delivers animated score tiles, form-driven scans, and trend charts without default boilerplate styling.
- **Autonomous refresh**: The backend retrains on startup and on a scheduled cadence, guaranteeing that LightGBM benefits from newly observed patterns.
- **Extensible data layer**: Deterministic seed samples are programmatically augmented, and the repo seeds 5,000 curated real attack traces that you can extend with fresh telemetry.

## Comprehensive Vulnerability Detection

### Classification Rules
**A website/payload is marked SAFE only when ALL checks pass:**
- ✓ No SQL injection patterns detected
- ✓ No XSS payload reflection patterns detected
- ✓ No path traversal indicators found
- ✓ No command injection patterns detected
- ✓ No missing security headers detected
- ✓ No open directories exposed
- ✓ Uses HTTPS (secure connection)

**If EVEN ONE vulnerability is found → Classification is UNSAFE**

### Detected Attack Patterns
1. **SQL Injection** (Severity: 0.95)
   - Patterns: `UNION`, `SELECT`, `INSERT`, `DROP`, `--`, `' OR '`, `1=1`
   - Impact: Unauthorized database access and data manipulation

2. **XSS (Cross-Site Scripting)** (Severity: 0.85)
   - Patterns: `<script>`, `onerror=`, `onclick=`, `javascript:`, `innerHTML`, `eval(`
   - Impact: Malicious script injection into web pages

3. **Path Traversal** (Severity: 0.80)
   - Patterns: `../`, `..\\`, `.env`, `/etc/passwd`, `.git`, `.htaccess`
   - Impact: Unauthorized file system access

4. **Command Injection** (Severity: 0.90)
   - Patterns: `;`, `|`, `&&`, `` ` ``, `$()`, `bash`, `cmd.exe`
   - Impact: Arbitrary system command execution

5. **Security Misconfigurations** (Severity: 0.60-0.70)
   - Insecure HTTP: Uses plain HTTP instead of HTTPS
   - Missing Headers: CSP, HSTS, X-Frame-Options not enforced
   - Open Directories: Admin panels, debug endpoints, sensitive files exposed

### Error Handling & Input Validation
- **Frontend**: URL validation, payload sanitization, null safety checks
- **Backend**: Input validation, response validation, defensive null handling
- **User Experience**: Clear error messages, meaningful validation feedback


## Repository Layout
```
.
├── backend
│   ├── app
│   │   ├── api/              # FastAPI routers
│   │   ├── models/           # Pydantic schemas
│   │   └── services/         # Feature extraction, training, inference
│   ├── scripts/train_model.py
│   ├── requirements.txt
│   └── tests/                # Pytest smoke tests
├── frontend
│   ├── src/
│   │   ├── api/              # REST helpers
│   │   ├── components/       # Dashboard widgets
│   │   └── hooks/            # Reusable React hooks
│   └── package.json
└── README.md
```

## Getting Started
### Prerequisites
- Python 3.11+
- Node.js 18+
- Recommended: `uv` or `pip` for Python deps, `npm` or `pnpm` for frontend deps

### 1. Backend Setup
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Set `VITE_API_URL` inside `frontend/.env` if the backend runs on a non-default host.

### 3. Running Tests
```bash
cd backend
pytest
```

## ML Workflow
1. **Feature Engineering** – `features.py` extracts ratios, entropy, suspicious token counts, and semantic signals from URLs + payloads.
2. **Real Attack Curation** – `trainer.py` bootstraps balanced safe/vulnerable traces from the 5K real dataset and still allows augmentation for scenario testing.
3. **Hybrid Modeling** – `VulnerabilityPipeline` scales numeric inputs, learns Isolation Forest anomaly scores, concatenates them with the scaled matrix, and trains LightGBM.
4. **Explainability** – The pipeline surfaces the top 5 weighted features per prediction, which power the UI’s insight cards and the API response payload.

## Frontend Experience
- **Scan Composer** – Analysts paste endpoints + payloads, annotate frameworks, and kick off scans with a single action.
- **Risk Tiles + Timeline** – Animated cards broadcast severity, probability, and anomaly scores while a Recharts timeline tracks drift across sessions.
- **Fix Playbook** – Curated OWASP-aligned recommendations adapt to the attack surface (SQLi, XSS, traversal, or general hardening).

## Extending the Project
1. Extend the 5K base dataset with new labeled traffic or static analysis results.
2. Persist Isolation Forest metrics and LightGBM models using the provided `scripts/train_model.py` helper.
3. Wire the frontend’s health widget into real build metadata or CI pipelines.
4. Introduce authentication and role-based access on the API before productionizing.

## Troubleshooting
- **LightGBM compilation issues**: Install the latest Visual C++ Build Tools on Windows if `pip` cannot compile binary wheels.
- **CORS errors**: Update `FRONTEND_URL` in `backend/app/config.py` or set the `FRONTEND_URL` environment variable.
- **Model refresh timing**: Adjust `model_refresh_minutes` inside `Settings` to tune retraining cadence.

## Credits
- Team 15 — V.Lakshmi Subhashini (22BQ1A47A6), P. Karthik (22BQ1A4776), P. Venkata Rishi (22BQ1A4773), M. Kowshik (22BQ1A4758)
- Guide — S. K. Sameerunnisa, Assistant Professor (CIC)
