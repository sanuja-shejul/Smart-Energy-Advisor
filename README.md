# Smart Energy Advisor — all-Python version (Flask)

Every source file in this folder is **Python**. Same website as before (login → add bill → dashboard, the Watt chatbot, the guided tour, the lightbulb
mascot and all animations). The difference: **everything that "thinks" now runs in Python on the server.**

| What | Where it lives |
|---|---|
| Accounts (signup / login / guest), hashed passwords, SQLite | `app.py`, `db.py` |
| CSV reading + cleaning (pandas) | `modules/preprocessing.py` |
| Next-month forecast (numpy regression, seasonal after 12 months) + what-if simulator | `modules/forecasting.py` |
| Unusual-month detection (vs. the same month last year) | `modules/anomaly_detection.py` |
| Appliance breakdown, saving tips, dashboard numbers | `modules/appliance_breakdown.py`, `recommendations.py`, `dashboard.py` |
| Bill-photo OCR (Tesseract, English + Marathi) | `modules/ocr_extractor.py` |
| Watt's answers (use your real data) | `modules/chatbot.py` |
| The page itself (HTML, CSS and the browser script, kept as Python strings and served by Flask) | `ui/page.py`, `ui/styles.py`, `ui/script.py` |

The browser only draws the page and calls the JSON API (`/api/...`). A browser can only show a page
written in HTML/CSS/JavaScript, so those three are stored as text inside the `ui/` modules and sent to
the browser by `app.py` (`/`, `/assets/app.css`, `/assets/app.js`). Only `requirements.txt`, `Procfile`,
`.gitignore` and this README are not `.py`, because pip, the host and Git need them in that form.

## Run it (Windows)

```bat
cd smart_energy_advisor_python_csv
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5000**. (First run creates `instance/app.db` and `instance/secret.key`.)

### OCR (bill photos)
OCR needs the **Tesseract program** installed (not just the Python package). Install it, then if Python
can't find it, tell the app where it is *before* starting:
```bat
set TESSERACT_CMD=D:\smart_energy_advisor\tesseract.exe
python app.py
```
For **Marathi bills** also copy `mar.traineddata` into Tesseract's `tessdata` folder — it is picked up
automatically (English + Marathi). If Tesseract is missing the app still works: the photo box says
"automatic reading isn't set up" and you type the three values yourself.

## Run the tests
```bat
python -m pytest -q
```
39 tests cover accounts, CSV upload, manual entry, forecast, anomalies, simulator, chatbot, OCR and security.

## Deploying
**GitHub Pages cannot run Python** — it only hosts static files. Use a Python host, for example
**Render**, **Railway** or **PythonAnywhere**:
* start command: `gunicorn app:app` (a `Procfile` is included)
* environment variables: `SECRET_KEY` = a long random string, `SEA_HTTPS=1` (secure cookies on https)
* SQLite lives in `instance/`. On hosts with a temporary disk (Render free tier) accounts and bills are
  lost on every restart — attach a persistent disk, or move `db.py` to PostgreSQL.

## Good to know
* Passwords are stored hashed (werkzeug). Login is limited to 8 wrong tries per 10 minutes.
* All POST requests need a CSRF token; the page sends it automatically.
* Guest data is deleted after 3 days. A guest who then signs up keeps what they added.
* Uploads: CSV up to 5 MB, photos up to 6 MB.
* The forecast needs 3+ months; unusual-month detection needs 13+ months (it compares each month with the
  same month a year earlier, so the normal summer rise is not reported as a spike).
* The login rate limiter is per process; with several gunicorn workers use a shared store (e.g. Redis).

## Enterprise edition (new prototype)

The original household dashboard is preserved. A new organization-level prototype is available at:

- `http://127.0.0.1:5000/enterprise`

It is designed as a starting point for schools, colleges, offices and factories. It accepts department-level monthly meter records and provides:

- Department-wise consumption and estimated cost summaries
- Deterministic K-Means grouping of departments by average monthly units (NumPy implementation)
- Simple linear-trend next-month estimates when at least 3 months are available
- Month-to-month spike/drop flags using a 35% and 5-unit threshold
- Recommendations tied to highest usage, after-hours usage, anomalies and forecasts

### Input data format (CSV only)

Use the **Automatic CSV detection** section on the Enterprise page. The upload is the only organization-data entry workflow in the interface; there is no JSON editor or JSON upload section.

Required CSV columns:
- `month` in `YYYY-MM` format
- `units` (numeric energy consumption)
- At least one of `department` or `building`

Optional columns:
- `amount`
- `after_hours_units` (only when supported by meter data or a defensible measurement method)
- `organization_type` or industry-specific terms in column names/values to help automatic detection

At least 3 valid records are required. Built-in demonstration data, if used for testing, is synthetic and must not be presented as real field research.

### Run locally

```bash
python -m venv .venv
# Windows PowerShell:
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/enterprise`. The enterprise API is `POST /api/enterprise/analyze` and uses the same session CSRF protection as the rest of the application.

### Important limitations

This is an academic prototype, not yet a production multi-tenant enterprise platform. It does not yet include organization accounts/roles, live smart-meter integration, time-of-use tariff modeling, or a production database migration. K-Means uses only average monthly department units, so its labels are relative to the uploaded dataset. Forecasts are indicative, not guaranteed. Validate all recommendations with facilities staff before acting on them.

## Automatic CSV dataset detection (new)

The CSV upload flow now calls `/api/upload/auto`. It examines column headers and
sample values, calculates a heuristic confidence score, validates the records,
and routes the file:

- Household: existing bill-history parser and household dashboard.
- School, college, hospital, factory, or office: organization CSV validation,
  enterprise analysis, and Enterprise Dashboard.
- Unknown / low-evidence files: upload is rejected with a detection explanation
  rather than silently assigning the wrong dashboard.

The confidence score is an explainable heuristic evidence score, **not** a
trained machine-learning probability. When evidence is weak, the response sets
`needs_confirmation` and the API asks for a clearer CSV structure. Organization
CSV files need a month column (`YYYY-MM`), a numeric units column, and at least
one of department or building. Optional fields include amount and
`after_hours_units`. Organization analysis needs at least three valid rows.

API response includes `dataset_type`, `dataset_label`, `confidence`, `evidence`,
`validation`, `route`, and the analysis result for organization datasets.


## CSV data profiling (Phase 2)

The automatic CSV upload now creates a data-quality profile before analysis. It reports row/column counts, blank cells by column, duplicate rows, invalid numeric values, negative values, unrecognized dates, and possible IQR-based outliers. Possible outliers are review flags, not automatic errors, and zero consumption is allowed. The quality score is a transparent rule-based indicator (0–100), not an ML probability. Critical numeric/date issues stop analysis until corrected.

If a dataset has a generic organization-level structure but no clear industry-specific evidence, it is classified as **Other organization** with a request for user confirmation instead of being guessed as a hospital, college, or another industry. The user can confirm the suggested type or select the correct type before analysis.
