# PhishGuard AI Service

Behavioral phishing detection using Random Forest + XGBoost ensemble.

## Setup

```bash
pip install -r requirements.txt
```

## Train the model (run once)

```bash
cd training
python generate_dataset.py   # creates data/behavioral_dataset.csv
python train_model.py        # trains + saves models/
```

## Start the server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | /health | Service + model status |
| POST | /predict | Single session prediction |
| POST | /predict/batch | Batch predictions |
| GET | /model/info | Feature importances, model type |
| GET | /docs | Auto-generated Swagger UI |

## Prediction Request (from Spring Boot)

```json
POST /predict
{
  "session_id": "uuid",
  "features": {
    "mouse_point_count": 420,
    "mouse_jitter": 8,
    "avg_mouse_speed": 1.8,
    "keystroke_count": 45,
    "typing_speed_cps": 4.2,
    "backspace_count": 3,
    "paste_count": 0,
    "typing_delay_mean": 240,
    "typing_delay_stddev": 85,
    "click_count": 6,
    "rapid_clicks": 0,
    "total_active_ms": 22000,
    "frontend_anomaly_score": 10
  }
}
```

## Response

```json
{
  "label": "LEGIT",
  "threat_score": 5,
  "confidence": 0.97,
  "probabilities": { "LEGIT": 0.97, "SUSPICIOUS": 0.02, "PHISHING": 0.01 },
  "top_features": [...]
}
```

## Features (13 total)

| Feature | Description |
|---------|-------------|
| `mouse_point_count` | Number of mouse position samples |
| `mouse_jitter` | Abrupt direction changes (bots are erratic) |
| `avg_mouse_speed` | Average pixels/ms |
| `keystroke_count` | Total keys pressed |
| `typing_speed_cps` | Characters per second |
| `backspace_count` | Corrections (humans backspace, bots don't) |
| `paste_count` | Paste events (bots paste credentials) |
| `typing_delay_mean` | Average ms between keystrokes |
| `typing_delay_stddev` | Variance — low stddev = robotic typing |
| `click_count` | Total clicks |
| `rapid_clicks` | Clicks < 300ms apart |
| `total_active_ms` | Total session duration |
| `frontend_anomaly_score` | Pre-computed score from React tracker |
