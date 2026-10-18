"""
generate_dataset.py
Creates a synthetic behavioral dataset for training the phishing detector.

Features (13 total) extracted from user interaction data:
  mouse_point_count, mouse_jitter, avg_mouse_speed,
  keystroke_count, typing_speed_cps, backspace_count, paste_count,
  typing_delay_mean, typing_delay_stddev,
  click_count, rapid_clicks,
  total_active_ms, frontend_anomaly_score

Labels:
  0 = LEGIT
  1 = SUSPICIOUS
  2 = PHISHING
"""

import numpy as np
import pandas as pd

np.random.seed(42)

N_LEGIT      = 2000
N_SUSPICIOUS = 800
N_PHISHING   = 1200


def legit_samples(n):
    return pd.DataFrame({
        # Real users move mouse naturally: many points, moderate speed
        "mouse_point_count":    np.random.randint(150, 800, n),
        "mouse_jitter":         np.random.randint(0, 20, n),
        "avg_mouse_speed":      np.random.uniform(0.5, 3.0, n),

        # Humans type inconsistently: varied delays, normal speed
        "keystroke_count":      np.random.randint(20, 80, n),
        "typing_speed_cps":     np.random.uniform(2.0, 6.0, n),
        "backspace_count":      np.random.randint(0, 10, n),
        "paste_count":          np.zeros(n, dtype=int),        # legit users rarely paste password

        "typing_delay_mean":    np.random.uniform(150, 350, n),
        "typing_delay_stddev":  np.random.uniform(40, 120, n), # high variance = human

        "click_count":          np.random.randint(2, 12, n),
        "rapid_clicks":         np.random.randint(0, 2, n),

        "total_active_ms":      np.random.randint(8000, 60000, n),
        "frontend_anomaly_score": np.random.randint(0, 25, n),

        "label": 0,
    })


def suspicious_samples(n):
    return pd.DataFrame({
        "mouse_point_count":    np.random.randint(30, 200, n),
        "mouse_jitter":         np.random.randint(5, 40, n),
        "avg_mouse_speed":      np.random.uniform(0.1, 5.0, n),

        "keystroke_count":      np.random.randint(10, 60, n),
        "typing_speed_cps":     np.random.uniform(1.0, 10.0, n),
        "backspace_count":      np.random.randint(0, 20, n),
        "paste_count":          np.random.randint(0, 2, n),

        "typing_delay_mean":    np.random.uniform(80, 500, n),
        "typing_delay_stddev":  np.random.uniform(10, 150, n),

        "click_count":          np.random.randint(1, 20, n),
        "rapid_clicks":         np.random.randint(0, 5, n),

        "total_active_ms":      np.random.randint(2000, 30000, n),
        "frontend_anomaly_score": np.random.randint(30, 60, n),

        "label": 1,
    })


def phishing_samples(n):
    """
    Phishing/bot patterns:
    - Very few mouse points OR robotic high-count
    - Uniform typing delay (low stddev) = bot
    - Paste credentials
    - Very fast form submit
    - High anomaly score
    """
    # Mix: 60% automated bots, 40% human phishing (fast, suspicious)
    n_bot   = int(n * 0.6)
    n_human = n - n_bot

    bots = pd.DataFrame({
        "mouse_point_count":    np.random.choice([0, np.random.randint(5, 30)], n_bot),
        "mouse_jitter":         np.random.randint(40, 100, n_bot),
        "avg_mouse_speed":      np.random.uniform(8.0, 25.0, n_bot),  # unnaturally fast

        "keystroke_count":      np.random.randint(0, 20, n_bot),
        "typing_speed_cps":     np.random.uniform(15.0, 50.0, n_bot), # bot speed
        "backspace_count":      np.zeros(n_bot, dtype=int),
        "paste_count":          np.random.randint(1, 4, n_bot),        # bots paste

        "typing_delay_mean":    np.random.uniform(50, 120, n_bot),
        "typing_delay_stddev":  np.random.uniform(0, 15, n_bot),       # very uniform = bot

        "click_count":          np.random.randint(1, 5, n_bot),
        "rapid_clicks":         np.random.randint(3, 15, n_bot),

        "total_active_ms":      np.random.randint(500, 3000, n_bot),   # very fast
        "frontend_anomaly_score": np.random.randint(60, 100, n_bot),

        "label": 2,
    })

    humans = pd.DataFrame({
        "mouse_point_count":    np.random.randint(10, 100, n_human),
        "mouse_jitter":         np.random.randint(15, 60, n_human),
        "avg_mouse_speed":      np.random.uniform(1.0, 6.0, n_human),

        "keystroke_count":      np.random.randint(5, 40, n_human),
        "typing_speed_cps":     np.random.uniform(3.0, 12.0, n_human),
        "backspace_count":      np.random.randint(0, 5, n_human),
        "paste_count":          np.random.randint(1, 3, n_human),      # paste password

        "typing_delay_mean":    np.random.uniform(80, 200, n_human),
        "typing_delay_stddev":  np.random.uniform(5, 40, n_human),

        "click_count":          np.random.randint(1, 8, n_human),
        "rapid_clicks":         np.random.randint(2, 8, n_human),

        "total_active_ms":      np.random.randint(1500, 8000, n_human),
        "frontend_anomaly_score": np.random.randint(55, 90, n_human),

        "label": 2,
    })

    return pd.concat([bots, humans], ignore_index=True)


if __name__ == "__main__":
    df = pd.concat([
        legit_samples(N_LEGIT),
        suspicious_samples(N_SUSPICIOUS),
        phishing_samples(N_PHISHING),
    ], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    df.to_csv("data/behavioral_dataset.csv", index=False)
    print(f"Dataset saved: {len(df)} rows")
    print(df["label"].value_counts().rename({0: "LEGIT", 1: "SUSPICIOUS", 2: "PHISHING"}))
