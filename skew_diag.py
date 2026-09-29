#!/usr/bin/env python3
"""Reproduce training-time feature extraction on samples of the training corpus
vs the live feed, and report per-column variance so we can see which features
collapse to zero-variance in training (the skew that wrecks the retrained model)."""
import sys, json, itertools
import numpy as np
import yaml

sys.path.insert(0, "/root/NEW_DRIVE/aditya_ueba")
from ueba_preprocessor import FeatureExtractor

CFG = "/root/NEW_DRIVE/aditya_ueba/ueba_config.yaml"
TRAIN = "/data/ueba_training/combined_training.jsonl"
LIVE = "/root/NEW_DRIVE/aditya_ueba/enriched.jsonl"
N = 40000

with open(CFG) as f:
    config = yaml.safe_load(f)

# Training worker path uses profile_store=None (see preprocessor line 889).
fx = FeatureExtractor(config, profile_store=None)

def sample_matrix(path, n):
    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in itertools.islice(f, n):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            try:
                rows.append(fx.extract(d))
            except Exception:
                continue
    return np.array(rows, dtype=np.float64) if rows else np.zeros((0, 35))

def tail_matrix(path, n):
    # Read last n lines for the live feed (freshest events).
    import collections
    dq = collections.deque(maxlen=n)
    with open(path, "r", errors="ignore") as f:
        for line in f:
            dq.append(line)
    rows = []
    for line in dq:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line); rows.append(fx.extract(d))
        except Exception:
            continue
    return np.array(rows, dtype=np.float64) if rows else np.zeros((0, 35))

Xtr = sample_matrix(TRAIN, N)
Xlv = tail_matrix(LIVE, N)
print(f"train rows={len(Xtr)}  live rows={len(Xlv)}")

names = {
 0:"hour",1:"dow",2:"is_weekend",3:"is_business_hours",4:"is_night",
 5:"is_auth_event",6:"is_network_event",7:"is_file_event",8:"is_process_event",
 9:"is_brute_force",10:"is_port_scan",11:"is_tor",12:"is_malicious_ip",
 13:"is_impossible_travel",14:"is_lateral_movement",15:"is_data_exfil",
 16:"is_after_hours",17:"is_high_frequency",18:"src_ip_5m",19:"src_ip_1h",
 20:"user_1h",21:"host_1h",22:"uniq_dst_1h",23:"uniq_ports_1h",
 24:"recent_failures_5m",25:"geo_distance",26:"cross_border",27:"cross_continent",
 28:"risk_score",29:"rule_level",30:"is_cloud",31:"event_category",
 32:"event_outcome",33:"traffic_direction",34:"baseline_deviation"}

print(f"\n{'idx':>3} {'name':<20} {'train_std':>12} {'train_mean':>12} {'live_std':>12} {'live_mean':>12}  flag")
for i in range(35):
    ts = Xtr[:, i].std() if len(Xtr) else 0.0
    tm = Xtr[:, i].mean() if len(Xtr) else 0.0
    ls = Xlv[:, i].std() if len(Xlv) else 0.0
    lm = Xlv[:, i].mean() if len(Xlv) else 0.0
    flag = ""
    if ts < 1e-9 and ls >= 1e-9:
        flag = "<<< SKEW (const in train, varies live)"
    elif ts < 1e-9:
        flag = "(const both)"
    print(f"{i:>3} {names[i]:<20} {ts:>12.5f} {tm:>12.5f} {ls:>12.5f} {lm:>12.5f}  {flag}")
