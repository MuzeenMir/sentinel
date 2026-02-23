# SENTINEL Training Pipeline

Train all detection models (XGBoost, LSTM, Isolation Forest, Autoencoder, Ensemble, DRL PPO) on real-world cybersecurity datasets using an AWS EC2 instance.

## Quick Start

```bash
# From sentinel-core/

# 1. AWS prerequisites (local machine)
bash training/aws-setup.sh

# 2. Launch cheap EC2 instance
bash training/ec2-provision.sh

# 3. SSH into instance
ssh -i sentinel-training.pem ubuntu@<IP>

# 4. Set up environment (on EC2)
bash sentinel-core/training/ec2-setup.sh

# 5. Download datasets (on EC2)
bash sentinel-core/training/download_datasets.sh

# 6. Upgrade to GPU (from local machine) -- see ec2-provision.sh upgrade section
#    Stop -> change type to g4dn.2xlarge -> start -> SSH back in

# 6b. (Optional) Add 48GB swap to avoid OOM during full-dataset training
sudo bash sentinel-core/training/ec2-add-swap.sh

# 7. Train all models (on EC2)
cd ~/sentinel/sentinel-core
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018 \
    --device cuda \
    --output-path backend/ai-engine/trained_models
```

## Datasets

| Dataset | Size | Source | Download |
|---------|------|--------|----------|
| CSE-CIC-IDS2018 | ~8 GB | AWS Open Data | `aws s3 sync s3://cse-cic-ids2018/ ...` (free in us-east-1) |
| CIC-IDS2017 | ~6.5 GB | UNB | [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) |
| UNSW-NB15 | ~2 GB | UNSW Canberra | [Kaggle](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15) |

Place datasets under `training/datasets/data/`:

```
training/datasets/data/
  cicids2018/       # CSV files from CIC-IDS2018
  cicids2017/       # CSV files from CIC-IDS2017
  unsw_nb15/        # CSV files from UNSW-NB15
```

Run `bash training/download_datasets.sh` to download automatically.

## Training Commands

```bash
# Train all models on CIC-IDS2018 with GPU
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018 \
    --device cuda

# Train specific models only (no retraining of others; never use --force)
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018 \
    --models autoencoder lstm \
    --device cuda

# Train only missing/failed models (e.g. after some failed: --models autoencoder lstm)
# Do NOT use --force; that retrains everything and costs time/money.

# Quick test run (limited rows, CPU)
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018 \
    --max-rows 5000 \
    --device cpu

# Train on multiple datasets
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018,cicids2017,unsw_nb15 \
    --device cuda

# Force retrain (ignore checkpoint)
python training/train_all.py \
    --data-path training/datasets/data \
    --dataset cicids2018 \
    --device cuda \
    --force
```

## Models

| Model | Type | Framework | Device | Purpose |
|-------|------|-----------|--------|---------|
| XGBoost | Supervised | xgboost | CPU/GPU | Multi-class threat classification |
| LSTM | Supervised | PyTorch | CPU/GPU | Temporal sequence attack detection |
| Isolation Forest | Unsupervised | scikit-learn | CPU | Zero-day anomaly detection |
| Autoencoder | Unsupervised | PyTorch | CPU/GPU | Reconstruction-based anomaly detection |
| Ensemble | Meta-learner | scikit-learn | CPU | Combines all detector outputs |
| DRL PPO | Reinforcement | Stable-Baselines3 | CPU/GPU | Automated firewall policy decisions |

Trained models are saved to `backend/ai-engine/trained_models/`:

```
backend/ai-engine/trained_models/
  xgboost/            # xgboost_model.json + xgboost_meta.json
  lstm/               # lstm_model.pt + lstm_config.json
  isolation_forest/   # isolation_forest.joblib + scaler + meta
  autoencoder/        # autoencoder.pt + autoencoder_config.json
  ensemble/           # ensemble_config.json + meta_learner.joblib
  drl/                # ppo_firewall.zip + drl_meta.json
  training_report.json
```

## EC2 Instance Strategy

| Phase | Instance | Specs | Cost |
|-------|----------|-------|------|
| Setup + Download | `t3.medium` | 2 vCPU, 4 GB RAM | ~$0.042/hr |
| Training | `g4dn.2xlarge` | 8 vCPU, 32 GB RAM, T4 GPU | ~$0.75/hr |
| Training (more RAM) | `g4dn.4xlarge` | 16 vCPU, 64 GB RAM, T4 GPU | ~$1.20/hr |

**Note:** Default GPU choice is `g4dn.2xlarge` (8 vCPU). If your AWS account has an 8 vCPU limit for G/VT instances, use only `g4dn.2xlarge`; `g4dn.4xlarge` requires a quota increase.

Storage: 150 GB gp3 EBS.

### Upgrade / Downgrade

```bash
INSTANCE_ID=$(cat .sentinel-instance-id)

# Stop
aws ec2 stop-instances --instance-ids "$INSTANCE_ID"
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID"

# Change type
aws ec2 modify-instance-attribute \
    --instance-id "$INSTANCE_ID" \
    --instance-type '{"Value": "g4dn.2xlarge"}'

# Start
aws ec2 start-instances --instance-ids "$INSTANCE_ID"
```

## Checkpointing and Spot Interruptions

The training pipeline automatically:

- Saves a checkpoint after each model completes
- Monitors the EC2 Spot interruption metadata endpoint
- On interruption (2-min warning), saves current state and exits cleanly
- On resume, skips already-completed models (use `--force` to retrain)

Checkpoint file: `backend/ai-engine/trained_models/.training_checkpoint.json`

## Retrieving Trained Models

After training, copy models back to your local machine:

```bash
# From local machine
scp -i sentinel-training.pem -r \
    ubuntu@<IP>:~/sentinel/sentinel-core/backend/ai-engine/trained_models/ \
    ./backend/ai-engine/trained_models/
```

Or push to S3:

```bash
# From EC2
aws s3 sync backend/ai-engine/trained_models/ \
    s3://your-bucket/sentinel-models/ \
    --exclude ".training_checkpoint.json"
```

## Files

| File | Purpose |
|------|---------|
| `aws-setup.sh` | Install AWS CLI, configure credentials, create key pair + security group |
| `ec2-provision.sh` | Launch EC2 instance, print SSH command, upgrade instructions |
| `ec2-setup.sh` | On-instance: system deps, Python 3.12, CUDA, venv, pip packages |
| `ec2-add-swap.sh` | On-instance: add 48GB swap (run once: `sudo bash training/ec2-add-swap.sh`) |
| `download_datasets.sh` | Download CIC-IDS2018, CIC-IDS2017, UNSW-NB15 |
| `train_all.py` | Main training orchestrator with checkpointing |
| `data_loader.py` | Dataset loading, label mapping, preprocessing |
| `spot_handler.py` | Spot Instance interruption detection |
| `requirements.txt` | Combined Python dependencies |
