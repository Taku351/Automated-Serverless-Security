# Model Artifacts

The Streamlit dashboard expects these local files:

```text
xgboost_natural.pkl
xgboost_balanced.pkl
label_encoder.pkl
```

They are intentionally not committed.

## Why the binaries are excluded

- Pickle and joblib files are not human-reviewable.
- Loading an untrusted pickle can execute arbitrary code.
- Model binaries can be incompatible across Python, scikit-learn, joblib, or XGBoost versions.
- The label encoder must match the class ordering used during model training.
- The notebooks can regenerate the artifacts from authorized source data.

## Safe use

1. Generate the files yourself by running the notebooks.
2. Keep the model and label encoder from the same training run.
3. Record package versions and file checksums.
4. Never load a model downloaded from an unknown source.
5. Store production models in a controlled model registry or protected S3 location.

The repository `.gitignore` excludes `*.pkl`, `*.joblib`, and the contents of this directory except for this README.
