# Model Evaluation

Two XGBoost classifiers were evaluated using the same seven network-flow features:

- Destination port
- Protocol
- Flow duration
- Flow bytes per second
- Flow packets per second
- Total forward packets
- Total backward packets

The main experiment compared a naturally distributed sample with a deliberately balanced sample.

## Results

| Metric | Natural distribution | Balanced sampling |
|---|---:|---:|
| Training accuracy | 0.9756 | 0.8411 |
| Test accuracy | 0.9754 | 0.8406 |
| Macro F1 | 0.61 | 0.79 |
| Weighted F1 | 0.97 | 0.82 |

## Interpretation

The natural-distribution model produced higher overall accuracy because benign and common classes dominated the dataset. Its macro F1 was much lower than its weighted F1, showing that performance was uneven across classes.

The balanced model reduced overall accuracy but improved macro F1. That tradeoff is important in security analytics because rare attacks may matter more than the most frequent class.

## Aggregated benign-versus-attack matrices

### Natural distribution

| Actual / Predicted | Benign | Attack |
|---|---:|---:|
| Benign | 174,396 | 856 |
| Attack | 1,584 | 23,164 |

### Balanced sampling

| Actual / Predicted | Benign | Attack |
|---|---:|---:|
| Benign | 97,452 | 2,548 |
| Attack | 23,739 | 214,579 |

These binary matrices aggregate the multiclass results into `Benign` and `Attack` for easier operational interpretation.

## Important limitations

- The dataset is highly imbalanced.
- Some classes contain very few examples.
- A class can show high scores in one split and fail to generalize.
- Accuracy should not be used by itself to justify automated blocking.
- The model was evaluated in an educational environment and was not validated against live campus or enterprise traffic.
- Additional validation should include cross-validation, temporal splits, probability calibration, drift monitoring, and false-positive cost analysis.

## Notebook files

- [`natural_sampling_xgboost.ipynb`](../notebooks/natural_sampling_xgboost.ipynb)
- [`balanced_sampling_xgboost.ipynb`](../notebooks/balanced_sampling_xgboost.ipynb)

The notebooks are cleaned versions of the project experiments. Environment-specific bucket names and generated outputs were removed before publication.
