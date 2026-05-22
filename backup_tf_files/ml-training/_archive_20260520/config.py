"""Configuration for WAF ML training pipeline."""
from dataclasses import dataclass, field


@dataclass
class TrainingConfig:
    test_size: float = 0.15
    val_size: float = 0.15
    random_state: int = 42

    # XGBoost
    xgb_params: dict = field(default_factory=lambda: {
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "gamma": 0.1,
        "reg_alpha": 0.1,
        "reg_lambda": 1.0,
        "eval_metric": "logloss",
    })

    # Gradient Boosting
    gbm_params: dict = field(default_factory=lambda: {
        "n_estimators": 300,
        "max_depth": 5,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "min_samples_split": 10,
        "min_samples_leaf": 5,
        "max_features": "sqrt",
    })

    # Logistic Regression (baseline)
    lr_params: dict = field(default_factory=lambda: {
        "C": 1.0,
        "max_iter": 1000,
        "solver": "lbfgs",
    })


@dataclass
class EvalConfig:
    malicious_block_weight: float = 2.0
    false_positive_penalty: float = 1.5
    attack_categories: list = field(default_factory=lambda: [
        "xss", "sqli", "lfi", "rfi", "ssti", "cmdi", "log4j", "size_evasion",
    ])
