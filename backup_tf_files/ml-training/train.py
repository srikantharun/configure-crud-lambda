"""Model training for WAF policy quality prediction."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from xgboost import XGBClassifier

from config import TrainingConfig
from features import get_feature_columns


def split_data(
    df: pd.DataFrame,
    target_col: str = "is_blocked",
    config: TrainingConfig = TrainingConfig(),
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split data into train/val/test sets.

    Returns (train_df, val_df, test_df) with features + target intact.
    """
    # First split: train+val vs test
    train_val, test = train_test_split(
        df,
        test_size=config.test_size,
        random_state=config.random_state,
        stratify=df[target_col] if df[target_col].nunique() > 1 else None,
    )

    # Second split: train vs val
    val_ratio = config.val_size / (1 - config.test_size)
    train, val = train_test_split(
        train_val,
        test_size=val_ratio,
        random_state=config.random_state,
        stratify=train_val[target_col] if train_val[target_col].nunique() > 1 else None,
    )

    print(f"Data split: train={len(train)}, val={len(val)}, test={len(test)}")
    return train, val, test


def get_xy(df: pd.DataFrame, feature_cols: list[str], target_col: str = "is_blocked"):
    """Extract X (features) and y (target) from DataFrame."""
    X = df[feature_cols].fillna(0).values
    y = df[target_col].values
    return X, y


def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    config: TrainingConfig = TrainingConfig(),
) -> XGBClassifier:
    """Train XGBoost classifier."""
    model = XGBClassifier(
        **config.xgb_params,
        random_state=config.random_state,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    print(f"XGBoost trained: {model.n_estimators} estimators, best iteration: {model.best_iteration}")
    return model


def train_gbm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    config: TrainingConfig = TrainingConfig(),
) -> GradientBoostingClassifier:
    """Train Gradient Boosting classifier."""
    model = GradientBoostingClassifier(
        **config.gbm_params,
        random_state=config.random_state,
    )

    model.fit(X_train, y_train)

    print(f"GBM trained: {model.n_estimators} estimators")
    return model


def train_logistic_regression(
    X_train: np.ndarray,
    y_train: np.ndarray,
    config: TrainingConfig = TrainingConfig(),
) -> LogisticRegression:
    """Train Logistic Regression baseline."""
    model = LogisticRegression(
        **config.lr_params,
        random_state=config.random_state,
    )

    model.fit(X_train, y_train)

    print("Logistic Regression baseline trained")
    return model


def train_all_models(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: list[str],
    target_col: str = "is_blocked",
    config: TrainingConfig = TrainingConfig(),
) -> dict:
    """
    Train all three models and return them.

    Returns dict of {model_name: model}.
    """
    X_train, y_train = get_xy(train_df, feature_cols, target_col)
    X_val, y_val = get_xy(val_df, feature_cols, target_col)

    print(f"\nTraining on {len(X_train)} samples, validating on {len(X_val)} samples")
    print(f"Target distribution (train): blocked={y_train.sum()}, allowed={len(y_train) - y_train.sum()}")

    models = {}

    # 1. XGBoost
    print("\n--- XGBoost ---")
    models["xgboost"] = train_xgboost(X_train, y_train, X_val, y_val, config)

    # 2. Gradient Boosting
    print("\n--- Gradient Boosting ---")
    models["gbm"] = train_gbm(X_train, y_train, config)

    # 3. Logistic Regression (baseline)
    print("\n--- Logistic Regression (baseline) ---")
    models["logistic_regression"] = train_logistic_regression(X_train, y_train, config)

    return models


def get_feature_importance(model, feature_cols: list[str]) -> pd.DataFrame:
    """Extract feature importance from a trained model."""
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = np.abs(model.coef_[0])
    else:
        return pd.DataFrame()

    fi = pd.DataFrame({
        "feature": feature_cols,
        "importance": importances,
    }).sort_values("importance", ascending=False)

    return fi
