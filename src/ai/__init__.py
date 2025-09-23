"""
NEXUS AI Module - Machine Learning based threat detection and analysis
"""

from .config import MLConfig
from .features import FeatureExtractor
from .detectors import MLDetector, AnomalyDetector
from .embeddings import EmbeddingManager
from .training import ModelTrainer
from .data_processor import DataProcessor

__all__ = [
    'MLConfig',
    'FeatureExtractor', 
    'MLDetector',
    'AnomalyDetector',
    'EmbeddingManager',
    'ModelTrainer',
    'DataProcessor'
]

__version__ = "1.0.0"
