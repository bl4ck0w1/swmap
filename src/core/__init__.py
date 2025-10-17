__version__ = "1.0.0"
__author__ = "SWMap Security"
__description__ = "Service Worker Security Analyzer"

from .scanner import SWScanner
from .fetcher import AdvancedFetcher
from .parser import SWParser
from .analyzer import SWAnalyzer
from .security_analyzer import SecurityAnalyzer
from .risk_assessor import RiskAssessor
from .normalizer import URLNormalizer

__all__ = [
    'SWScanner',
    'AdvancedFetcher', 
    'SWParser',
    'SWAnalyzer',
    'SecurityAnalyzer',
    'RiskAssessor',
    'URLNormalizer'
]