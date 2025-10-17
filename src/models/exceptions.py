from typing import Any, Dict, Optional

class SWMapException(Exception):
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        context_str = f" - Context: {self.context}" if self.context else ""
        return f"{self.__class__.__name__}: {self.message}{context_str}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, context={self.context!r})"


class NetworkException(SWMapException):
    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if url:
            ctx["url"] = url
        if status_code is not None:
            ctx["status_code"] = status_code
        super().__init__(message, ctx)


class SecurityException(SWMapException):
    def __init__(
        self,
        message: str,
        security_control: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if security_control:
            ctx["security_control"] = security_control
        super().__init__(message, ctx)


class ValidationException(SWMapException):
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if field:
            ctx["field"] = field
        if value is not None:
            ctx["value"] = value
        super().__init__(message, ctx)


class AnalysisException(SWMapException):
    def __init__(
        self,
        message: str,
        analysis_type: Optional[str] = None,
        content_sample: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if analysis_type:
            ctx["analysis_type"] = analysis_type
        if content_sample:
            ctx["content_sample"] = content_sample[:100]
        super().__init__(message, ctx)


class ConfigurationException(SWMapException):

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if config_key:
            ctx["config_key"] = config_key
        if config_value is not None:
            ctx["config_value"] = config_value
        super().__init__(message, ctx)


class OutputException(SWMapException):
    def __init__(
        self,
        message: str,
        output_format: Optional[str] = None,
        data_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        ctx = dict(context or {})
        if output_format:
            ctx["output_format"] = output_format
        if data_type:
            ctx["data_type"] = data_type
        super().__init__(message, ctx)


class URLValidationException(ValidationException):
    """URL validation failed"""
    pass


class ContentSizeException(SecurityException):
    """Content size exceeds limits"""
    pass


class PatternExtractionException(AnalysisException):
    """Pattern extraction failed"""
    pass


class RiskCalculationException(AnalysisException):
    """Risk calculation failed"""
    pass


class ScopeCalculationException(AnalysisException):
    """Scope calculation failed"""
    pass
