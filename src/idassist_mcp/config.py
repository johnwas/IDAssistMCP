"""
Configuration management for IDAssistMCP

This module provides configuration management using Pydantic settings
with environment variable support (IDASSISTMCP_ prefix).
"""

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings

from .logging import log


class TransportType(str, Enum):
    """Available transport types for the MCP server"""
    SSE = "sse"
    STREAMABLEHTTP = "streamablehttp"


class LogLevel(str, Enum):
    """Available logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ServerConfig(BaseModel):
    """Server-specific configuration"""
    host: str = Field(default="localhost", description="Server host address")
    port: int = Field(default=9080, ge=1024, le=65535, description="Server port")
    transport: TransportType = Field(default=TransportType.STREAMABLEHTTP, description="Transport type (SSE or Streamable HTTP)")
    max_connections: int = Field(default=100, ge=1, description="Maximum concurrent connections")

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("Host must be a non-empty string")
        return v.strip()


class AnalysisConfig(BaseModel):
    """IDA analysis configuration"""
    auto_analysis_wait: bool = Field(default=True, description="Wait for IDA auto-analysis to complete")
    analysis_timeout: int = Field(default=300, ge=30, description="Analysis timeout in seconds")
    cache_results: bool = Field(default=True, description="Cache analysis results")


class PluginConfig(BaseModel):
    """IDA plugin configuration"""
    auto_startup: bool = Field(default=False, description="Auto-start server on plugin load")
    show_notifications: bool = Field(default=True, description="Show status notifications in IDA output")
    menu_integration: bool = Field(default=True, description="Enable menu integration")


class IDAssistMCPConfig(BaseSettings):
    """Main configuration class for IDAssistMCP"""

    # Core settings
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Server configuration
    server: ServerConfig = Field(default_factory=ServerConfig)

    # Analysis configuration
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)

    # Plugin configuration
    plugin: PluginConfig = Field(default_factory=PluginConfig)

    model_config = ConfigDict(
        env_prefix="IDASSISTMCP_",
        env_nested_delimiter="__",
        case_sensitive=False
    )

    def get_server_url(self) -> str:
        """Get the server URL"""
        return f"http://{self.server.host}:{self.server.port}"

    def get_sse_url(self) -> str:
        """Get the SSE endpoint URL"""
        return f"{self.get_server_url()}/sse"

    def get_streamablehttp_url(self) -> str:
        """Get the Streamable HTTP endpoint URL"""
        return f"{self.get_server_url()}/mcp"

    def is_transport_enabled(self, transport: TransportType) -> bool:
        """Check if a specific transport is enabled"""
        return self.server.transport == transport

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors"""
        errors = []

        if self.server.port < 1024 or self.server.port > 65535:
            errors.append("Server port must be between 1024 and 65535")

        if not self.server.host.strip():
            errors.append("Server host cannot be empty")

        if self.analysis.analysis_timeout < 30:
            errors.append("Analysis timeout must be at least 30 seconds")

        return errors


def create_default_config() -> IDAssistMCPConfig:
    """Create a default configuration instance"""
    return IDAssistMCPConfig()


def load_config_from_file(config_path: Optional[Path] = None) -> IDAssistMCPConfig:
    """Load configuration from file"""
    if config_path and config_path.exists():
        try:
            import json
            with open(config_path) as f:
                config_data = json.load(f)
            return IDAssistMCPConfig(**config_data)
        except Exception as e:
            log.log_error(f"Failed to load config from {config_path}: {e}")

    return create_default_config()
