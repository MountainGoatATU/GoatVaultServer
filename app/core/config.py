from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DOMAIN: str = "localhost"
    PROJECT_NAME: str = "GoatVaultServer"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "local"
    BACKEND_CORS_ORIGINS: str = "http://localhost"
    SECRET_KEY: str = "local_dev"
    SUPABASE_URL: str
    SUPABASE_KEY: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()  # type: ignore[call-arg]
