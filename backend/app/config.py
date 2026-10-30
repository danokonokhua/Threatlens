from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    ELASTICSEARCH_URL: str
    ENVIRONMENT: str = "local"
    SECRET_KEY: str = "super_secret_local_key_change_in_prod"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 43200  # 30 days default for dev/demo

    class Config:
        env_file = ".env"

settings = Settings()