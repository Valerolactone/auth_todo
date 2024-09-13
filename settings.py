from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_host: str = Field(..., env="APP_HOST")
    reset_password_url: str = Field(..., env="RESET_PASSWORD_URL")
    confirm_registration_url: str = Field(..., env="CONFIRM_REGISTRATION_URL")
    drf_url: str = Field(..., env="DRF_URL")

    db_user: str = Field(..., env="DB_USER")
    db_password: str = Field(..., env="DB_PASSWORD")
    db_host: str = Field(..., env="DB_HOST")
    db_port: int = Field(..., env="DB_PORT")
    db_name: str = Field(..., env="DB_NAME")
    test_db_name: str = Field(..., env="TEST_DB_NAME")

    access_token_expiration_minutes: int = Field(
        ..., env="ACCESS_TOKEN_EXPIRATION_MINUTES"
    )
    refresh_token_expiration_days: int = Field(..., env="REFRESH_TOKEN_EXPIRATION_DAYS")
    link_expiration_minutes: int = Field(..., env="LINK_EXPIRATION_MINUTES")

    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(..., env="JWT_ALGORITHM")
    jwt_for_link_secret_key: str = Field(..., env="JWT_FOR_LINK_SECRET_KEY")

    mail_password: str = Field(..., env="MAIL_PASSWORD")
    mail_username: str = Field(..., env="MAIL_USERNAME")
    mail_server: str = Field(..., env="MAIL_SERVER")
    mail_from_name: str = Field(..., env="MAIL_FROM_NAME")
    mail_port: int = Field(..., env="MAIL_PORT")

    debug: bool = Field(False, env="DEBUG")

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
