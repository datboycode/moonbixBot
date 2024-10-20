from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    API_ID: int
    API_HASH: str

    USE_REF: bool = True
    REF_ID: str = 'ref_6110684070'

    ENABLE_AUTO_TASKS: bool = True
    ENABLE_AUTO_PLAY_GAMES: bool = True

    USE_RANDOM_DELAY_IN_RUN: bool = True
    RANDOM_DELAY_IN_RUN: list[int] = [5, 40] #Increase the delay if you have lots of sessions

    RANDOM_DELAY_BETWEEN_CYCLES: list[int] = [15, 25, 40, 60] 
    
    MORE_ACCURATE_CAPTCHA_SOLVER: bool = True

    USE_PROXY_FROM_FILE: bool = False


settings = Settings()
