"""
配置檔案 - 管理所有設定參數
"""
import os, random
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()  # 載入 .env 檔案

# 解析多組 VirusTotal API Key
def _parse_vt_multi(raw: str) -> List[str]:
    keys = []
    for part in raw.split(','):
        p = part.strip()
        if p:
            keys.append(p)
    # 去重保持順序
    seen = set()
    ordered = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered

# 指數backoff + full jitter
def _backoff_delay(attempt: int, base: float = 0.5, cap: float = 3.0) -> float:

    upper = min(cap, base * (2 ** attempt))
    return random.uniform(0.0, upper)

@dataclass
class Config:
    """應用程式配置（最小修改：支援多組 VirusTotal API Key）"""
    # API Keys
    SHODAN_API_KEY: str = os.getenv('SHODAN_API_KEY', '')
    OTX_API_KEY: str = os.getenv('OTX_API_KEY', '')
    MERKLEMAP_API_TOKEN: str = os.getenv('MERKLEMAP_API_TOKEN', '')

    # 憑證透明度資料來源
    CT_PROVIDER: str = os.getenv('CT_PROVIDER', 'crtsh').strip().lower()
    MERKLEMAP_REQUEST_DELAY: float = float(os.getenv('MERKLEMAP_REQUEST_DELAY', '0.25'))
    MERKLEMAP_MAX_RETRIES: int = int(os.getenv('MERKLEMAP_MAX_RETRIES', '3'))
    # 0 表示完整讀取所有分頁
    MERKLEMAP_MAX_PAGES: int = int(os.getenv('MERKLEMAP_MAX_PAGES', '0'))

    # 舊的單一 VT 變數（向下相容）
    VIRUSTOTAL_API_KEY: str = os.getenv('VIRUSTOTAL_API_KEY', '')
    # 新的多組 VT 變數（逗號分隔）
    _VIRUSTOTAL_API_KEYS_RAW: str = os.getenv('VIRUSTOTAL_API_KEYS', '')
    # 解析後的列表
    VIRUSTOTAL_API_KEYS: List[str] = field(default_factory=list)

    # DNS SERVER 設定
    DNS_SERVERS: List[str] = field(default_factory=lambda: os.getenv('DNS_SERVERS', '').split(','))

    # 資料庫設定
    DATABASE_PATH: str = 'website.db'
    
    # 網路設定
    REQUEST_TIMEOUT: int = 10
    REQUEST_DELAY: float = 1.0
    VT_API_DELAY: float = 2.0

    VALIDATOR_MAX_WORKERS: int = 16          # 驗證階段同時併發數
    CONNECT_TIMEOUT: float = 5.0             # TCP 連線逾時（秒）
    READ_TIMEOUT: float = 30.0               # 回應讀取逾時（秒）
    HTTP_POOL_SIZE: int = 64                 # 連線池大小（每執行緒）
    HTTP_RETRIES: int = 2                    # 臨時錯誤重試次數
    # OTX 相關重試設定
    OTX_MAX_RETRIES: int = int(os.getenv('OTX_MAX_RETRIES', '5'))   # 單一目標失敗後最多再試幾次
    
    # User Agent
    USER_AGENT: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    # 搜尋設定
    DEFAULT_COUNTRY: str = 'TW'
    DEFAULT_PORT: str = '443'

    # 資料匯入
    CITY_DOMAIN_CSV_PATH: str = os.getenv('CITY_DOMAIN_CSV_PATH', 'domain_of_city.csv')
    
    @classmethod
    def from_env(cls) -> 'Config':
        cfg = cls()
        if cfg._VIRUSTOTAL_API_KEYS_RAW:
            cfg.VIRUSTOTAL_API_KEYS = _parse_vt_multi(cfg._VIRUSTOTAL_API_KEYS_RAW)
        elif cfg.VIRUSTOTAL_API_KEY:
            cfg.VIRUSTOTAL_API_KEYS = [cfg.VIRUSTOTAL_API_KEY]
        else:
            cfg.VIRUSTOTAL_API_KEYS = []
        return cfg

    @property
    def PRIMARY_VT_KEY(self) -> str:
        return self.VIRUSTOTAL_API_KEYS[0] if self.VIRUSTOTAL_API_KEYS else ''
    
    def validate(self) -> bool:
        """驗證配置是否有效"""
        if not self.SHODAN_API_KEY:
            raise ValueError("SHODAN_API_KEY 未設定")
        if not self.VIRUSTOTAL_API_KEYS:
            raise ValueError("VIRUSTOTAL_API_KEY 或 VIRUSTOTAL_API_KEYS 未設定")
        if self.CT_PROVIDER not in {"crtsh", "merklemap"}:
            raise ValueError("CT_PROVIDER 必須是 crtsh 或 merklemap")
        if self.CT_PROVIDER == "merklemap" and not self.MERKLEMAP_API_TOKEN:
            raise ValueError("CT_PROVIDER=merklemap 時必須設定 MERKLEMAP_API_TOKEN")
        if self.MERKLEMAP_MAX_RETRIES < 1:
            raise ValueError("MERKLEMAP_MAX_RETRIES 必須大於等於 1")
        if self.MERKLEMAP_MAX_PAGES < 0:
            raise ValueError("MERKLEMAP_MAX_PAGES 不可小於 0")
        # OTX 可選，允許空
        return True
