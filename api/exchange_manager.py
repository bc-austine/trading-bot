# api/exchange_manager.py
import ccxt
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from ..security.encryption import EncryptionService

logger = logging.getLogger(__name__)

class ExchangeManager:
    """Manage multiple exchange connections using CCXT"""
    
    def __init__(self, config: Dict, encryption_service: EncryptionService):
        self.config = config
        self.encryption = encryption_service
        self.exchanges = {}
        self.setup_exchanges()
    
    def setup_exchanges(self) -> None:
        """Initialize all configured exchanges"""
        for exchange_name, exchange_config in self.config['exchanges'].items():
            if exchange_config.get('enabled', False):
                try:
                    # Decrypt API keys
                    api_key = self.encryption.decrypt(exchange_config['apiKey'])
                    secret = self.encryption.decrypt(exchange_config['secret'])
                    
                    # Initialize exchange
                    exchange_class = getattr(ccxt, exchange_name)
                    exchange = exchange_class({
                        'apiKey': api_key,
                        'secret': secret,
                        'timeout': exchange_config.get('timeout', 30000),
                        'enableRateLimit': True,
                        'options': {
                            'adjustForTimeDifference': True,
                            'test': exchange_config.get('testnet', False)
                        }
                    })
                    
                    # Set rate limit if specified
                    if 'rate_limit' in exchange_config:
                        exchange.rateLimit = exchange_config['rate_limit']
                    
                    self.exchanges[exchange_name] = exchange
                    logger.info(f"Initialized {exchange_name} exchange")
                    
                except Exception as e:
                    logger.error(f"Failed to initialize {exchange_name}: {e}")
    
    def get_exchange(self, exchange_name: str) -> Optional[ccxt.Exchange]:
        """Get exchange instance by name"""
        return self.exchanges.get(exchange_name)
    
    def get_balances(self, exchange_name: str) -> Dict:
        """Get account balances for an exchange"""
        exchange = self.get_exchange(exchange_name)
        if not exchange:
            raise ValueError(f"Exchange {exchange_name} not found or not enabled")
        
        try:
            balances = exchange.fetch_balance()
            return {k: v for k, v in balances['total'].items() if v > 0}
        except Exception as e:
            logger.error(f"Error fetching balances from {exchange_name}: {e}")
            raise
    
    def get_ticker(self, exchange_name: str, symbol: str) -> Dict:
        """Get ticker data for a symbol"""
        exchange = self.get_exchange(exchange_name)
        if not exchange:
            raise ValueError(f"Exchange {exchange_name} not found or not enabled")
        
        try:
            return exchange.fetch_ticker(symbol)
        except Exception as e:
            logger.error(f"Error fetching ticker {symbol} from {exchange_name}: {e}")
            raise
    
    def get_ohlcv(self, exchange_name: str, symbol: str, timeframe: str = '1h', limit: int = 100) -> List[List]:
        """Get OHLCV data for a symbol"""
        exchange = self.get_exchange(exchange_name)
        if not exchange:
            raise ValueError(f"Exchange {exchange_name} not found or not enabled")
        
        try:
            return exchange.fetch_ohlcv(symbol, timeframe, limit=limit)
        except Exception as e:
            logger.error(f"Error fetching OHLCV for {symbol} from {exchange_name}: {e}")
            raise