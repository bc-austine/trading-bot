# main.py
import logging
import yaml
import os
import time
from typing import Dict, Any
from dotenv import load_dotenv

from api.exchange_manager import ExchangeManager
from trading.strategy import MeanReversionStrategy, MomentumStrategy
from trading.order_executor import OrderExecutor
from trading.portfolio_manager import PortfolioManager
from security.encryption import EncryptionService
from security.access_control import AccessControl
from security.anomaly_detector import AnomalyDetector
from security.audit_logger import AuditLogger
from utils.logger import setup_logging

class SecureTradingBot:
    """Main application class for the Secure Trading Bot using CCXT"""
    
    def __init__(self, config_path: str = "config/config.yaml", 
                 security_config_path: str = "config/security.yaml"):
        self.config = self._load_config(config_path)
        self.security_config = self._load_config(security_config_path)
        self.setup_logging()
        self.setup_security()
        self.setup_exchanges()
        self.setup_trading()
        self.setup_monitoring()
        self.logger.info("Secure Trading Bot initialized with CCXT")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    
    def setup_logging(self) -> None:
        """Setup application logging"""
        log_level = self.config.get("logging", {}).get("level", "INFO")
        setup_logging(level=log_level)
        self.logger = logging.getLogger(__name__)
    
    def setup_security(self) -> None:
        """Initialize security components"""
        # Encryption service
        encryption_cfg = self.security_config["encryption"]
        self.encryption = EncryptionService(
            password=os.environ["ENCRYPTION_PASSWORD"],
            salt=encryption_cfg.get("salt")
        )
        
        # Access control
        access_cfg = self.security_config["access_control"]
        self.access_control = AccessControl(access_cfg["ip_whitelist"])
        
        # Anomaly detection
        anomaly_cfg = self.security_config["anomaly_detection"]
        self.anomaly_detector = AnomalyDetector(
            trade_volume_threshold=anomaly_cfg["trade_volume_threshold"],
            price_change_threshold=anomaly_cfg["price_change_threshold"],
            time_window=anomaly_cfg["time_window"]
        )
        
        # Audit logging
        audit_cfg = self.security_config["auditing"]
        self.audit_logger = AuditLogger(
            log_trades=audit_cfg["log_trades"],
            log_balance_changes=audit_cfg["log_balance_changes"],
            log_api_calls=audit_cfg["log_api_calls"],
            retention_days=audit_cfg["retention_days"]
        )
    
    def setup_exchanges(self) -> None:
        """Initialize exchange connections"""
        self.exchange_manager = ExchangeManager(self.config, self.encryption)
    
    def setup_trading(self) -> None:
        """Initialize trading components"""
        # Strategies
        self.strategies = {}
        for strategy_cfg in self.config['trading']['strategies']:
            if strategy_cfg['enabled']:
                if strategy_cfg['name'] == 'mean_reversion':
                    self.strategies[strategy_cfg['name']] = MeanReversionStrategy(strategy_cfg['params'])
                elif strategy_cfg['name'] == 'momentum':
                    self.strategies[strategy_cfg['name']] = MomentumStrategy(strategy_cfg['params'])
        
        # Portfolio manager
        self.portfolio = PortfolioManager()
        
        # Order executor
        self.order_executor = OrderExecutor(
            exchange_manager=self.exchange_manager,
            strategies=self.strategies,
            portfolio_manager=self.portfolio,
            config=self.config
        )
    
    def setup_monitoring(self) -> None:
        """Initialize monitoring components"""
        self.check_interval = self.config['monitoring']['check_interval']
        self.profit_alert_threshold = self.config['monitoring']['profit_alert_threshold']
        self.loss_alert_threshold = self.config['monitoring']['loss_alert_threshold']
    
    def run(self) -> None:
        """Main application loop"""
        self.logger.info("Starting Secure Trading Bot with CCXT")
        
        try:
            while True:
                # Check for security anomalies
                if self.anomaly_detector.detect_anomalies():
                    self.logger.warning("Security anomaly detected. Pausing trading.")
                    time.sleep(self.check_interval)
                    continue
                
                # Execute trading for each symbol and exchange
                for exchange_name in self.config['exchanges']:
                    if not self.config['exchanges'][exchange_name]['enabled']:
                        continue
                    
                    for symbol in self.config['trading']['symbols']:
                        for strategy_name in self.strategies:
                            # Execute strategy
                            order = self.order_executor.execute_strategy(
                                exchange_name, symbol, strategy_name
                            )
                            
                            # Log the order if it was executed
                            if order:
                                self.audit_logger.log_trade(order)
                
                # Sleep for a period before next iteration
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Shutting down Secure Trading Bot")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    
    # Initialize and run the bot
    bot = SecureTradingBot()
    bot.run()