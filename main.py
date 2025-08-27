# main.py
import logging
import yaml
import os
import time
import smtplib
import requests
from typing import Dict, Any
from email.mime.text import MIMEText
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
        """Load configuration from YAML file safely"""
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file not found: {config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML config {config_path}: {e}")

    def setup_logging(self) -> None:
        """Setup application logging"""
        log_level = self.config.get("logging", {}).get("level", "INFO")
        setup_logging(level=log_level)
        self.logger = logging.getLogger(__name__)

    def setup_security(self) -> None:
        """Initialize security components"""
        # Encryption service
        encryption_cfg = self.security_config.get("encryption", {})
        password = os.getenv("ENCRYPTION_PASSWORD")
        if not password:
            raise EnvironmentError("ENCRYPTION_PASSWORD not set in environment")
        self.encryption = EncryptionService(
            password=password,
            salt=encryption_cfg.get("salt")
        )

        # Access control
        access_cfg = self.security_config.get("access_control", {})
        self.access_control = AccessControl(access_cfg.get("ip_whitelist", []))

        # Anomaly detection
        anomaly_cfg = self.security_config.get("anomaly_detection", {})
        self.anomaly_detector = AnomalyDetector(
            trade_volume_threshold=anomaly_cfg.get("trade_volume_threshold", 0),
            price_change_threshold=anomaly_cfg.get("price_change_threshold", 0),
            time_window=anomaly_cfg.get("time_window", 60)
        )

        # Audit logging
        audit_cfg = self.security_config.get("auditing", {})
        self.audit_logger = AuditLogger(
            log_trades=audit_cfg.get("log_trades", True),
            log_balance_changes=audit_cfg.get("log_balance_changes", True),
            log_api_calls=audit_cfg.get("log_api_calls", True),
            retention_days=audit_cfg.get("retention_days", 30)
        )

    def setup_exchanges(self) -> None:
        """Initialize exchange connections"""
        self.exchange_manager = ExchangeManager(self.config, self.encryption)

    def setup_trading(self) -> None:
        """Initialize trading components"""
        # Strategies
        self.strategies = {}
        for strategy_cfg in self.config.get("trading", {}).get("strategies", []):
            if strategy_cfg.get("enabled", False):
                if strategy_cfg["name"] == "mean_reversion":
                    self.strategies[strategy_cfg["name"]] = MeanReversionStrategy(strategy_cfg["params"])
                elif strategy_cfg["name"] == "momentum":
                    self.strategies[strategy_cfg["name"]] = MomentumStrategy(strategy_cfg["params"])

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
        monitoring_cfg = self.config.get("monitoring", {})
        self.check_interval = monitoring_cfg.get("check_interval", 30)
        self.profit_alert_threshold = monitoring_cfg.get("profit_alert_threshold", 0.05)
        self.loss_alert_threshold = monitoring_cfg.get("loss_alert_threshold", -0.05)

        # Alerting config
        self.alert_cfg = monitoring_cfg.get("alerts", {})
        self.alert_email = self.alert_cfg.get("email")
        self.alert_slack = self.alert_cfg.get("slack_webhook")

    # -----------------------------
    # ALERTING SYSTEM
    # -----------------------------
    def send_email_alert(self, subject: str, message: str) -> None:
        """Send email alerts using SMTP"""
        try:
            smtp_server = os.getenv("SMTP_SERVER")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_user = os.getenv("SMTP_USER")
            smtp_pass = os.getenv("SMTP_PASS")
            recipient = self.alert_email

            if not all([smtp_server, smtp_user, smtp_pass, recipient]):
                self.logger.warning("Email alert skipped: SMTP credentials or recipient not configured")
                return

            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = smtp_user
            msg["To"] = recipient

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, recipient, msg.as_string())

            self.logger.info(f"Email alert sent to {recipient}")

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def send_slack_alert(self, message: str) -> None:
        """Send Slack alerts using Incoming Webhook"""
        try:
            webhook_url = self.alert_slack
            if not webhook_url:
                self.logger.warning("Slack alert skipped: No webhook URL configured")
                return

            response = requests.post(webhook_url, json={"text": message})
            if response.status_code != 200:
                self.logger.error(f"Slack alert failed: {response.text}")
            else:
                self.logger.info("Slack alert sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")

    def send_security_alert(self, message: str) -> None:
        """Send security alerts to configured channels"""
        subject = "🚨 SecureTradingBot Alert"
        self.logger.warning(f"SECURITY ALERT: {message}")

        if self.alert_email:
            self.send_email_alert(subject, message)

        if self.alert_slack:
            self.send_slack_alert(message)

    # -----------------------------
    # MAIN LOOP
    # -----------------------------
    def run(self) -> None:
        """Main application loop"""
        self.logger.info("Starting Secure Trading Bot with CCXT")

        try:
            while True:
                # Check for security anomalies
                if self.anomaly_detector.detect_anomalies():
                    self.logger.warning("Security anomaly detected. Pausing trading.")
                    self.audit_logger.log_event("anomaly_detected", {"message": "Trading paused"})
                    self.send_security_alert("Anomaly detected. Trading paused.")
                    time.sleep(self.check_interval)
                    continue

                # Execute trading for each symbol and exchange
                for exchange_name, ex_cfg in self.config.get("exchanges", {}).items():
                    if not ex_cfg.get("enabled", False):
                        continue

                    for symbol in self.config.get("trading", {}).get("symbols", []):
                        for strategy_name in self.strategies:
                            try:
                                # Execute strategy
                                order = self.order_executor.execute_strategy(
                                    exchange_name, symbol, strategy_name
                                )

                                # Log the order if it was executed
                                if order:
                                    self.audit_logger.log_trade(order)

                            except Exception as e:
                                self.logger.error(f"Error executing {strategy_name} on {symbol} ({exchange_name}): {e}")
                                self.audit_logger.log_event("strategy_error", {
                                    "exchange": exchange_name,
                                    "symbol": symbol,
                                    "strategy": strategy_name,
                                    "error": str(e)
                                })
                                continue

                # Sleep for a period before next iteration
                time.sleep(self.check_interval)

        except KeyboardInterrupt:
            self.logger.info("Shutting down Secure Trading Bot")
        except Exception as e:
            self.logger.exception("Unexpected critical error in main loop")
            self.audit_logger.log_event("critical_error", {"error": str(e)})
            self.send_security_alert(f"Critical error in bot: {e}")
            raise


if __name__ == "__main__":
    # Load environment variables
    load_dotenv()

    # Initialize and run the bot
    bot = SecureTradingBot()
    bot.run()
