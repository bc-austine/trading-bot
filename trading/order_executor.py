# trading/order_executor.py
import logging
from typing import Dict, List, Optional, Tuple
from ..api.exchange_manager import ExchangeManager
from .strategy import TradingStrategy
from .portfolio_manager import PortfolioManager

logger = logging.getLogger(__name__)

class OrderExecutor:
    """Execute trades based on strategy signals"""
    
    def __init__(self, exchange_manager: ExchangeManager, 
                 strategies: Dict[str, TradingStrategy],
                 portfolio_manager: PortfolioManager,
                 config: Dict):
        self.exchange_manager = exchange_manager
        self.strategies = strategies
        self.portfolio = portfolio_manager
        self.config = config
        self.open_orders = {}
    
    def execute_strategy(self, exchange_name: str, symbol: str, strategy_name: str) -> Optional[Dict]:
        """Execute a trading strategy for a symbol on an exchange"""
        exchange = self.exchange_manager.get_exchange(exchange_name)
        strategy = self.strategies.get(strategy_name)
        
        if not exchange or not strategy:
            logger.error(f"Exchange {exchange_name} or strategy {strategy_name} not found")
            return None
        
        # Get market data
        try:
            ohlcv = self.exchange_manager.get_ohlcv(exchange_name, symbol, '1h', 100)
            data = strategy.prepare_data(ohlcv)
            
            # Generate signal
            signal = strategy.generate_signal(data)
            
            if signal == 0:
                return None  # No action needed
            
            # Get current position
            current_position = self.portfolio.get_position(exchange_name, symbol)
            
            # Execute trade based on signal
            if signal == 1 and current_position <= 0:  # Buy signal
                return self.place_buy_order(exchange_name, symbol, data)
            elif signal == -1 and current_position >= 0:  # Sell signal
                return self.place_sell_order(exchange_name, symbol, data)
                
        except Exception as e:
            logger.error(f"Error executing strategy {strategy_name} on {exchange_name}: {e}")
            return None
    
    def place_buy_order(self, exchange_name: str, symbol: str, data: pd.DataFrame) -> Dict:
        """Place a buy order"""
        exchange = self.exchange_manager.get_exchange(exchange_name)
        base_currency = symbol.split('/')[0]
        quote_currency = symbol.split('/')[1]
        
        # Get available balance
        balances = self.exchange_manager.get_balances(exchange_name)
        available_quote = balances.get(quote_currency, 0)
        
        if available_quote <= 0:
            logger.warning(f"Insufficient {quote_currency} balance on {exchange_name}")
            return {}
        
        # Calculate order amount based on allocation rules
        max_per_trade = self.config['trading']['allocation']['max_per_trade']
        order_amount = available_quote * max_per_trade
        latest_price = data['close'].iloc[-1]
        
        # Calculate order size
        order_size = order_amount / latest_price
        
        # Get market info for precision
        market = exchange.load_markets()
        market_info = market[symbol]
        order_size = exchange.amount_to_precision(symbol, order_size)
        
        try:
            # Place market buy order
            order = exchange.create_market_buy_order(symbol, order_size)
            logger.info(f"Placed buy order: {order}")
            
            # Update portfolio
            self.portfolio.update_position(
                exchange_name, symbol, order_size, latest_price, 'buy'
            )
            
            return order
            
        except Exception as e:
            logger.error(f"Error placing buy order on {exchange_name}: {e}")
            return {}
    
    def place_sell_order(self, exchange_name: str, symbol: str, data: pd.DataFrame) -> Dict:
        """Place a sell order"""
        exchange = self.exchange_manager.get_exchange(exchange_name)
        base_currency = symbol.split('/')[0]
        
        # Get current position
        current_position = self.portfolio.get_position(exchange_name, symbol)
        
        if current_position <= 0:
            logger.warning(f"No position to sell for {symbol} on {exchange_name}")
            return {}
        
        # Get market info for precision
        market = exchange.load_markets()
        market_info = market[symbol]
        order_size = exchange.amount_to_precision(symbol, current_position)
        latest_price = data['close'].iloc[-1]
        
        try:
            # Place market sell order
            order = exchange.create_market_sell_order(symbol, order_size)
            logger.info(f"Placed sell order: {order}")
            
            # Update portfolio
            self.portfolio.update_position(
                exchange_name, symbol, order_size, latest_price, 'sell'
            )
            
            return order
            
        except Exception as e:
            logger.error(f"Error placing sell order on {exchange_name}: {e}")
            return {}