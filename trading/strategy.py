# trading/strategy.py
import abc
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple

class TradingStrategy(abc.ABC):
    """Abstract base class for trading strategies"""
    
    def __init__(self, params: Dict):
        self.params = params
        self.name = "base_strategy"
    
    @abc.abstractmethod
    def generate_signal(self, data: pd.DataFrame) -> int:
        """Generate trading signal: 1 for buy, -1 for sell, 0 for hold"""
        pass
    
    def prepare_data(self, ohlcv_data: List[List]) -> pd.DataFrame:
        """Convert OHLCV data to DataFrame"""
        df = pd.DataFrame(ohlcv_data, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
        df.set_index('timestamp', inplace=True)
        return df

class MeanReversionStrategy(TradingStrategy):
    """Mean reversion trading strategy using Bollinger Bands"""
    
    def __init__(self, params: Dict):
        super().__init__(params)
        self.name = "mean_reversion"
        self.period = params.get("period", 14)
        self.threshold = params.get("threshold", 2.0)
    
    def generate_signal(self, data: pd.DataFrame) -> int:
        """Generate signal based on Bollinger Bands"""
        if len(data) < self.period:
            return 0  # Not enough data
        
        # Calculate Bollinger Bands
        data['sma'] = data['close'].rolling(window=self.period).mean()
        data['std'] = data['close'].rolling(window=self.period).std()
        data['upper_band'] = data['sma'] + (data['std'] * self.threshold)
        data['lower_band'] = data['sma'] - (data['std'] * self.threshold)
        
        latest = data.iloc[-1]
        
        # Buy signal when price is below lower band
        if latest['close'] < latest['lower_band']:
            return 1
        
        # Sell signal when price is above upper band
        elif latest['close'] > latest['upper_band']:
            return -1
        
        return 0

class MomentumStrategy(TradingStrategy):
    """Momentum trading strategy using RSI"""
    
    def __init__(self, params: Dict):
        super().__init__(params)
        self.name = "momentum"
        self.period = params.get("period", 14)
        self.overbought = params.get("overbought", 70)
        self.oversold = params.get("oversold", 30)
    
    def calculate_rsi(self, data: pd.DataFrame) -> pd.Series:
        """Calculate RSI indicator"""
        delta = data['close'].diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=self.period).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=self.period).mean()
        rs = gain / loss
        rsi = 100 - (100 / (1 + rs))
        return rsi
    
    def generate_signal(self, data: pd.DataFrame) -> int:
        """Generate signal based on RSI"""
        if len(data) < self.period + 1:
            return 0  # Not enough data
        
        data['rsi'] = self.calculate_rsi(data)
        latest_rsi = data['rsi'].iloc[-1]
        
        # Buy signal when RSI is below oversold level
        if latest_rsi < self.oversold:
            return 1
        
        # Sell signal when RSI is above overbought level
        elif latest_rsi > self.overbought:
            return -1
        
        return 0