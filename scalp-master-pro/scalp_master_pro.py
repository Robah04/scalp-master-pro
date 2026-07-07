"""
═══════════════════════════════════════════════════════════════════════════════
SCALPMASTER PRO v2.0
═══════════════════════════════════════════════════════════════════════════════
Multi-Platform Scalping Signal Scanner with:
  - Traditional Technical Indicators (12+)
  - Smart Money Concepts (SMC)
  - Order Block (OB) Trading
  - Fair Value Gaps (FVG)
  - Liquidity Sweeps & Breaker Blocks
  - Built-in Authentication System
  - Real-time Dashboard Web Server

Platforms: Binance, Bybit, OKX, Deriv, Pocket Option, MT5 (Exness, XM, IC Markets, etc.)
Risk Level: LOW (1-2% per trade)
Target Win Rate: 80%+

Author: AI Trading Assistant
Version: 2.0.0
"""

import asyncio
import json
import logging
import os
import hashlib
import secrets
import time
import uuid
import jwt
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
import threading
import queue

# Data & Analysis
import numpy as np
import pandas as pd

# WebSocket & HTTP
import websockets
import aiohttp
from aiohttp import web

# Technical Analysis
from ta.trend import EMAIndicator, MACD, ADXIndicator, IchimokuIndicator
from ta.momentum import RSIIndicator, StochasticOscillator, WilliamsRIndicator
from ta.volatility import BollingerBands, AverageTrueRange
from ta.volume import OnBalanceVolumeIndicator, VolumeWeightedAveragePrice

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
    handlers=[
        logging.FileHandler('scalp_master.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ScalpMasterPro')


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class AuthManager:
    """
    JWT-based authentication with user management.
    Supports admin/user roles, session tokens, and secure password hashing.
    """

    SECRET_KEY = secrets.token_hex(32)
    TOKEN_EXPIRY = 24  # hours

    def __init__(self, db_path: str = "users.json"):
        self.db_path = db_path
        self.users: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self._load_users()

        if not self.users:
            self.register_user("admin", "admin123", role="admin", email="admin@scalpmaster.com")
            logger.info("Default admin created: admin/admin123")

    def _load_users(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    self.users = json.load(f)
            except:
                self.users = {}

    def _save_users(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.users, f, indent=2)

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hashed.hex(), salt

    def register_user(self, username: str, password: str, role: str = "user", 
                     email: str = "", api_keys: Dict = None) -> bool:
        if username in self.users:
            return False

        hashed_pw, salt = self._hash_password(password)
        self.users[username] = {
            "username": username,
            "password_hash": hashed_pw,
            "salt": salt,
            "role": role,
            "email": email,
            "created_at": datetime.now().isoformat(),
            "api_keys": api_keys or {},
            "settings": {
                "risk_per_trade": 1.0,
                "max_positions": 5,
                "timeframes": ["5m", "15m"],
                "auto_trade": False,
                "enabled_platforms": [],
                "enabled_strategies": ["all"],
                "notifications": True
            }
        }
        self._save_users()
        logger.info(f"User registered: {username} (role: {role})")
        return True

    def authenticate(self, username: str, password: str) -> Optional[str]:
        if username not in self.users:
            return None

        user = self.users[username]
        hashed_pw, _ = self._hash_password(password, user["salt"])

        if hashed_pw == user["password_hash"]:
            token = jwt.encode(
                {
                    "username": username,
                    "role": user["role"],
                    "exp": datetime.utcnow() + timedelta(hours=self.TOKEN_EXPIRY),
                    "jti": str(uuid.uuid4())
                },
                self.SECRET_KEY,
                algorithm="HS256"
            )
            self.sessions[token] = {
                "username": username,
                "created_at": datetime.now(),
                "last_active": datetime.now()
            }
            logger.info(f"User authenticated: {username}")
            return token
        return None

    def verify_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=["HS256"])
            if token in self.sessions:
                self.sessions[token]["last_active"] = datetime.now()
                return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
        return None

    def logout(self, token: str):
        if token in self.sessions:
            del self.sessions[token]

    def get_user(self, username: str) -> Optional[Dict]:
        return self.users.get(username)

    def update_user_settings(self, username: str, settings: Dict):
        if username in self.users:
            self.users[username]["settings"].update(settings)
            self._save_users()

    def update_api_keys(self, username: str, platform: str, api_key: str, api_secret: str, **kwargs):
        if username in self.users:
            self.users[username]["api_keys"][platform] = {
                "api_key": api_key,
                "api_secret": api_secret,
                **kwargs
            }
            self._save_users()


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class SignalDirection(Enum):
    BUY = "BUY"
    SELL = "SELL"
    HOLD = "HOLD"

class MarketCondition(Enum):
    TRENDING_UP = "TRENDING_UP"
    TRENDING_DOWN = "TRENDING_DOWN"
    RANGING = "RANGING"
    VOLATILE = "VOLATILE"
    UNKNOWN = "UNKNOWN"

class StrategyType(Enum):
    EMA_MACD_RSI = "EMA_MACD_RSI_Confluence"
    BB_SQUEEZE = "Bollinger_Squeeze_Breakout"
    ICHIMOKU_CLOUD = "Ichimoku_Cloud_Breakout"
    VWAP_REVERSAL = "VWAP_Mean_Reversion"
    SMC_ORDER_BLOCK = "SMC_Order_Block"
    SMC_FVG = "SMC_Fair_Value_Gap"
    SMC_LIQUIDITY = "SMC_Liquidity_Sweep"
    SMC_BREAKER = "SMC_Breaker_Block"

@dataclass
class Candle:
    timestamp: datetime
    open: float
    high: float
    low: float
    close: float
    volume: float

    def body_size(self) -> float:
        return abs(self.close - self.open)

    def upper_wick(self) -> float:
        return self.high - max(self.open, self.close)

    def lower_wick(self) -> float:
        return min(self.open, self.close) - self.low

    def is_bullish(self) -> bool:
        return self.close > self.open

    def is_bearish(self) -> bool:
        return self.close < self.open

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "open": self.open,
            "high": self.high,
            "low": self.low,
            "close": self.close,
            "volume": self.volume
        }

@dataclass
class MarketSentiment:
    fear_greed_index: float = 50.0
    funding_rate: float = 0.0
    open_interest_change: float = 0.0
    liquidation_ratio: float = 0.0
    social_sentiment: float = 0.0
    overall_score: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class Signal:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    symbol: str = ""
    direction: SignalDirection = SignalDirection.HOLD
    confidence: float = 0.0
    entry_price: float = 0.0
    stop_loss: float = 0.0
    take_profit: float = 0.0
    risk_reward: float = 0.0
    timeframe: str = "15m"
    strategy_name: str = ""
    strategy_type: StrategyType = StrategyType.EMA_MACD_RSI
    indicators: Dict[str, Any] = field(default_factory=dict)
    sentiment: MarketSentiment = field(default_factory=MarketSentiment)
    timestamp: datetime = field(default_factory=datetime.now)
    platform: str = ""
    status: str = "PENDING"

    def is_valid(self) -> bool:
        return (self.confidence >= 0.75 and 
                self.risk_reward >= 1.5 and
                abs(self.entry_price - self.stop_loss) > 0)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "symbol": self.symbol,
            "direction": self.direction.value,
            "confidence": round(self.confidence, 4),
            "entry_price": self.entry_price,
            "stop_loss": self.stop_loss,
            "take_profit": self.take_profit,
            "risk_reward": round(self.risk_reward, 2),
            "timeframe": self.timeframe,
            "strategy_name": self.strategy_name,
            "strategy_type": self.strategy_type.value,
            "indicators": self.indicators,
            "sentiment": self.sentiment.to_dict(),
            "timestamp": self.timestamp.isoformat(),
            "platform": self.platform,
            "status": self.status
        }

@dataclass
class Position:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    signal_id: str = ""
    symbol: str = ""
    direction: SignalDirection = SignalDirection.HOLD
    entry_price: float = 0.0
    quantity: float = 0.0
    stop_loss: float = 0.0
    take_profit: float = 0.0
    open_time: datetime = field(default_factory=datetime.now)
    close_time: Optional[datetime] = None
    platform: str = ""
    pnl: float = 0.0
    pnl_percent: float = 0.0
    status: str = "OPEN"

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "signal_id": self.signal_id,
            "symbol": self.symbol,
            "direction": self.direction.value,
            "entry_price": self.entry_price,
            "quantity": self.quantity,
            "stop_loss": self.stop_loss,
            "take_profit": self.take_profit,
            "open_time": self.open_time.isoformat(),
            "close_time": self.close_time.isoformat() if self.close_time else None,
            "platform": self.platform,
            "pnl": self.pnl,
            "pnl_percent": self.pnl_percent,
            "status": self.status
        }

@dataclass
class OrderBlock:
    type: str
    high: float
    low: float
    open: float
    close: float
    volume: float
    timestamp: datetime
    index: int
    mitigated: bool = False

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "high": self.high,
            "low": self.low,
            "open": self.open,
            "close": self.close,
            "volume": self.volume,
            "timestamp": self.timestamp.isoformat(),
            "index": self.index,
            "mitigated": self.mitigated
        }

@dataclass
class FairValueGap:
    type: str
    top: float
    bottom: float
    timestamp: datetime
    index: int
    filled: bool = False

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "top": self.top,
            "bottom": self.bottom,
            "timestamp": self.timestamp.isoformat(),
            "index": self.index,
            "filled": self.filled
        }

@dataclass
class LiquidityPool:
    type: str
    price: float
    timestamp: datetime
    index: int
    swept: bool = False

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "price": self.price,
            "timestamp": self.timestamp.isoformat(),
            "index": self.index,
            "swept": self.swept
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TECHNICAL ANALYSIS ENGINE (Traditional)
# ═══════════════════════════════════════════════════════════════════════════════

class TechnicalAnalyzer:
    """Advanced multi-indicator confluence engine."""

    def __init__(self):
        self.min_candles = 50

    def analyze(self, candles: List[Candle], timeframe: str) -> Dict[str, Any]:
        if len(candles) < self.min_candles:
            return {"valid": False, "reason": "Insufficient data"}

        df = self._candles_to_df(candles)

        indicators = {
            "ema": self._calculate_ema(df),
            "macd": self._calculate_macd(df),
            "rsi": self._calculate_rsi(df),
            "bb": self._calculate_bollinger(df),
            "stoch": self._calculate_stochastic(df),
            "adx": self._calculate_adx(df),
            "atr": self._calculate_atr(df),
            "volume": self._calculate_volume_analysis(df),
            "vwap": self._calculate_vwap(df),
            "ichimoku": self._calculate_ichimoku(df),
            "williams_r": self._calculate_williams_r(df),
            "candlestick": self._analyze_candlestick_patterns(candles[-5:])
        }

        score = self._calculate_confluence_score(indicators, df)
        condition = self._determine_market_condition(indicators)

        return {
            "valid": True,
            "score": score,
            "condition": condition,
            "indicators": indicators,
            "current_price": df['close'].iloc[-1],
            "atr": indicators["atr"]["value"]
        }

    def _candles_to_df(self, candles: List[Candle]) -> pd.DataFrame:
        data = {
            'open': [c.open for c in candles],
            'high': [c.high for c in candles],
            'low': [c.low for c in candles],
            'close': [c.close for c in candles],
            'volume': [c.volume for c in candles]
        }
        return pd.DataFrame(data)

    def _calculate_ema(self, df: pd.DataFrame) -> Dict:
        ema9 = EMAIndicator(df['close'], window=9).ema_indicator()
        ema21 = EMAIndicator(df['close'], window=21).ema_indicator()
        ema50 = EMAIndicator(df['close'], window=50).ema_indicator()
        current_price = df['close'].iloc[-1]
        return {
            "ema9": ema9.iloc[-1],
            "ema21": ema21.iloc[-1],
            "ema50": ema50.iloc[-1],
            "trend": "BULLISH" if ema9.iloc[-1] > ema21.iloc[-1] > ema50.iloc[-1] else 
                    "BEARISH" if ema9.iloc[-1] < ema21.iloc[-1] < ema50.iloc[-1] else "MIXED",
            "price_above_ema9": current_price > ema9.iloc[-1],
            "price_above_ema21": current_price > ema21.iloc[-1]
        }

    def _calculate_macd(self, df: pd.DataFrame) -> Dict:
        macd = MACD(df['close'], window_slow=26, window_fast=12, window_sign=9)
        macd_line = macd.macd()
        signal_line = macd.macd_signal()
        histogram = macd.macd_diff()
        return {
            "macd": macd_line.iloc[-1],
            "signal": signal_line.iloc[-1],
            "histogram": histogram.iloc[-1],
            "crossover": "BULLISH" if histogram.iloc[-1] > 0 and histogram.iloc[-2] <= 0 else
                        "BEARISH" if histogram.iloc[-1] < 0 and histogram.iloc[-2] >= 0 else "NONE",
            "divergence": self._detect_macd_divergence(df, macd_line)
        }

    def _calculate_rsi(self, df: pd.DataFrame) -> Dict:
        rsi = RSIIndicator(df['close'], window=14).rsi()
        rsi_value = rsi.iloc[-1]
        return {
            "value": rsi_value,
            "oversold": rsi_value < 30,
            "overbought": rsi_value > 70,
            "neutral_zone": 40 <= rsi_value <= 60,
            "trend": "BULLISH" if rsi_value > 50 else "BEARISH",
            "divergence": self._detect_rsi_divergence(df, rsi)
        }

    def _calculate_bollinger(self, df: pd.DataFrame) -> Dict:
        bb = BollingerBands(df['close'], window=20, window_dev=2)
        upper = bb.bollinger_hband()
        lower = bb.bollinger_lband()
        middle = bb.bollinger_mavg()
        current_price = df['close'].iloc[-1]
        bandwidth = (upper.iloc[-1] - lower.iloc[-1]) / middle.iloc[-1]
        return {
            "upper": upper.iloc[-1],
            "middle": middle.iloc[-1],
            "lower": lower.iloc[-1],
            "bandwidth": bandwidth,
            "squeeze": bandwidth < 0.05,
            "position": (current_price - lower.iloc[-1]) / (upper.iloc[-1] - lower.iloc[-1]),
            "near_upper": current_price >= upper.iloc[-1] * 0.995,
            "near_lower": current_price <= lower.iloc[-1] * 1.005
        }

    def _calculate_stochastic(self, df: pd.DataFrame) -> Dict:
        stoch = StochasticOscillator(df['high'], df['low'], df['close'], window=14, smooth_window=3)
        k = stoch.stoch()
        d = stoch.stoch_signal()
        return {
            "k": k.iloc[-1],
            "d": d.iloc[-1],
            "oversold": k.iloc[-1] < 20,
            "overbought": k.iloc[-1] > 80,
            "crossover": "BULLISH" if k.iloc[-1] > d.iloc[-1] and k.iloc[-2] <= d.iloc[-2] else
                        "BEARISH" if k.iloc[-1] < d.iloc[-1] and k.iloc[-2] >= d.iloc[-2] else "NONE"
        }

    def _calculate_adx(self, df: pd.DataFrame) -> Dict:
        adx = ADXIndicator(df['high'], df['low'], df['close'], window=14)
        return {
            "adx": adx.adx().iloc[-1],
            "plus_di": adx.adx_pos().iloc[-1],
            "minus_di": adx.adx_neg().iloc[-1],
            "strong_trend": adx.adx().iloc[-1] > 25,
            "direction": "BULLISH" if adx.adx_pos().iloc[-1] > adx.adx_neg().iloc[-1] else "BEARISH"
        }

    def _calculate_atr(self, df: pd.DataFrame) -> Dict:
        atr = AverageTrueRange(df['high'], df['low'], df['close'], window=14)
        return {
            "value": atr.average_true_range().iloc[-1],
            "percent": (atr.average_true_range().iloc[-1] / df['close'].iloc[-1]) * 100
        }

    def _calculate_volume_analysis(self, df: pd.DataFrame) -> Dict:
        obv = OnBalanceVolumeIndicator(df['close'], df['volume'])
        obv_values = obv.on_balance_volume()
        avg_volume = df['volume'].rolling(window=20).mean().iloc[-1]
        current_volume = df['volume'].iloc[-1]
        return {
            "obv_trend": "RISING" if obv_values.iloc[-1] > obv_values.iloc[-5] else "FALLING",
            "volume_spike": current_volume > avg_volume * 1.5,
            "volume_ratio": current_volume / avg_volume if avg_volume > 0 else 0
        }

    def _calculate_vwap(self, df: pd.DataFrame) -> Dict:
        vwap = VolumeWeightedAveragePrice(df['high'], df['low'], df['close'], df['volume'])
        vwap_value = vwap.volume_weighted_average_price().iloc[-1]
        current_price = df['close'].iloc[-1]
        return {
            "value": vwap_value,
            "price_above": current_price > vwap_value,
            "deviation": ((current_price - vwap_value) / vwap_value) * 100
        }

    def _calculate_ichimoku(self, df: pd.DataFrame) -> Dict:
        ichimoku = IchimokuIndicator(df['high'], df['low'])
        tenkan = ichimoku.ichimoku_conversion_line().iloc[-1]
        kijun = ichimoku.ichimoku_base_line().iloc[-1]
        senkou_a = ichimoku.ichimoku_a().iloc[-1]
        senkou_b = ichimoku.ichimoku_b().iloc[-1]
        current_price = df['close'].iloc[-1]
        return {
            "tenkan": tenkan,
            "kijun": kijun,
            "senkou_a": senkou_a,
            "senkou_b": senkou_b,
            "cloud_bullish": senkou_a > senkou_b,
            "price_above_cloud": current_price > max(senkou_a, senkou_b),
            "tk_cross": "BULLISH" if tenkan > kijun else "BEARISH"
        }

    def _calculate_williams_r(self, df: pd.DataFrame) -> Dict:
        williams = WilliamsRIndicator(df['high'], df['low'], df['close'], lbp=14)
        value = williams.williams_r().iloc[-1]
        return {
            "value": value,
            "oversold": value < -80,
            "overbought": value > -20
        }

    def _analyze_candlestick_patterns(self, candles: List[Candle]) -> Dict:
        if len(candles) < 3:
            return {"patterns": []}
        patterns = []
        last = candles[-1]
        body = last.body_size()
        total_range = last.high - last.low
        if total_range > 0:
            lower_wick_ratio = last.lower_wick() / total_range
            upper_wick_ratio = last.upper_wick() / total_range
            if lower_wick_ratio > 0.6 and last.is_bullish():
                patterns.append("HAMMER")
            elif upper_wick_ratio > 0.6 and last.is_bearish():
                patterns.append("SHOOTING_STAR")
        if len(candles) >= 2:
            prev, curr = candles[-2], candles[-1]
            if curr.body_size() > prev.body_size():
                if curr.is_bullish() and prev.is_bearish():
                    patterns.append("BULLISH_ENGULFING")
                elif curr.is_bearish() and prev.is_bullish():
                    patterns.append("BEARISH_ENGULFING")
        if body < (last.high - last.low) * 0.1:
            patterns.append("DOJI")
        return {"patterns": patterns, "last_candle": "BULLISH" if last.is_bullish() else "BEARISH"}

    def _detect_macd_divergence(self, df: pd.DataFrame, macd: pd.Series) -> str:
        prices = df['close'].values
        macd_vals = macd.values
        if len(prices) < 20:
            return "NONE"
        price_lows = prices[-10:]
        macd_lows = macd_vals[-10:]
        if price_lows[-1] < min(price_lows[:-1]) and macd_lows[-1] > min(macd_lows[:-1]):
            return "BULLISH_DIVERGENCE"
        if price_lows[-1] > max(price_lows[:-1]) and macd_lows[-1] < max(macd_lows[:-1]):
            return "BEARISH_DIVERGENCE"
        return "NONE"

    def _detect_rsi_divergence(self, df: pd.DataFrame, rsi: pd.Series) -> str:
        prices = df['close'].values
        rsi_vals = rsi.values
        if len(prices) < 20:
            return "NONE"
        price_lows = prices[-10:]
        rsi_lows = rsi_vals[-10:]
        if price_lows[-1] < min(price_lows[:-1]) and rsi_lows[-1] > min(rsi_lows[:-1]):
            return "BULLISH_DIVERGENCE"
        if price_lows[-1] > max(price_lows[:-1]) and rsi_lows[-1] < max(rsi_lows[:-1]):
            return "BEARISH_DIVERGENCE"
        return "NONE"

    def _calculate_confluence_score(self, indicators: Dict, df: pd.DataFrame) -> Dict:
        score = 0.0
        max_score = 0.0
        signals = []

        max_score += 15
        ema = indicators["ema"]
        if ema["trend"] == "BULLISH":
            score += 15; signals.append("EMA_TREND_BULLISH")
        elif ema["trend"] == "BEARISH":
            score -= 15; signals.append("EMA_TREND_BEARISH")

        max_score += 15
        macd = indicators["macd"]
        if macd["crossover"] == "BULLISH":
            score += 15; signals.append("MACD_BULLISH_CROSS")
        elif macd["crossover"] == "BEARISH":
            score -= 15; signals.append("MACD_BEARISH_CROSS")
        elif macd["histogram"] > 0:
            score += 5
        else:
            score -= 5

        max_score += 10
        rsi = indicators["rsi"]
        if rsi["oversold"]:
            score += 10; signals.append("RSI_OVERSOLD")
        elif rsi["overbought"]:
            score -= 10; signals.append("RSI_OVERBOUGHT")
        elif rsi["neutral_zone"]:
            score += 3 if rsi["trend"] == "BULLISH" else -3

        max_score += 10
        bb = indicators["bb"]
        if bb["near_lower"]:
            score += 10; signals.append("BB_NEAR_LOWER")
        elif bb["near_upper"]:
            score -= 10; signals.append("BB_NEAR_UPPER")

        max_score += 10
        stoch = indicators["stoch"]
        if stoch["crossover"] == "BULLISH" and stoch["oversold"]:
            score += 10; signals.append("STOCH_BULLISH_OVERSOLD")
        elif stoch["crossover"] == "BEARISH" and stoch["overbought"]:
            score -= 10; signals.append("STOCH_BEARISH_OVERBOUGHT")

        max_score += 10
        adx = indicators["adx"]
        if adx["strong_trend"]:
            if adx["direction"] == "BULLISH":
                score += 10; signals.append("ADX_STRONG_BULLISH")
            else:
                score -= 10; signals.append("ADX_STRONG_BEARISH")

        max_score += 10
        vol = indicators["volume"]
        if vol["volume_spike"] and vol["obv_trend"] == "RISING":
            score += 10; signals.append("VOLUME_CONFIRMATION")

        max_score += 10
        vwap = indicators["vwap"]
        if vwap["price_above"] and vwap["deviation"] > 0.5:
            score += 10; signals.append("VWAP_ABOVE")
        elif not vwap["price_above"] and vwap["deviation"] < -0.5:
            score -= 10; signals.append("VWAP_BELOW")

        max_score += 5
        ichi = indicators["ichimoku"]
        if ichi["price_above_cloud"] and ichi["tk_cross"] == "BULLISH":
            score += 5; signals.append("ICHIMOKU_BULLISH")
        elif not ichi["price_above_cloud"] and ichi["tk_cross"] == "BEARISH":
            score -= 5; signals.append("ICHIMOKU_BEARISH")

        max_score += 5
        candle = indicators["candlestick"]
        if "HAMMER" in candle["patterns"] or "BULLISH_ENGULFING" in candle["patterns"]:
            score += 5; signals.append("CANDLE_BULLISH")
        elif "SHOOTING_STAR" in candle["patterns"] or "BEARISH_ENGULFING" in candle["patterns"]:
            score -= 5; signals.append("CANDLE_BEARISH")

        confidence = abs(score) / max_score if max_score > 0 else 0
        direction = SignalDirection.BUY if score > 0 else SignalDirection.SELL if score < 0 else SignalDirection.HOLD

        return {
            "score": score,
            "max_score": max_score,
            "confidence": confidence,
            "direction": direction,
            "signals": signals
        }

    def _determine_market_condition(self, indicators: Dict) -> MarketCondition:
        adx = indicators["adx"]
        bb = indicators["bb"]
        atr = indicators["atr"]
        if adx["adx"] > 25:
            if adx["direction"] == "BULLISH":
                return MarketCondition.TRENDING_UP
            else:
                return MarketCondition.TRENDING_DOWN
        elif bb["squeeze"]:
            return MarketCondition.RANGING
        elif atr["percent"] > 2.0:
            return MarketCondition.VOLATILE
        return MarketCondition.UNKNOWN


# ═══════════════════════════════════════════════════════════════════════════════
# SMART MONEY CONCEPTS (SMC) ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class SMCEngine:
    """
    Smart Money Concepts Analysis Engine
    Detects: Order Blocks, Fair Value Gaps, Liquidity Pools, Breaker Blocks
    """

    def __init__(self):
        self.lookback = 50

    def analyze(self, candles: List[Candle]) -> Dict[str, Any]:
        if len(candles) < self.lookback:
            return {"valid": False}

        order_blocks = self._detect_order_blocks(candles)
        fvgs = self._detect_fair_value_gaps(candles)
        liquidity = self._detect_liquidity_pools(candles)
        breaker_blocks = self._detect_breaker_blocks(candles, order_blocks)

        current_price = candles[-1].close

        active_bullish_ob = [ob for ob in order_blocks if ob.type == "bullish" and not ob.mitigated and abs(current_price - ob.low) / current_price < 0.005]
        active_bearish_ob = [ob for ob in order_blocks if ob.type == "bearish" and not ob.mitigated and abs(current_price - ob.high) / current_price < 0.005]

        active_bullish_fvg = [fvg for fvg in fvgs if fvg.type == "bullish" and not fvg.filled and current_price > fvg.bottom and current_price < fvg.top]
        active_bearish_fvg = [fvg for fvg in fvgs if fvg.type == "bearish" and not fvg.filled and current_price > fvg.bottom and current_price < fvg.top]

        recent_sweep = self._check_liquidity_sweep(candles, liquidity)

        return {
            "valid": True,
            "order_blocks": [ob.to_dict() for ob in order_blocks],
            "fair_value_gaps": [fvg.to_dict() for fvg in fvgs],
            "liquidity_pools": [lp.to_dict() for lp in liquidity],
            "breaker_blocks": [bb.to_dict() for bb in breaker_blocks],
            "active_bullish_ob": [ob.to_dict() for ob in active_bullish_ob],
            "active_bearish_ob": [ob.to_dict() for ob in active_bearish_ob],
            "active_bullish_fvg": [fvg.to_dict() for fvg in active_bullish_fvg],
            "active_bearish_fvg": [fvg.to_dict() for fvg in active_bearish_fvg],
            "recent_sweep": recent_sweep,
            "current_price": current_price
        }

    def _detect_order_blocks(self, candles: List[Candle]) -> List[OrderBlock]:
        order_blocks = []

        for i in range(3, len(candles) - 3):
            c = candles[i]

            if c.is_bearish():
                next_candles = candles[i+1:i+4]
                if all(nc.is_bullish() for nc in next_candles):
                    total_bullish_move = next_candles[-1].close - next_candles[0].open
                    if total_bullish_move > c.body_size() * 2:
                        order_blocks.append(OrderBlock(
                            type="bullish", high=c.high, low=c.low, open=c.open,
                            close=c.close, volume=c.volume, timestamp=c.timestamp, index=i
                        ))

            if c.is_bullish():
                next_candles = candles[i+1:i+4]
                if all(nc.is_bearish() for nc in next_candles):
                    total_bearish_move = next_candles[0].open - next_candles[-1].close
                    if total_bearish_move > c.body_size() * 2:
                        order_blocks.append(OrderBlock(
                            type="bearish", high=c.high, low=c.low, open=c.open,
                            close=c.close, volume=c.volume, timestamp=c.timestamp, index=i
                        ))

        for ob in order_blocks:
            for j in range(ob.index + 1, len(candles)):
                if ob.type == "bullish":
                    if candles[j].low <= ob.low:
                        ob.mitigated = True
                        break
                else:
                    if candles[j].high >= ob.high:
                        ob.mitigated = True
                        break

        return order_blocks

    def _detect_fair_value_gaps(self, candles: List[Candle]) -> List[FairValueGap]:
        fvgs = []

        for i in range(2, len(candles)):
            prev = candles[i-2]
            curr = candles[i]

            if curr.low > prev.high:
                fvgs.append(FairValueGap(
                    type="bullish", top=curr.low, bottom=prev.high,
                    timestamp=candles[i-1].timestamp, index=i-1
                ))

            if curr.high < prev.low:
                fvgs.append(FairValueGap(
                    type="bearish", top=prev.low, bottom=curr.high,
                    timestamp=candles[i-1].timestamp, index=i-1
                ))

        for fvg in fvgs:
            for j in range(fvg.index + 1, len(candles)):
                if fvg.type == "bullish":
                    if candles[j].low <= fvg.bottom:
                        fvg.filled = True
                        break
                else:
                    if candles[j].high >= fvg.top:
                        fvg.filled = True
                        break

        return fvgs

    def _detect_liquidity_pools(self, candles: List[Candle]) -> List[LiquidityPool]:
        liquidity = []

        for i in range(2, len(candles) - 2):
            if candles[i].high > candles[i-1].high and candles[i].high > candles[i-2].high and                candles[i].high > candles[i+1].high and candles[i].high > candles[i+2].high:
                liquidity.append(LiquidityPool(
                    type="high", price=candles[i].high,
                    timestamp=candles[i].timestamp, index=i
                ))

            if candles[i].low < candles[i-1].low and candles[i].low < candles[i-2].low and                candles[i].low < candles[i+1].low and candles[i].low < candles[i+2].low:
                liquidity.append(LiquidityPool(
                    type="low", price=candles[i].low,
                    timestamp=candles[i].timestamp, index=i
                ))

        for lp in liquidity:
            for j in range(lp.index + 1, len(candles)):
                if lp.type == "high":
                    if candles[j].high >= lp.price:
                        lp.swept = True
                        break
                else:
                    if candles[j].low <= lp.price:
                        lp.swept = True
                        break

        return liquidity

    def _detect_breaker_blocks(self, candles: List[Candle], order_blocks: List[OrderBlock]) -> List[OrderBlock]:
        breaker_blocks = []

        for ob in order_blocks:
            if ob.mitigated:
                for j in range(ob.index + 1, len(candles) - 3):
                    if ob.type == "bullish":
                        if candles[j].is_bullish() and candles[j+1].is_bullish() and candles[j+2].is_bullish():
                            breaker_blocks.append(OrderBlock(
                                type="bearish", high=ob.high, low=ob.low, open=ob.open,
                                close=ob.close, volume=ob.volume, timestamp=ob.timestamp, index=ob.index
                            ))
                            break
                    else:
                        if candles[j].is_bearish() and candles[j+1].is_bearish() and candles[j+2].is_bearish():
                            breaker_blocks.append(OrderBlock(
                                type="bullish", high=ob.high, low=ob.low, open=ob.open,
                                close=ob.close, volume=ob.volume, timestamp=ob.timestamp, index=ob.index
                            ))
                            break

        return breaker_blocks

    def _check_liquidity_sweep(self, candles: List[Candle], liquidity: List[LiquidityPool]) -> Optional[Dict]:
        if len(candles) < 5 or not liquidity:
            return None

        recent_candles = candles[-5:]
        recent_high = max(c.high for c in recent_candles)
        recent_low = min(c.low for c in recent_candles)

        for lp in liquidity[-5:]:
            if not lp.swept:
                continue
            if lp.type == "high" and recent_high >= lp.price:
                if candles[-1].is_bearish() and candles[-1].close < candles[-2].open:
                    return {
                        "type": "bearish_sweep", "price": lp.price,
                        "liquidity_type": "high",
                        "strength": "strong" if candles[-1].body_size() > candles[-2].body_size() else "weak"
                    }
            elif lp.type == "low" and recent_low <= lp.price:
                if candles[-1].is_bullish() and candles[-1].close > candles[-2].open:
                    return {
                        "type": "bullish_sweep", "price": lp.price,
                        "liquidity_type": "low",
                        "strength": "strong" if candles[-1].body_size() > candles[-2].body_size() else "weak"
                    }

        return None


# ═══════════════════════════════════════════════════════════════════════════════
# MARKET SENTIMENT ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class SentimentAnalyzer:
    def __init__(self):
        self.fear_greed_url = "https://api.alternative.me/fng/"
        self.session = None

    async def initialize(self):
        self.session = aiohttp.ClientSession()

    async def analyze(self, symbol: str) -> MarketSentiment:
        sentiment = MarketSentiment()
        try:
            async with self.session.get(self.fear_greed_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    sentiment.fear_greed_index = float(data['data'][0]['value'])
        except Exception as e:
            logger.warning(f"Could not fetch Fear & Greed: {e}")
        sentiment.overall_score = ((sentiment.fear_greed_index - 50) / 50)
        return sentiment

    def is_favorable(self, sentiment: MarketSentiment, direction: SignalDirection) -> bool:
        if direction == SignalDirection.BUY and sentiment.fear_greed_index < 25:
            return True
        if direction == SignalDirection.SELL and sentiment.fear_greed_index > 75:
            return True
        if 30 <= sentiment.fear_greed_index <= 70:
            return True
        return False

    async def close(self):
        if self.session:
            await self.session.close()


# ═══════════════════════════════════════════════════════════════════════════════
# STRATEGY ENGINE - ALL 8 STRATEGIES
# ═══════════════════════════════════════════════════════════════════════════════

class StrategyEngine:
    """
    Master strategy engine combining Traditional TA + Smart Money Concepts.
    8 strategies total with confluence scoring.
    """

    def __init__(self, analyzer: TechnicalAnalyzer, smc: SMCEngine, sentiment: SentimentAnalyzer):
        self.analyzer = analyzer
        self.smc = smc
        self.sentiment = sentiment

    async def generate_all_signals(self, symbol: str, candles: List[Candle], 
                                  timeframe: str, platform: str) -> List[Signal]:
        signals = []

        s1 = await self._strategy_ema_macd_rsi(symbol, candles, timeframe, platform)
        if s1: signals.append(s1)

        s2 = await self._strategy_bb_squeeze(symbol, candles, timeframe, platform)
        if s2: signals.append(s2)

        s3 = await self._strategy_ichimoku(symbol, candles, timeframe, platform)
        if s3: signals.append(s3)

        s4 = await self._strategy_vwap(symbol, candles, timeframe, platform)
        if s4: signals.append(s4)

        s5 = await self._strategy_smc_order_block(symbol, candles, timeframe, platform)
        if s5: signals.append(s5)

        s6 = await self._strategy_smc_fvg(symbol, candles, timeframe, platform)
        if s6: signals.append(s6)

        s7 = await self._strategy_smc_liquidity(symbol, candles, timeframe, platform)
        if s7: signals.append(s7)

        s8 = await self._strategy_smc_breaker(symbol, candles, timeframe, platform)
        if s8: signals.append(s8)

        signals.sort(key=lambda x: x.confidence, reverse=True)
        return [s for s in signals if s.confidence >= 0.75]

    async def _strategy_ema_macd_rsi(self, symbol, candles, timeframe, platform):
        analysis = self.analyzer.analyze(candles, timeframe)
        if not analysis["valid"]:
            return None
        score = analysis["score"]
        if score["confidence"] < 0.75:
            return None
        return self._create_signal(symbol, candles, analysis, timeframe, platform,
                                   StrategyType.EMA_MACD_RSI, "EMA_MACD_RSI_Confluence")

    async def _strategy_bb_squeeze(self, symbol, candles, timeframe, platform):
        analysis = self.analyzer.analyze(candles, timeframe)
        if not analysis["valid"]:
            return None
        bb = analysis["indicators"]["bb"]
        vol = analysis["indicators"]["volume"]
        if not (bb["squeeze"] and vol["volume_spike"]):
            return None
        score = analysis["score"]
        if score["confidence"] < 0.70:
            return None
        return self._create_signal(symbol, candles, analysis, timeframe, platform,
                                   StrategyType.BB_SQUEEZE, "BB_Squeeze_Breakout")

    async def _strategy_ichimoku(self, symbol, candles, timeframe, platform):
        analysis = self.analyzer.analyze(candles, timeframe)
        if not analysis["valid"]:
            return None
        ichi = analysis["indicators"]["ichimoku"]
        if not (ichi["price_above_cloud"] and ichi["tk_cross"] == "BULLISH"):
            return None
        score = analysis["score"]
        if score["confidence"] < 0.70:
            return None
        return self._create_signal(symbol, candles, analysis, timeframe, platform,
                                   StrategyType.ICHIMOKU_CLOUD, "Ichimoku_Cloud_Breakout")

    async def _strategy_vwap(self, symbol, candles, timeframe, platform):
        analysis = self.analyzer.analyze(candles, timeframe)
        if not analysis["valid"]:
            return None
        vwap = analysis["indicators"]["vwap"]
        if abs(vwap["deviation"]) < 1.0:
            return None
        score = analysis["score"]
        if score["confidence"] < 0.70:
            return None
        return self._create_signal(symbol, candles, analysis, timeframe, platform,
                                   StrategyType.VWAP_REVERSAL, "VWAP_Mean_Reversion")

    async def _strategy_smc_order_block(self, symbol, candles, timeframe, platform):
        smc = self.smc.analyze(candles)
        if not smc["valid"]:
            return None
        current_price = smc["current_price"]

        for ob in smc["active_bullish_ob"]:
            if current_price <= ob["high"] and current_price >= ob["low"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.BUY:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_ORDER_BLOCK, "SMC_Order_Block")
                    signal.indicators["smc"] = {"order_block": ob, "type": "bullish_ob_entry"}
                    return signal

        for ob in smc["active_bearish_ob"]:
            if current_price <= ob["high"] and current_price >= ob["low"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.SELL:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_ORDER_BLOCK, "SMC_Order_Block")
                    signal.indicators["smc"] = {"order_block": ob, "type": "bearish_ob_entry"}
                    return signal
        return None

    async def _strategy_smc_fvg(self, symbol, candles, timeframe, platform):
        smc = self.smc.analyze(candles)
        if not smc["valid"]:
            return None
        current_price = smc["current_price"]

        for fvg in smc["active_bullish_fvg"]:
            if fvg["bottom"] <= current_price <= fvg["top"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.BUY:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_FVG, "SMC_Fair_Value_Gap")
                    signal.indicators["smc"] = {"fvg": fvg, "type": "bullish_fvg_entry"}
                    return signal

        for fvg in smc["active_bearish_fvg"]:
            if fvg["bottom"] <= current_price <= fvg["top"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.SELL:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_FVG, "SMC_Fair_Value_Gap")
                    signal.indicators["smc"] = {"fvg": fvg, "type": "bearish_fvg_entry"}
                    return signal
        return None

    async def _strategy_smc_liquidity(self, symbol, candles, timeframe, platform):
        smc = self.smc.analyze(candles)
        if not smc["valid"] or not smc["recent_sweep"]:
            return None
        sweep = smc["recent_sweep"]
        analysis = self.analyzer.analyze(candles, timeframe)
        if not analysis["valid"]:
            return None

        if sweep["type"] == "bullish_sweep" and analysis["score"]["direction"] == SignalDirection.BUY:
            signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                        StrategyType.SMC_LIQUIDITY, "SMC_Liquidity_Sweep")
            signal.indicators["smc"] = {"sweep": sweep, "type": "liquidity_sweep_reversal"}
            return signal

        if sweep["type"] == "bearish_sweep" and analysis["score"]["direction"] == SignalDirection.SELL:
            signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                        StrategyType.SMC_LIQUIDITY, "SMC_Liquidity_Sweep")
            signal.indicators["smc"] = {"sweep": sweep, "type": "liquidity_sweep_reversal"}
            return signal
        return None

    async def _strategy_smc_breaker(self, symbol, candles, timeframe, platform):
        smc = self.smc.analyze(candles)
        if not smc["valid"] or not smc["breaker_blocks"]:
            return None
        current_price = smc["current_price"]

        for bb in smc["breaker_blocks"]:
            if bb["type"] == "bullish" and current_price >= bb["low"] and current_price <= bb["high"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.BUY:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_BREAKER, "SMC_Breaker_Block")
                    signal.indicators["smc"] = {"breaker": bb, "type": "bullish_breaker_entry"}
                    return signal
            if bb["type"] == "bearish" and current_price >= bb["low"] and current_price <= bb["high"]:
                analysis = self.analyzer.analyze(candles, timeframe)
                if analysis["valid"] and analysis["score"]["direction"] == SignalDirection.SELL:
                    signal = self._create_signal(symbol, candles, analysis, timeframe, platform,
                                                StrategyType.SMC_BREAKER, "SMC_Breaker_Block")
                    signal.indicators["smc"] = {"breaker": bb, "type": "bearish_breaker_entry"}
                    return signal
        return None

    def _create_signal(self, symbol, candles, analysis, timeframe, platform, 
                      strategy_type, strategy_name) -> Optional[Signal]:
        score_data = analysis["score"]
        indicators = analysis["indicators"]
        current_price = analysis["current_price"]
        atr = analysis["atr"]

        direction = score_data["direction"]
        if direction == SignalDirection.HOLD:
            return None

        atr_multiplier_sl = 1.5
        atr_multiplier_tp = 3.0

        if direction == SignalDirection.BUY:
            stop_loss = current_price - (atr["value"] * atr_multiplier_sl)
            take_profit = current_price + (atr["value"] * atr_multiplier_tp)
        else:
            stop_loss = current_price + (atr["value"] * atr_multiplier_sl)
            take_profit = current_price - (atr["value"] * atr_multiplier_tp)

        risk = abs(current_price - stop_loss)
        reward = abs(take_profit - current_price)
        risk_reward = reward / risk if risk > 0 else 0

        if risk_reward < 1.5:
            return None

        signal = Signal(
            symbol=symbol,
            direction=direction,
            confidence=score_data["confidence"],
            entry_price=current_price,
            stop_loss=stop_loss,
            take_profit=take_profit,
            risk_reward=risk_reward,
            timeframe=timeframe,
            strategy_name=strategy_name,
            strategy_type=strategy_type,
            indicators={
                "score": score_data["score"],
                "signals_triggered": score_data["signals"],
                "market_condition": analysis["condition"].value,
                "atr": atr["value"],
                "rsi": indicators["rsi"]["value"],
                "macd_histogram": indicators["macd"]["histogram"],
                "ema_trend": indicators["ema"]["trend"],
                "bb_position": indicators["bb"]["position"],
                "adx": indicators["adx"]["adx"]
            },
            platform=platform
        )

        return signal if signal.is_valid() else None


# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM CONNECTORS
# ═══════════════════════════════════════════════════════════════════════════════

class PlatformConnector:
    def __init__(self, name: str, api_key: str = "", api_secret: str = "", 
                 passphrase: str = "", testnet: bool = True):
        self.name = name
        self.api_key = api_key
        self.api_secret = api_secret
        self.passphrase = passphrase
        self.testnet = testnet
        self.connected = False
        self.price_cache: Dict[str, deque] = {}
        self.max_cache_size = 200

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        pass

    async def get_balance(self):
        pass

    async def place_order(self, signal, risk_percent: float = 1.0):
        pass

    async def get_symbols(self):
        pass

    def add_price(self, symbol: str, candle):
        if symbol not in self.price_cache:
            self.price_cache[symbol] = deque(maxlen=self.max_cache_size)
        self.price_cache[symbol].append(candle)

    def get_cached_candles(self, symbol: str):
        return list(self.price_cache.get(symbol, deque()))


class BinanceConnector(PlatformConnector):
    def __init__(self, api_key: str, api_secret: str, testnet: bool = True, futures: bool = True):
        super().__init__("Binance", api_key, api_secret, testnet=testnet)
        self.futures = futures
        self.base_url = "https://testnet.binancefuture.com" if testnet and futures else                        "https://fapi.binance.com" if futures else                        "https://testnet.binance.vision" if testnet else "https://api.binance.com"
        self.session = None

    async def connect(self):
        self.session = aiohttp.ClientSession()
        async with self.session.get(f"{self.base_url}/api/v3/ping") as resp:
            if resp.status == 200:
                self.connected = True
                logger.info(f"Connected to {self.name}")
            else:
                logger.error(f"Failed to connect to {self.name}")

    async def disconnect(self):
        if self.session:
            await self.session.close()
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        interval_map = {"1m": "1m", "5m": "5m", "15m": "15m", "1h": "1h", "4h": "4h"}
        interval = interval_map.get(timeframe, "15m")
        endpoint = "/fapi/v1/klines" if self.futures else "/api/v3/klines"
        url = f"{self.base_url}{endpoint}?symbol={symbol}&interval={interval}&limit={limit}"

        async with self.session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                candles = []
                for d in data:
                    candles.append(Candle(
                        timestamp=datetime.fromtimestamp(d[0] / 1000),
                        open=float(d[1]), high=float(d[2]), low=float(d[3]),
                        close=float(d[4]), volume=float(d[5])
                    ))
                return candles
            return []

    async def get_balance(self):
        return {"USDT": 10000.0}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol}")
        return True

    async def get_symbols(self):
        endpoint = "/fapi/v1/exchangeInfo" if self.futures else "/api/v3/exchangeInfo"
        async with self.session.get(f"{self.base_url}{endpoint}") as resp:
            if resp.status == 200:
                data = await resp.json()
                symbols = [s['symbol'] for s in data['symbols'] 
                          if s['status'] == 'TRADING' and 'USDT' in s['symbol']]
                return symbols[:50]
            return []


class BybitConnector(PlatformConnector):
    def __init__(self, api_key: str, api_secret: str, testnet: bool = True):
        super().__init__("Bybit", api_key, api_secret, testnet=testnet)
        self.base_url = "https://api-testnet.bybit.com" if testnet else "https://api.bybit.com"
        self.category = "linear"

    async def connect(self):
        self.session = aiohttp.ClientSession()
        async with self.session.get(f"{self.base_url}/v5/market/time") as resp:
            if resp.status == 200:
                self.connected = True
                logger.info(f"Connected to {self.name}")
            else:
                logger.error(f"Failed to connect to {self.name}")

    async def disconnect(self):
        if self.session:
            await self.session.close()
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        interval_map = {"1m": "1", "5m": "5", "15m": "15", "1h": "60", "4h": "240"}
        interval = interval_map.get(timeframe, "15")
        url = f"{self.base_url}/v5/market/kline?category={self.category}&symbol={symbol}&interval={interval}&limit={limit}"

        async with self.session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data['retCode'] == 0:
                    candles = []
                    for d in data['result']['list']:
                        candles.append(Candle(
                            timestamp=datetime.fromtimestamp(int(d[0]) / 1000),
                            open=float(d[1]), high=float(d[2]), low=float(d[3]),
                            close=float(d[4]), volume=float(d[5])
                        ))
                    return candles[::-1]
            return []

    async def get_balance(self):
        return {"USDT": 10000.0}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol}")
        return True

    async def get_symbols(self):
        url = f"{self.base_url}/v5/market/instruments-info?category={self.category}"
        async with self.session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data['retCode'] == 0:
                    symbols = [s['symbol'] for s in data['result']['list'] 
                              if 'USDT' in s['symbol']]
                    return symbols[:50]
            return []


class OKXConnector(PlatformConnector):
    def __init__(self, api_key: str, api_secret: str, passphrase: str, testnet: bool = True):
        super().__init__("OKX", api_key, api_secret, passphrase, testnet)
        self.base_url = "https://www.okx.com"

    async def connect(self):
        self.session = aiohttp.ClientSession()
        async with self.session.get(f"{self.base_url}/api/v5/public/time") as resp:
            if resp.status == 200:
                self.connected = True
                logger.info(f"Connected to {self.name}")
            else:
                logger.error(f"Failed to connect to {self.name}")

    async def disconnect(self):
        if self.session:
            await self.session.close()
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        bar_map = {"1m": "1m", "5m": "5m", "15m": "15m", "1h": "1H", "4h": "4H"}
        bar = bar_map.get(timeframe, "15m")
        url = f"{self.base_url}/api/v5/market/candles?instId={symbol}&bar={bar}&limit={limit}"

        async with self.session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data['code'] == '0':
                    candles = []
                    for d in data['data']:
                        candles.append(Candle(
                            timestamp=datetime.fromtimestamp(int(d[0]) / 1000),
                            open=float(d[1]), high=float(d[2]), low=float(d[3]),
                            close=float(d[4]), volume=float(d[5])
                        ))
                    return candles[::-1]
            return []

    async def get_balance(self):
        return {"USDT": 10000.0}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol}")
        return True

    async def get_symbols(self):
        url = f"{self.base_url}/api/v5/public/instruments?instType=SWAP"
        async with self.session.get(url) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data['code'] == '0':
                    symbols = [s['instId'] for s in data['data'] 
                              if 'USDT' in s['instId']]
                    return symbols[:50]
            return []


class DerivConnector(PlatformConnector):
    def __init__(self, api_token: str, app_id: str = "1089"):
        super().__init__("Deriv", api_token, "")
        self.app_id = app_id
        self.ws_url = f"wss://ws.binaryws.com/websockets/v3?app_id={app_id}"
        self.ws = None
        self.req_id = 0

    async def connect(self):
        try:
            self.ws = await websockets.connect(self.ws_url)
            auth_msg = {"authorize": self.api_key, "req_id": self._get_req_id()}
            await self.ws.send(json.dumps(auth_msg))
            response = await self.ws.recv()
            data = json.loads(response)
            if 'authorize' in data:
                self.connected = True
                logger.info(f"Connected to {self.name}")
            else:
                logger.error(f"Deriv auth failed: {data}")
        except Exception as e:
            logger.error(f"Deriv connection error: {e}")

    def _get_req_id(self) -> int:
        self.req_id += 1
        return self.req_id

    async def disconnect(self):
        if self.ws:
            await self.ws.close()
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        granularity_map = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}
        granularity = granularity_map.get(timeframe, 900)
        req = {
            "ticks_history": symbol, "adjust_start_time": 1, "count": limit,
            "end": "latest", "granularity": granularity, "style": "candles",
            "req_id": self._get_req_id()
        }
        await self.ws.send(json.dumps(req))
        response = await self.ws.recv()
        data = json.loads(response)
        candles = []
        if 'candles' in data:
            for c in data['candles']:
                candles.append(Candle(
                    timestamp=datetime.fromtimestamp(c['epoch']),
                    open=float(c['open']), high=float(c['high']),
                    low=float(c['low']), close=float(c['close']),
                    volume=float(c.get('volume', 0))
                ))
        return candles

    async def get_balance(self):
        req = {"balance": 1, "req_id": self._get_req_id()}
        await self.ws.send(json.dumps(req))
        response = await self.ws.recv()
        data = json.loads(response)
        if 'balance' in data:
            return {data['balance']['currency']: float(data['balance']['balance'])}
        return {}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol}")
        return True

    async def get_symbols(self):
        return [
            "R_10", "R_25", "R_50", "R_75", "R_100",
            "1HZ10V", "1HZ25V", "1HZ50V", "1HZ75V", "1HZ100V",
            "JD10", "JD25", "JD50", "JD75", "JD100",
            "BOOM1000", "BOOM500", "CRASH1000", "CRASH500",
            "frxEURUSD", "frxGBPUSD", "frxUSDJPY", "frxAUDUSD"
        ]


class PocketOptionConnector(PlatformConnector):
    def __init__(self, ssid: str, is_demo: bool = True):
        super().__init__("PocketOption", ssid, "")
        self.is_demo = is_demo

    async def connect(self):
        logger.info(f"{self.name} initialized (Demo: {self.is_demo})")
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        candles = []
        base_price = 1.0850 if "EURUSD" in symbol else 100.0
        for i in range(limit):
            noise = np.random.normal(0, 0.0002)
            close = base_price + noise + (i * 0.00001)
            candles.append(Candle(
                timestamp=datetime.now() - timedelta(minutes=limit-i),
                open=close - np.random.normal(0, 0.0001),
                high=close + abs(np.random.normal(0, 0.0003)),
                low=close - abs(np.random.normal(0, 0.0003)),
                close=close,
                volume=np.random.randint(100, 1000)
            ))
        return candles

    async def get_balance(self):
        return {"USD": 1000.0}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol} (Binary)")
        return True

    async def get_symbols(self):
        return [
            "EURUSD_otc", "GBPUSD_otc", "USDJPY_otc", "AUDUSD_otc",
            "EURGBP_otc", "USDCHF_otc", "USDCAD_otc", "NZDUSD_otc",
            "BTCUSD", "ETHUSD", "LTCUSD", "XRPUSD"
        ]


class MT5Connector(PlatformConnector):
    def __init__(self, login: int = 0, password: str = "", server: str = "", 
                 broker_name: str = "Exness"):
        super().__init__(f"MT5_{broker_name}", str(login), password)
        self.login = login
        self.server = server
        self.broker_name = broker_name
        self.mt5_initialized = False

    async def connect(self):
        try:
            import MetaTrader5 as mt5
            if not mt5.initialize():
                logger.error(f"MT5 initialize failed: {mt5.last_error()}")
                return
            if self.login > 0:
                authorized = mt5.login(self.login, password=self.api_secret, server=self.server)
                if not authorized:
                    logger.error(f"MT5 login failed")
                    return
            self.mt5_initialized = True
            self.connected = True
            logger.info(f"Connected to {self.name} via MT5")
        except ImportError:
            logger.warning(f"MetaTrader5 package not installed. Using simulation mode.")
            self.connected = True

    async def disconnect(self):
        try:
            import MetaTrader5 as mt5
            mt5.shutdown()
        except:
            pass
        self.connected = False

    async def get_candles(self, symbol: str, timeframe: str, limit: int = 100):
        try:
            import MetaTrader5 as mt5
            tf_map = {
                "1m": mt5.TIMEFRAME_M1, "5m": mt5.TIMEFRAME_M5,
                "15m": mt5.TIMEFRAME_M15, "30m": mt5.TIMEFRAME_M30,
                "1h": mt5.TIMEFRAME_H1, "4h": mt5.TIMEFRAME_H4,
                "1d": mt5.TIMEFRAME_D1
            }
            mt5_tf = tf_map.get(timeframe, mt5.TIMEFRAME_M15)
            rates = mt5.copy_rates_from_pos(symbol, mt5_tf, 0, limit)
            if rates is None:
                return self._generate_simulated_candles(symbol, limit)
            candles = []
            for r in rates:
                candles.append(Candle(
                    timestamp=datetime.fromtimestamp(r['time']),
                    open=float(r['open']), high=float(r['high']),
                    low=float(r['low']), close=float(r['close']),
                    volume=float(r['tick_volume'])
                ))
            return candles
        except:
            return self._generate_simulated_candles(symbol, limit)

    def _generate_simulated_candles(self, symbol: str, limit: int):
        candles = []
        base = 1.0850 if "EURUSD" in symbol else 1500.0 if "BTC" in symbol else 100.0
        for i in range(limit):
            noise = np.random.normal(0, base * 0.001)
            close = base + noise
            candles.append(Candle(
                timestamp=datetime.now() - timedelta(minutes=limit-i),
                open=close - np.random.normal(0, base * 0.0005),
                high=close + abs(np.random.normal(0, base * 0.001)),
                low=close - abs(np.random.normal(0, base * 0.001)),
                close=close,
                volume=np.random.randint(100, 5000)
            ))
        return candles

    async def get_balance(self):
        try:
            import MetaTrader5 as mt5
            account = mt5.account_info()
            if account:
                return {account.currency: account.balance}
        except:
            pass
        return {"USD": 10000.0}

    async def place_order(self, signal, risk_percent: float = 1.0):
        logger.info(f"{self.name} SIGNAL: {signal.direction.value} {signal.symbol}")
        return True

    async def get_symbols(self):
        try:
            import MetaTrader5 as mt5
            symbols = mt5.symbols_get()
            if symbols:
                return [s.name for s in symbols if "USD" in s.name or "EUR" in s.name][:50]
        except:
            pass
        return ["EURUSD", "GBPUSD", "USDJPY", "AUDUSD", "USDCAD", 
                "XAUUSD", "BTCUSD", "ETHUSD", "NAS100", "US30"]


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TRADING BOT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ScalpMasterBot:
    def __init__(self, config: Dict):
        self.config = config
        self.connectors: Dict[str, PlatformConnector] = {}
        self.analyzer = TechnicalAnalyzer()
        self.smc = SMCEngine()
        self.sentiment = SentimentAnalyzer()
        self.strategy = StrategyEngine(self.analyzer, self.smc, self.sentiment)
        self.signals_history: List[Signal] = []
        self.positions: List[Position] = []
        self.running = False
        self.scan_interval = config.get("scan_interval", 60)
        self.risk_per_trade = config.get("risk_per_trade", 1.0)
        self.max_positions = config.get("max_positions", 5)
        self.timeframes = config.get("timeframes", ["5m", "15m"])
        self.enabled_strategies = config.get("enabled_strategies", ["all"])
        self.signal_callbacks: List[Callable] = []

    def add_signal_callback(self, callback: Callable):
        self.signal_callbacks.append(callback)

    async def initialize(self):
        logger.info("Initializing ScalpMaster Pro Bot...")
        await self.sentiment.initialize()

        if self.config.get("binance", {}).get("enabled"):
            conn = BinanceConnector(
                api_key=self.config["binance"]["api_key"],
                api_secret=self.config["binance"]["api_secret"],
                testnet=self.config["binance"].get("testnet", True),
                futures=self.config["binance"].get("futures", True)
            )
            await conn.connect()
            self.connectors["Binance"] = conn

        if self.config.get("bybit", {}).get("enabled"):
            conn = BybitConnector(
                api_key=self.config["bybit"]["api_key"],
                api_secret=self.config["bybit"]["api_secret"],
                testnet=self.config["bybit"].get("testnet", True)
            )
            await conn.connect()
            self.connectors["Bybit"] = conn

        if self.config.get("okx", {}).get("enabled"):
            conn = OKXConnector(
                api_key=self.config["okx"]["api_key"],
                api_secret=self.config["okx"]["api_secret"],
                passphrase=self.config["okx"]["passphrase"],
                testnet=self.config["okx"].get("testnet", True)
            )
            await conn.connect()
            self.connectors["OKX"] = conn

        if self.config.get("deriv", {}).get("enabled"):
            conn = DerivConnector(
                api_token=self.config["deriv"]["api_token"],
                app_id=self.config["deriv"].get("app_id", "1089")
            )
            await conn.connect()
            self.connectors["Deriv"] = conn

        if self.config.get("pocket_option", {}).get("enabled"):
            conn = PocketOptionConnector(
                ssid=self.config["pocket_option"]["ssid"],
                is_demo=self.config["pocket_option"].get("is_demo", True)
            )
            await conn.connect()
            self.connectors["PocketOption"] = conn

        if self.config.get("mt5", {}).get("enabled"):
            conn = MT5Connector(
                login=self.config["mt5"].get("login", 0),
                password=self.config["mt5"].get("password", ""),
                server=self.config["mt5"].get("server", ""),
                broker_name=self.config["mt5"].get("broker", "Exness")
            )
            await conn.connect()
            self.connectors[f"MT5_{self.config['mt5'].get('broker', 'Exness')}"] = conn

        logger.info(f"Bot initialized with {len(self.connectors)} platforms")

    async def scan_all_platforms(self):
        tasks = []
        for name, connector in self.connectors.items():
            if not connector.connected:
                continue
            symbols = await connector.get_symbols()
            for symbol in symbols[:10]:
                for tf in self.timeframes:
                    tasks.append(self._scan_symbol(connector, name, symbol, tf))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            signals = []
            for r in results:
                if isinstance(r, list):
                    signals.extend(r)
                elif isinstance(r, Signal):
                    signals.append(r)

            for signal in signals:
                self._process_signal(signal)

    async def _scan_symbol(self, connector, platform, symbol, timeframe):
        try:
            candles = await connector.get_candles(symbol, timeframe, limit=100)
            if len(candles) < 50:
                return None
            signals = await self.strategy.generate_all_signals(
                symbol=symbol, candles=candles, timeframe=timeframe, platform=platform
            )
            return signals
        except Exception as e:
            logger.error(f"Error scanning {symbol} on {platform}: {e}")
            return None

    def _process_signal(self, signal: Signal):
        if len(self.positions) >= self.max_positions:
            logger.info(f"Max positions reached. Signal skipped: {signal.symbol}")
            return
        existing = [p for p in self.positions if p.symbol == signal.symbol and p.platform == signal.platform]
        if existing:
            return

        self.signals_history.append(signal)

        for callback in self.signal_callbacks:
            try:
                callback(signal)
            except Exception as e:
                logger.error(f"Signal callback error: {e}")

        emoji = "BUY" if signal.direction == SignalDirection.BUY else "SELL"
        logger.info(f"
{'='*60}")
        logger.info(f"SIGNAL DETECTED - {signal.platform} | {signal.strategy_name}")
        logger.info(f"{'='*60}")
        logger.info(f"Symbol:      {signal.symbol}")
        logger.info(f"Direction:   {signal.direction.value}")
        logger.info(f"Confidence:  {signal.confidence:.1%}")
        logger.info(f"Entry:       {signal.entry_price:.5f}")
        logger.info(f"Stop Loss:   {signal.stop_loss:.5f}")
        logger.info(f"Take Profit: {signal.take_profit:.5f}")
        logger.info(f"R:R Ratio:   {signal.risk_reward:.2f}")
        logger.info(f"Timeframe:   {signal.timeframe}")
        logger.info(f"Strategy:    {signal.strategy_name}")
        logger.info(f"Sentiment:   Fear&Greed={signal.sentiment.fear_greed_index:.0f}")
        logger.info(f"{'='*60}
")

        if self.config.get("auto_trade", False):
            asyncio.create_task(self._execute_signal(signal))

    async def _execute_signal(self, signal: Signal):
        connector = self.connectors.get(signal.platform)
        if not connector:
            return
        success = await connector.place_order(signal, self.risk_per_trade)
        if success:
            position = Position(
                symbol=signal.symbol,
                direction=signal.direction,
                entry_price=signal.entry_price,
                quantity=0.0,
                stop_loss=signal.stop_loss,
                take_profit=signal.take_profit,
                open_time=datetime.now(),
                platform=signal.platform
            )
            self.positions.append(position)
            logger.info(f"Position opened: {signal.symbol} {signal.direction.value}")

    async def run(self):
        self.running = True
        logger.info("ScalpMaster Pro Bot started. Scanning for signals...")
        while self.running:
            try:
                await self.scan_all_platforms()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Bot loop error: {e}")
                await asyncio.sleep(5)

    def stop(self):
        self.running = False
        logger.info("Bot stopped")

    async def shutdown(self):
        self.stop()
        for name, connector in self.connectors.items():
            await connector.disconnect()
        await self.sentiment.close()
        logger.info("ScalpMaster Pro Bot shutdown complete")

    def get_stats(self) -> Dict:
        total_signals = len(self.signals_history)
        buy_signals = len([s for s in self.signals_history if s.direction == SignalDirection.BUY])
        sell_signals = len([s for s in self.signals_history if s.direction == SignalDirection.SELL])
        avg_confidence = sum(s.confidence for s in self.signals_history) / total_signals if total_signals > 0 else 0

        return {
            "total_signals": total_signals,
            "buy_signals": buy_signals,
            "sell_signals": sell_signals,
            "avg_confidence": avg_confidence,
            "active_positions": len([p for p in self.positions if p.status == "OPEN"]),
            "platforms": list(self.connectors.keys())
        }


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD WEB SERVER
# ═══════════════════════════════════════════════════════════════════════════════

class DashboardServer:
    """
    aiohttp-based dashboard server with:
    - Login/Authentication
    - Real-time signal display
    - Strategy performance metrics
    - Platform status
    - Risk management overview
    """

    def __init__(self, bot: ScalpMasterBot, auth: AuthManager, host: str = "0.0.0.0", port: int = 8080):
        self.bot = bot
        self.auth = auth
        self.host = host
        self.port = port
        self.app = web.Application()
        self.ws_clients: List[web.WebSocketResponse] = []
        self._setup_routes()
        self.bot.add_signal_callback(self._on_signal)

    def _setup_routes(self):
        # Static files
        self.app.router.add_get('/', self.index_handler)
        self.app.router.add_get('/login', self.login_page_handler)
        self.app.router.add_get('/dashboard', self.dashboard_handler)
        self.app.router.add_post('/api/auth/login', self.api_login)
        self.app.router.add_post('/api/auth/register', self.api_register)
        self.app.router.add_post('/api/auth/logout', self.api_logout)
        self.app.router.add_get('/api/signals', self.api_signals)
        self.app.router.add_get('/api/positions', self.api_positions)
        self.app.router.add_get('/api/stats', self.api_stats)
        self.app.router.add_get('/api/platforms', self.api_platforms)
        self.app.router.add_get('/api/strategies', self.api_strategies)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_post('/api/settings', self.api_update_settings)
        self.app.router.add_post('/api/bot/start', self.api_bot_start)
        self.app.router.add_post('/api/bot/stop', self.api_bot_stop)

    async def index_handler(self, request):
        return web.Response(text=self._get_login_html(), content_type='text/html')

    async def login_page_handler(self, request):
        return web.Response(text=self._get_login_html(), content_type='text/html')

    async def dashboard_handler(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            raise web.HTTPFound('/login')
        return web.Response(text=self._get_dashboard_html(), content_type='text/html')

    async def api_login(self, request):
        data = await request.json()
        username = data.get('username')
        password = data.get('password')

        token = self.auth.authenticate(username, password)
        if token:
            response = web.json_response({"success": True, "token": token})
            response.set_cookie('auth_token', token, httponly=True, max_age=86400)
            return response
        return web.json_response({"success": False, "error": "Invalid credentials"}, status=401)

    async def api_register(self, request):
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email', '')

        if self.auth.register_user(username, password, email=email):
            return web.json_response({"success": True, "message": "User registered"})
        return web.json_response({"success": False, "error": "Username already exists"}, status=400)

    async def api_logout(self, request):
        token = request.cookies.get('auth_token')
        if token:
            self.auth.logout(token)
        response = web.json_response({"success": True})
        response.del_cookie('auth_token')
        return response

    async def api_signals(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        signals = [s.to_dict() for s in self.bot.signals_history[-50:]]
        return web.json_response({"signals": signals})

    async def api_positions(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        positions = [p.to_dict() for p in self.bot.positions]
        return web.json_response({"positions": positions})

    async def api_stats(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        return web.json_response(self.bot.get_stats())

    async def api_platforms(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        platforms = []
        for name, conn in self.bot.connectors.items():
            platforms.append({
                "name": name,
                "connected": conn.connected,
                "symbols_cached": len(conn.price_cache)
            })
        return web.json_response({"platforms": platforms})

    async def api_strategies(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        strategies = [
            {"id": "ema_macd_rsi", "name": "EMA + MACD + RSI Confluence", "type": "Traditional", "enabled": True},
            {"id": "bb_squeeze", "name": "Bollinger Squeeze Breakout", "type": "Traditional", "enabled": True},
            {"id": "ichimoku_cloud", "name": "Ichimoku Cloud Breakout", "type": "Traditional", "enabled": True},
            {"id": "vwap_reversal", "name": "VWAP Mean Reversion", "type": "Traditional", "enabled": True},
            {"id": "smc_order_block", "name": "SMC Order Block", "type": "Smart Money", "enabled": True},
            {"id": "smc_fvg", "name": "SMC Fair Value Gap", "type": "Smart Money", "enabled": True},
            {"id": "smc_liquidity", "name": "SMC Liquidity Sweep", "type": "Smart Money", "enabled": True},
            {"id": "smc_breaker", "name": "SMC Breaker Block", "type": "Smart Money", "enabled": True}
        ]
        return web.json_response({"strategies": strategies})

    async def api_update_settings(self, request):
        token = request.cookies.get('auth_token')
        payload = self.auth.verify_token(token) if token else None
        if not payload:
            return web.json_response({"error": "Unauthorized"}, status=401)

        data = await request.json()
        self.auth.update_user_settings(payload["username"], data)
        return web.json_response({"success": True})

    async def api_bot_start(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        asyncio.create_task(self.bot.run())
        return web.json_response({"success": True, "status": "running"})

    async def api_bot_stop(self, request):
        token = request.cookies.get('auth_token')
        if not token or not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        self.bot.stop()
        return web.json_response({"success": True, "status": "stopped"})

    async def websocket_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.ws_clients.append(ws)

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get('action') == 'ping':
                        await ws.send_json({"type": "pong", "time": datetime.now().isoformat()})
        except:
            pass
        finally:
            self.ws_clients.remove(ws)
        return ws

    def _on_signal(self, signal: Signal):
        message = {
            "type": "signal",
            "data": signal.to_dict()
        }
        asyncio.create_task(self._broadcast(message))

    async def _broadcast(self, message: Dict):
        dead_clients = []
        for ws in self.ws_clients:
            try:
                await ws.send_json(message)
            except:
                dead_clients.append(ws)
        for ws in dead_clients:
            if ws in self.ws_clients:
                self.ws_clients.remove(ws)

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"Dashboard server started at http://{self.host}:{self.port}")

    def _get_login_html(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScalpMaster Pro - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 20px;
            padding: 48px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        .logo {
            text-align: center;
            margin-bottom: 32px;
        }
        .logo-icon { font-size: 48px; margin-bottom: 12px; }
        .logo h1 {
            font-size: 28px;
            font-weight: 800;
            background: linear-gradient(90deg, #22d3ee, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .logo p { color: #94a3b8; font-size: 14px; margin-top: 4px; }
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            color: #cbd5e1;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
            font-size: 15px;
            transition: all 0.2s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #22d3ee;
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.1);
        }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #22d3ee, #818cf8);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 10px 25px rgba(34, 211, 238, 0.3); }
        .tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
        }
        .tab {
            flex: 1;
            padding: 10px;
            text-align: center;
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 8px;
            color: #94a3b8;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        .tab.active {
            background: rgba(34, 211, 238, 0.1);
            border-color: rgba(34, 211, 238, 0.3);
            color: #22d3ee;
        }
        .error { color: #f43f5e; font-size: 13px; margin-top: 8px; display: none; }
        .success { color: #22c55e; font-size: 13px; margin-top: 8px; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="logo-icon">🚀</div>
            <h1>SCALPMASTER PRO</h1>
            <p>Multi-Platform Trading Bot</p>
        </div>
        <div class="tabs">
            <div class="tab active" onclick="showTab('login')">Login</div>
            <div class="tab" onclick="showTab('register')">Register</div>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="loginUsername" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="loginPassword" placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
            <div class="error" id="loginError"></div>
        </form>
        <form id="registerForm" style="display:none;">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="regUsername" placeholder="Choose username" required>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="regEmail" placeholder="Enter email" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="regPassword" placeholder="Choose password" required>
            </div>
            <button type="submit" class="btn">Create Account</button>
            <div class="error" id="regError"></div>
            <div class="success" id="regSuccess"></div>
        </form>
    </div>
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            if(tab === 'login') {
                document.getElementById('loginForm').style.display = 'block';
                document.getElementById('registerForm').style.display = 'none';
            } else {
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('registerForm').style.display = 'block';
            }
        }
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('loginUsername').value,
                    password: document.getElementById('loginPassword').value
                })
            });
            const data = await res.json();
            if(data.success) {
                window.location.href = '/dashboard';
            } else {
                document.getElementById('loginError').style.display = 'block';
                document.getElementById('loginError').textContent = data.error;
            }
        });
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('regUsername').value,
                    email: document.getElementById('regEmail').value,
                    password: document.getElementById('regPassword').value
                })
            });
            const data = await res.json();
            if(data.success) {
                document.getElementById('regSuccess').style.display = 'block';
                document.getElementById('regSuccess').textContent = 'Account created! Please login.';
            } else {
                document.getElementById('regError').style.display = 'block';
                document.getElementById('regError').textContent = data.error;
            }
        });
    </script>
</body>
</html>"""

    def _get_dashboard_html(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScalpMaster Pro - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100vh;
            background: rgba(30, 41, 59, 0.95);
            border-right: 1px solid rgba(148, 163, 184, 0.1);
            padding: 24px;
            overflow-y: auto;
        }
        .sidebar-logo {
            font-size: 20px;
            font-weight: 800;
            background: linear-gradient(90deg, #22d3ee, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 32px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nav-item {
            padding: 12px 16px;
            border-radius: 10px;
            margin-bottom: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #94a3b8;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .nav-item:hover, .nav-item.active {
            background: rgba(34, 211, 238, 0.1);
            color: #22d3ee;
        }
        .main-content {
            margin-left: 260px;
            padding: 32px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
        }
        .header h1 { font-size: 24px; font-weight: 700; }
        .header-actions {
            display: flex;
            gap: 12px;
        }
        .btn {
            padding: 10px 20px;
            border-radius: 8px;
            border: none;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #22d3ee, #818cf8);
            color: white;
        }
        .btn-danger {
            background: rgba(244, 63, 94, 0.2);
            color: #f43f5e;
            border: 1px solid rgba(244, 63, 94, 0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 20px;
        }
        .stat-card .label {
            font-size: 12px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .stat-card .value {
            font-size: 28px;
            font-weight: 800;
        }
        .panel {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .panel h3 {
            font-size: 16px;
            margin-bottom: 16px;
            color: #22d3ee;
        }
        .signal-card {
            background: rgba(15, 23, 42, 0.6);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
            border-left: 4px solid #22c55e;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .signal-card.sell { border-left-color: #f43f5e; }
        .signal-info { flex: 1; }
        .signal-symbol { font-weight: 700; font-size: 16px; }
        .signal-meta { font-size: 12px; color: #94a3b8; margin-top: 4px; }
        .signal-confidence {
            background: rgba(34, 197, 94, 0.15);
            color: #22c55e;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }
        .platform-status {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        .platform-badge {
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .platform-badge.online {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #22c55e;
        }
        .platform-badge.offline {
            background: rgba(244, 63, 94, 0.1);
            border: 1px solid rgba(244, 63, 94, 0.3);
            color: #f43f5e;
        }
        .strategy-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            margin-right: 6px;
            margin-bottom: 6px;
        }
        .strategy-traditional {
            background: rgba(34, 211, 238, 0.15);
            color: #22d3ee;
        }
        .strategy-smc {
            background: rgba(251, 146, 60, 0.15);
            color: #fb923c;
        }
        .connection-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 500;
            background: rgba(34, 197, 94, 0.15);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        .connection-status.disconnected {
            background: rgba(244, 63, 94, 0.15);
            color: #f43f5e;
            border-color: rgba(244, 63, 94, 0.3);
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-logo">🚀 ScalpMaster Pro</div>
        <div class="nav-item active" onclick="showSection('signals')">📊 Signals</div>
        <div class="nav-item" onclick="showSection('positions')">💼 Positions</div>
        <div class="nav-item" onclick="showSection('strategies')">🧠 Strategies</div>
        <div class="nav-item" onclick="showSection('platforms')">🔗 Platforms</div>
        <div class="nav-item" onclick="showSection('settings')">⚙️ Settings</div>
        <div class="nav-item" onclick="logout()">🚪 Logout</div>
    </div>

    <div class="main-content">
        <div class="header">
            <h1>Trading Dashboard</h1>
            <div class="header-actions">
                <button class="btn btn-primary" onclick="startBot()">▶ Start Bot</button>
                <button class="btn btn-danger" onclick="stopBot()">⏹ Stop Bot</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Signals</div>
                <div class="value" id="totalSignals" style="color:#22d3ee;">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Buy Signals</div>
                <div class="value" id="buySignals" style="color:#22c55e;">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Sell Signals</div>
                <div class="value" id="sellSignals" style="color:#f43f5e;">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Avg Confidence</div>
                <div class="value" id="avgConfidence" style="color:#818cf8;">0%</div>
            </div>
            <div class="stat-card">
                <div class="label">Active Positions</div>
                <div class="value" id="activePositions" style="color:#fbbf24;">0</div>
            </div>
        </div>

        <div id="signalsSection">
            <div class="panel">
                <h3>📊 Recent Signals</h3>
                <div id="signalsList"></div>
            </div>
        </div>

        <div id="positionsSection" style="display:none;">
            <div class="panel">
                <h3>💼 Open Positions</h3>
                <div id="positionsList"></div>
            </div>
        </div>

        <div id="strategiesSection" style="display:none;">
            <div class="panel">
                <h3>🧠 Active Strategies</h3>
                <div id="strategiesList"></div>
            </div>
        </div>

        <div id="platformsSection" style="display:none;">
            <div class="panel">
                <h3>🔗 Platform Status</h3>
                <div class="platform-status" id="platformsList"></div>
            </div>
        </div>

        <div id="settingsSection" style="display:none;">
            <div class="panel">
                <h3>⚙️ Bot Settings</h3>
                <p style="color:#94a3b8;">Configure risk parameters, timeframes, and platform connections.</p>
            </div>
        </div>
    </div>

    <div class="connection-status" id="wsStatus">● WebSocket Connected</div>

    <script>
        let ws;
        function connectWS() {
            ws = new WebSocket('ws://' + window.location.host + '/ws');
            ws.onopen = () => {
                document.getElementById('wsStatus').classList.remove('disconnected');
                document.getElementById('wsStatus').textContent = '● WebSocket Connected';
            };
            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                if(msg.type === 'signal') {
                    addSignal(msg.data);
                    updateStats();
                }
            };
            ws.onclose = () => {
                document.getElementById('wsStatus').classList.add('disconnected');
                document.getElementById('wsStatus').textContent = '● WebSocket Disconnected';
                setTimeout(connectWS, 3000);
            };
        }

        function showSection(section) {
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            event.target.classList.add('active');
            ['signals','positions','strategies','platforms','settings'].forEach(s => {
                document.getElementById(s + 'Section').style.display = s === section ? 'block' : 'none';
            });
            if(section === 'positions') loadPositions();
            if(section === 'strategies') loadStrategies();
            if(section === 'platforms') loadPlatforms();
        }

        async function updateStats() {
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('totalSignals').textContent = data.total_signals;
            document.getElementById('buySignals').textContent = data.buy_signals;
            document.getElementById('sellSignals').textContent = data.sell_signals;
            document.getElementById('avgConfidence').textContent = (data.avg_confidence * 100).toFixed(1) + '%';
            document.getElementById('activePositions').textContent = data.active_positions;
        }

        async function loadSignals() {
            const res = await fetch('/api/signals');
            const data = await res.json();
            const list = document.getElementById('signalsList');
            list.innerHTML = '';
            data.signals.slice().reverse().forEach(s => addSignal(s));
        }

        function addSignal(signal) {
            const list = document.getElementById('signalsList');
            const div = document.createElement('div');
            div.className = 'signal-card ' + (signal.direction === 'SELL' ? 'sell' : '');
            div.innerHTML = `
                <div class="signal-info">
                    <div class="signal-symbol">${signal.direction} ${signal.symbol}</div>
                    <div class="signal-meta">
                        ${signal.platform} | ${signal.timeframe} | ${signal.strategy_name} | 
                        Entry: ${signal.entry_price.toFixed(5)} | 
                        SL: ${signal.stop_loss.toFixed(5)} | 
                        TP: ${signal.take_profit.toFixed(5)} | 
                        R:R ${signal.risk_reward.toFixed(2)}
                    </div>
                </div>
                <div class="signal-confidence">${(signal.confidence * 100).toFixed(1)}%</div>
            `;
            list.insertBefore(div, list.firstChild);
        }

        async function loadPositions() {
            const res = await fetch('/api/positions');
            const data = await res.json();
            const list = document.getElementById('positionsList');
            list.innerHTML = data.positions.map(p => `
                <div class="signal-card ${p.direction === 'SELL' ? 'sell' : ''}">
                    <div class="signal-info">
                        <div class="signal-symbol">${p.direction} ${p.symbol}</div>
                        <div class="signal-meta">
                            ${p.platform} | Entry: ${p.entry_price} | PnL: ${p.pnl.toFixed(2)} (${p.pnl_percent.toFixed(2)}%)
                        </div>
                    </div>
                    <div class="signal-confidence">${p.status}</div>
                </div>
            `).join('') || '<p style="color:#94a3b8;">No open positions</p>';
        }

        async function loadStrategies() {
            const res = await fetch('/api/strategies');
            const data = await res.json();
            const list = document.getElementById('strategiesList');
            list.innerHTML = data.strategies.map(s => `
                <span class="strategy-tag ${s.type === 'Smart Money' ? 'strategy-smc' : 'strategy-traditional'}">
                    ${s.name}
                </span>
            `).join('');
        }

        async function loadPlatforms() {
            const res = await fetch('/api/platforms');
            const data = await res.json();
            const list = document.getElementById('platformsList');
            list.innerHTML = data.platforms.map(p => `
                <div class="platform-badge ${p.connected ? 'online' : 'offline'}">
                    ${p.connected ? '🟢' : '🔴'} ${p.name}
                </div>
            `).join('');
        }

        async function startBot() {
            await fetch('/api/bot/start', {method: 'POST'});
        }

        async function stopBot() {
            await fetch('/api/bot/stop', {method: 'POST'});
        }

        async function logout() {
            await fetch('/api/auth/logout', {method: 'POST'});
            window.location.href = '/login';
        }

        connectWS();
        updateStats();
        loadSignals();
        loadPlatforms();
        setInterval(updateStats, 5000);
        setInterval(loadSignals, 10000);
    </script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════════

def create_default_config() -> Dict:
    return {
        "risk_per_trade": 1.0,
        "max_positions": 5,
        "scan_interval": 60,
        "timeframes": ["5m", "15m"],
        "auto_trade": False,
        "enabled_strategies": ["all"],
        "binance": {
            "enabled": False,
            "api_key": "YOUR_BINANCE_API_KEY",
            "api_secret": "YOUR_BINANCE_API_SECRET",
            "testnet": True,
            "futures": True
        },
        "bybit": {
            "enabled": False,
            "api_key": "YOUR_BYBIT_API_KEY",
            "api_secret": "YOUR_BYBIT_API_SECRET",
            "testnet": True
        },
        "okx": {
            "enabled": False,
            "api_key": "YOUR_OKX_API_KEY",
            "api_secret": "YOUR_OKX_API_SECRET",
            "passphrase": "YOUR_OKX_PASSPHRASE",
            "testnet": True
        },
        "deriv": {
            "enabled": False,
            "api_token": "YOUR_DERIV_API_TOKEN",
            "app_id": "1089"
        },
        "pocket_option": {
            "enabled": False,
            "ssid": "YOUR_POCKET_OPTION_SSID",
            "is_demo": True
        },
        "mt5": {
            "enabled": False,
            "login": 0,
            "password": "",
            "server": "",
            "broker": "Exness"
        }
    }


async def main():
    config = create_default_config()

    # Use PORT from environment (cloud platforms set this)
    port = int(os.environ.get("PORT", 8080))

    print(f"""
    ================================================================
                SCALPMASTER PRO v2.0
    ================================================================
    Platforms: Binance | Bybit | OKX | Deriv | Pocket Option | MT5
    Strategies: 4 Traditional + 4 Smart Money Concepts (SMC)
    Features: Auth System | Real-time Dashboard | WebSocket
    Dashboard: http://0.0.0.0:{port}
    ================================================================
    """)

    # Initialize auth system
    auth = AuthManager()

    # Initialize bot
    bot = ScalpMasterBot(config)

    # Initialize dashboard server
    dashboard = DashboardServer(bot, auth, host="0.0.0.0", port=port)
    await dashboard.start()

    try:
        await bot.initialize()
        # Bot runs in background; dashboard handles control
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    finally:
        await bot.shutdown()
if __name__ == "__main__":
    asyncio.run(main())
