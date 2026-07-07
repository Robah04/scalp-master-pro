# ScalpMaster Pro v2.0

Multi-platform scalping signal scanner with Smart Money Concepts (SMC), built-in authentication, and a real-time dashboard.

## Features

- **8 Trading Strategies**: 4 Traditional TA + 4 Smart Money Concepts
- **6 Platform Connectors**: Binance, Bybit, OKX, Deriv, Pocket Option, MT5
- **Real-time Dashboard**: Live signals, positions, stats via WebSocket
- **JWT Authentication**: Secure login with user management
- **Low Risk**: 1-2% per trade, strict stop-losses, min 1.5:1 R:R

## Quick Start

### Local Development
```bash
pip install -r requirements.txt
python scalp_master_pro.py
```
Open http://localhost:8080

### Deploy to Cloud

#### Option 1: Koyeb (Recommended - Free, 24/7)
1. Push this repo to GitHub
2. Go to [koyeb.com](https://www.koyeb.com) → Sign up with GitHub
3. Create App → Select this repo
4. Set env var: `PORT=8080`
5. Click Deploy → Live!

#### Option 2: Render
1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Select this repo
4. Build: `pip install -r requirements.txt`
5. Start: `python scalp_master_pro.py`
6. Set env var: `PORT=10000`
7. Deploy!

## Default Login
- Username: `admin`
- Password: `admin123`

**Change this immediately after first login!**

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate |
| POST | `/api/auth/register` | Create account |
| GET | `/api/signals` | Recent signals |
| GET | `/api/positions` | Open positions |
| GET | `/api/stats` | Bot statistics |
| POST | `/api/bot/start` | Start scanning |
| POST | `/api/bot/stop` | Stop scanning |
| WS | `/ws` | Real-time signals |

## Strategies

### Traditional
1. EMA + MACD + RSI Confluence
2. Bollinger Squeeze Breakout
3. Ichimoku Cloud Breakout
4. VWAP Mean Reversion

### Smart Money Concepts (SMC)
5. Order Block (OB) Trading
6. Fair Value Gap (FVG)
7. Liquidity Sweep
8. Breaker Block

## Risk Disclaimer
Trading involves substantial risk of loss. Never trade with money you cannot afford to lose. Start with `auto_trade=False` and test thoroughly before live trading.

## License
MIT
