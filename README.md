# TRMNL Email Messages Plugin

Display your recent emails directly on your TRMNL e-ink display with real-time IMAP synchronization.

<!-- PLUGIN_STATS_START -->
<!-- PLUGIN_STATS_END-->

## 📧 What It Does

This plugin connects to your email account via IMAP and displays your most recent messages. Perfect for keeping an eye on important emails without constantly checking your phone or computer.

## 🚀 Quick Start

1. **Choose your email provider** (Gmail, Outlook, Yahoo, iCloud, or Custom)
2. **Generate an app password** (required for security)
3. **Configure your preferences** (filters, display options, etc.)
4. **Deploy the backend** to read your emails

## 🏗️ Backend Deployment

This plugin requires a backend service to fetch emails via IMAP.

### Deploy with Docker

```bash
# Clone the repository
git clone https://github.com/ExcuseMi/trmnl-email-messages-plugin
cd trmnl-email-messages-plugin

# Build and run
docker-compose up -d
```

### Environment Variables

```env
ENABLE_IP_WHITELIST=true    # Restrict access to TRMNL IPs only
IP_REFRESH_HOURS=24         # How often to refresh IP whitelist
LOG_LEVEL=INFO              # Logging verbosity
```

### Requirements

- **Python 3.13+**
- **Docker** (recommended) or Python environment
- **Open port 5000** (or configure your own)

## 🔧 How It Works

```
TRMNL Display → Polls Backend → Backend connects to Email via IMAP → Fetches messages → Returns to TRMNL → Displays on screen
```

1. **TRMNL polls your backend** every refresh interval
2. **Backend connects** to your email server using IMAP
3. **Fetches recent messages** based on your filters
4. **Returns data** to TRMNL in JSON format
5. **Display renders** emails using the Liquid template

## 📊 API Response Format

```json
{
  "success": true,
  "email": "user@example.com",
  "folder": "INBOX",
  "count": 10,
  "messages": [
    {
      "sender": "John Doe",
      "sender_email": "john@example.com",
      "subject": "Meeting Tomorrow",
      "timestamp": "2024-12-18T10:30:00+00:00",
      "msg_id": "12345",
      "read": false,
      "flagged": true
    }
  ],
  "fetched_at": "2024-12-18T15:30:00+00:00"
}
```

## 🎨 Display Features

### Ungrouped Mode
```
10:30 AM · john@example.com
  Meeting Tomorrow

Dec 17 · boss@company.com
  Quarterly Report Ready
```

### Grouped Mode
```
Today
  10:30 AM · john@example.com
    Meeting Tomorrow
  2:15 PM · team@company.com
    Quick Question

Yesterday
  9:00 AM · boss@company.com
    Quarterly Report Ready
```

## ⚡ Performance

- **Fast fetching** - Optimized IMAP queries with batch flag fetching
- **Concurrent requests** - Handles multiple simultaneous requests (4 workers)
- **Smart caching** - IP whitelist cached for 24 hours
- **Efficient** - ~4 seconds to fetch 30 messages

## 🔒 Security & Privacy

- **App passwords only** - Never use your main email password
- **IP whitelisting** - Optional restriction to TRMNL servers only
- **Direct connection** - Backend connects directly to email server
- **No data storage** - Messages are fetched in real-time, not stored
- **SSL/TLS** - All connections encrypted (port 993)

## 🐛 Troubleshooting

### "Authentication failed"
- Ensure you're using an **app password**, not your regular password
- Verify 2FA is enabled (required for app passwords)
- Check that IMAP is enabled for your account

### Outlook Issues
- New Outlook accounts may have limited IMAP support
- Approve connection in [account activity](https://account.live.com/activity)
- Wait 20-30 minutes after creating app password


## 📄 License

MIT License - See LICENSE file for details


<!-- PLUGIN_STATS_START -->
## 🚀 TRMNL Plugin

*Last updated: 2025-12-19 01:22:01 UTC*


## 🔒 Plugin ID: 198482

**Status**: ⏳ Not yet published on TRMNL or API unavailable

This plugin is configured but either hasn't been published to the TRMNL marketplace yet or the API is temporarily unavailable.

**Plugin URL**: https://usetrmnl.com/recipes/198482

---

<!-- PLUGIN_STATS_END -->
