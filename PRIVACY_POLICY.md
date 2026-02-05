# Privacy Policy for Gmail Messages (OAuth) TRMNL Plugin

**Last Updated:** 2026-02-05

## 1. Information We Collect

Through Google OAuth authentication, our plugin collects:

- **Your email address** (from Google profile)
- **Gmail message metadata** including:
  - Sender name and email address
  - Email subject lines
  - Email timestamps
  - Email labels and flags (read/unread, starred status)
  - Message IDs

**Important:** We **DO NOT** collect:
- Email body/content
- Email attachments
- Passwords or login credentials
- Financial or payment information
- Any other personal data beyond what's listed above

## 2. Why We Need This Information

The data is used **exclusively** to provide these features:

- **Fetching email metadata** (via `gmail.readonly` scope):
  - To display your inbox with sender, subject, and timestamp
  - To filter emails by status (read/unread, starred)
  - To organize emails by labels/categories

- **Identifying your account** (via `userinfo.email` scope):
  - To verify your identity
  - To ensure data belongs to the correct user

## 3. How We Process Your Data

Our technical flow:

1. **Authentication:** You grant OAuth access via Google's secure system
2. **API Requests:** We fetch data using Gmail API v1 with HTTPS encryption
3. **Data Processing:** We parse only the metadata headers (From, Subject, Date)
4. **Temporary Caching:** Email metadata is cached in memory for **5 minutes** to improve performance
5. **Automatic Deletion:** Cached data is automatically purged after 5 minutes

## 4. Data Storage & Retention

- **Storage Type:** In-memory cache (not written to disk)
- **Cache Duration:** Maximum 5 minutes
- **Retention Policy:** 
  - Data is automatically deleted after 5 minutes
  - Cache is cleared when you log out
  - No persistent storage of email data
- **Encryption:** All data is transmitted via HTTPS/TLS 1.2+ encryption

## 5. Data Sharing & Third Parties

We **do not**:
- Sell, rent, or trade your data
- Share your data with advertisers
- Use your data for marketing purposes
- Share your data with third parties except where required by law

**Service Providers:**
- **Google Cloud Platform:** For OAuth authentication and API access
- **Our Hosting Provider:** For application infrastructure

## 6. Your Rights & Controls

You have full control over your data:

- **Revoke Access:** Any time via [Google Security Settings](https://myaccount.google.com/permissions)

## 7. Security Measures

We implement:
- OAuth 2.0 secure authentication
- HTTPS encryption for all data transfers
- Automatic cache expiration (5 minutes)

## 8. Scope Justification

| Google Scope | Why We Need It | What We Do With It |
|-------------|----------------|-------------------|
| `gmail.readonly` | Fetch email metadata | Display sender, subject, timestamp with 5-min cache |
| `userinfo.email` | Identify your account | Ensure data belongs to correct user |

## 9. Compliance

We comply with:
- **Google API Services User Data Policy**
- **GDPR** (for EU users): Limited storage duration (5-min cache)
- **CCPA** (for California users): We honor "Do Not Sell" requests

## 10. Contact Information

For privacy questions or concerns:
- **Email:** wardje@gmail.com
- **Response Time:** Within 7 business days