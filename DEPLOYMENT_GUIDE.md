# Vigilant Canary - Deployment Guide

## Issues Fixed

This guide resolves the deployment issues with history area and port scanning sections.

### Problems Addressed
1. **Duplicate API route definitions** - Removed conflicting routes that were preventing proper endpoint registration
2. **Port parsing mismatch** - Backend now properly handles port ranges ("1-1000") and comma-separated lists ("21,22,80") from the frontend
3. **Database initialization** - Confirmed database schema creation and data retrieval methods
4. **Environment configuration** - Added proper .env files for development and production

## Development Setup

### Backend Setup
```bash
cd vuln/backend
pip install -r requirements.txt
export FRONTEND_URL=http://localhost:5173
python run_server.py
```

The backend will run on `http://localhost:8007`

### Frontend Setup
```bash
cd vuln/frontend
npm install
npm run dev
```

The frontend will run on `http://localhost:5173`

## API Endpoints

### History Endpoints
- **GET /api/v1/recent-scans** - Get vulnerability scans (limit: 10-50)
- **GET /api/v1/recent-port-scans** - Get port scan results (shows all open ports found)
- **GET /api/v1/recent-subdomain-scans** - Get subdomain enumeration results

### Scanning Endpoints
- **POST /api/v1/scan-ports** - Perform port scan
  - Accepts port ranges: "1-1000"
  - Accepts port lists: "21,22,80,443"
  - Returns open ports with service information

## Troubleshooting

### History Not Loading
1. Ensure backend is running on port 8007
2. Check browser console for API errors
3. Verify CORS is enabled (should be automatic)
4. Database file should be at: `vuln/backend/scan_history.db`

### Port Scanning Not Working
1. Ensure target host is valid (IP or hostname)
2. Common ports scanned by default: 21, 22, 80, 443, 3306, 8080
3. Custom port ranges are supported (e.g., "1-1000")
4. Socket-based scanning is used as fallback if nmap unavailable
5. Check network connectivity to target

### Empty History
- History data comes from actual scans performed
- First-time deployments will show empty history
- Run a test scan to see data in history

## Environment Variables

### Backend (.env)
```
FRONTEND_URL=http://localhost:5173
API_PREFIX=/api/v1
DATABASE_PATH=scan_history.db
```

### Frontend (.env)
```
VITE_API_URL=http://localhost:8007/api/v1
```

For production, use `.env.production` files with appropriate URLs.

## Database

The application uses SQLite for scan history:
- Location: `vuln/backend/scan_history.db`
- Tables: `scans`, `port_scans`, `subdomains`
- Auto-initializes on first run

To reset database:
```bash
cd vuln/backend
rm scan_history.db
python run_server.py
```

## Testing

To test the endpoints manually:

```bash
# Test port scanning
curl -X POST http://localhost:8007/api/v1/scan-ports \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "ports": "21,22,80,443"}'

# Get recent scans
curl http://localhost:8007/api/v1/recent-scans?limit=20

# Get recent port scans
curl http://localhost:8007/api/v1/recent-port-scans?limit=20
```

## Production Deployment

1. Use `.env.production` files with production URLs
2. Set `FRONTEND_URL` to your production domain
3. Set `VITE_API_URL` to `https://your-domain.com/api/v1`
4. Run backend with appropriate host binding:
   ```bash
   python run_server.py
   ```
   Or use environment variables to configure host/port

5. Build frontend for production:
   ```bash
   npm run build
   ```

6. Serve frontend static files with your web server (nginx, Apache, etc.)

## Known Limitations

- Port scanning uses socket-based TCP connections (non-invasive)
- NMap acceleration available if installed
- Scan results are stored in SQLite database
- No authentication/authorization in current version

## Support

For issues or questions, check:
1. Browser console for frontend errors
2. Server logs for backend errors
3. Ensure all endpoints respond with proper CORS headers
