# Vigilant Canary - Deployment Issues Resolution

## Issues Identified and Fixed

### 1. **Duplicate Route Definitions (CRITICAL)**

**Problem:**
- The `/recent-scans` endpoint was defined twice in `routes_full.py` (lines 208 and 1295)
- The `/recent-port-scans` endpoint was defined twice (lines 331 and 1678)
- This caused routing conflicts, with later definitions overriding earlier ones

**Fix Applied:**
- Removed the earlier duplicate route definitions (lines 208-223 and 331-347)
- Kept the more robust implementations with proper error handling (lines 1295 and 1678)
- This ensures consistent, reliable endpoint behavior

**Files Modified:**
- `vuln/backend/app/api/routes_full.py`

---

### 2. **Port Parsing Mismatch (CRITICAL)**

**Problem:**
- Frontend sends port parameters as strings: `"21,22,80,443"` or `"1-1000"`
- Backend `PortScanRequest` schema expected `Optional[List[int]]`
- Port ranges and comma-separated lists were not being parsed correctly

**Fix Applied:**
- Updated `PortScanRequest` schema to accept `ports: Optional[str | List[int]]`
- Added `parse_ports()` helper function that handles:
  - Comma-separated ports: `"21,22,80,443"` → `[21, 22, 80, 443]`
  - Port ranges: `"1-1000"` → `[1, 2, 3, ..., 1000]`
  - Single ports: `"80"` → `[80]`
  - Lists: `[21, 22, 80]` → `[21, 22, 80]`
  - Mixed ranges: `"21-22,80,443-445"` → `[21, 22, 80, 443, 444, 445]`

**Files Modified:**
- `vuln/backend/app/models/schemas.py` - Updated PortScanRequest schema
- `vuln/backend/app/api/routes_full.py` - Added parse_ports() function and updated scan-ports endpoint

---

### 3. **History Endpoints Configuration**

**Problem:**
- History area wasn't loading because endpoints were returning data with inconsistent field names
- Subdomain scans endpoint might not have been properly registered

**Verification & Fixes:**
- Confirmed `/recent-scans` endpoint returns proper fields:
  - `id`, `timestamp`, `target_url`, `scan_types`, `status`, `total_findings`, `risk_status`
- Confirmed `/recent-port-scans` endpoint returns:
  - `id`, `timestamp`, `target_host`, `scanned_ports`, `open_ports`, `scan_method`, `status`, `open_count`
- Confirmed `/recent-subdomain-scans` endpoint is properly defined
- All endpoints have error handling that returns empty results instead of errors

**Files Verified:**
- `vuln/backend/app/services/scan_history.py` - Database query methods
- `vuln/backend/app/api/routes_full.py` - Endpoint implementations

---

### 4. **Frontend API Configuration**

**Problem:**
- No environment configuration files for different deployment scenarios

**Fix Applied:**
- Created `.env.example` files with default configurations
- Created `.env.production` files with production-ready settings
- Configured proper API URLs for both development and production:
  - **Development:** `http://localhost:8007/api/v1`
  - **Production:** `/api/v1` (relative URL for same-origin requests)

**Files Created:**
- `vuln/backend/.env.example`
- `vuln/backend/.env.production`
- `vuln/frontend/.env.example`
- `vuln/frontend/.env.production`

---

## Summary of Changes

### Backend (`vuln/backend/`)

1. **routes_full.py**
   - Removed duplicate `/recent-scans` endpoint definition
   - Removed duplicate `/recent-port-scans` endpoint definition
   - Added `parse_ports()` helper function to handle port specifications
   - Updated `/scan-ports` endpoint to:
     - Parse port ranges (e.g., "1-1000")
     - Parse comma-separated ports (e.g., "21,22,80")
     - Handle mixed formats (e.g., "21-22,80,443-445")
     - Use common ports as fallback for invalid inputs

2. **models/schemas.py**
   - Updated `PortScanRequest.ports` field to accept `Optional[str | List[int]]`
   - Updated field description to document supported formats

3. **.env.example & .env.production**
   - Created configuration templates for different environments

### Frontend (`vuln/frontend/`)

1. **.env.example & .env.production**
   - Created environment configuration templates
   - Set production API URL to `/api/v1` for same-origin requests

### Documentation

1. **DEPLOYMENT_GUIDE.md**
   - Comprehensive deployment guide
   - API endpoint documentation
   - Troubleshooting guide
   - Configuration instructions

2. **test_deployment.py**
   - Automated test script for validating all endpoints
   - Tests for health checks, history endpoints, and port scanning
   - Validates response formats and required fields

---

## Testing the Fix

Run the automated test script to validate all changes:

```bash
cd /path/to/VigilantCanary
python test_deployment.py
```

This will test:
- ✓ API health check
- ✓ Recent scans endpoint
- ✓ Recent port scans endpoint
- ✓ Recent subdomain scans endpoint
- ✓ Port scan with common ports
- ✓ Port scan with port range
- ✓ Port scan with default ports

---

## Manual Testing

### Test Port Scanning
```bash
# Test with comma-separated ports
curl -X POST http://localhost:8007/api/v1/scan-ports \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "ports": "21,22,80,443"}'

# Test with port range
curl -X POST http://localhost:8007/api/v1/scan-ports \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "ports": "1-100"}'

# Test with default ports
curl -X POST http://localhost:8007/api/v1/scan-ports \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

### Test History Endpoints
```bash
# Get recent scans
curl 'http://localhost:8007/api/v1/recent-scans?limit=20'

# Get recent port scans
curl 'http://localhost:8007/api/v1/recent-port-scans?limit=20'

# Get recent subdomain scans
curl 'http://localhost:8007/api/v1/recent-subdomain-scans?limit=20'
```

---

## Deployment Checklist

Before deploying to production, ensure:

1. ✓ Backend configured with correct `FRONTEND_URL`
2. ✓ Frontend configured with correct `VITE_API_URL`
3. ✓ Database file path is writable
4. ✓ Port 8007 (backend) is accessible
5. ✓ Port 5173 (frontend dev) or 3000 (production) is accessible
6. ✓ All tests pass using `test_deployment.py`
7. ✓ CORS headers are properly configured (should be automatic)

---

## Known Limitations & Notes

1. **Database Location:** `scan_history.db` is created in `vuln/backend/` directory
2. **Port Limits:** Ports are limited to range 1-65535
3. **Port Range Accuracy:** For very large port ranges (>10,000), scanning may take longer
4. **Socket vs NMap:** System uses socket-based scanning by default; NMap is used if available
5. **Scan Results:** Results are stored in SQLite; no cleanup scheduled by default

---

## Files Changed Summary

| File | Change | Type |
|------|--------|------|
| routes_full.py | Removed duplicates, added parse_ports() | Bug Fix |
| schemas.py | Updated PortScanRequest schema | Enhancement |
| .env.example | Created | New |
| .env.production | Created | New |
| DEPLOYMENT_GUIDE.md | Created | Documentation |
| test_deployment.py | Created | Testing Tool |

---

## Support

If issues persist:
1. Check browser console for frontend errors
2. Check backend logs for API errors
3. Run `test_deployment.py` to identify which endpoint is failing
4. Verify database file exists at `vuln/backend/scan_history.db`
5. Ensure both backend and frontend are running on correct ports
