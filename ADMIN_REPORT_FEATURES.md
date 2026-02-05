# Admin Report Generation Features

## Overview
Added comprehensive report generation capabilities to the Hound admin panel, matching CLI functionality and enabling automated workflows.

## Implemented Features

### 1. **AuditSessionAdmin - Generate Report Action**
**Location**: [server/admin.py](server/admin.py#L426-L522)

Generate professional HTML audit reports directly from completed audit sessions.

**Usage**:
1. Navigate to `/admin/auditsession/list`
2. Select one or more completed audit sessions
3. Click **"Generate Report"** in the actions dropdown
4. Reports are generated with confirmed findings only
5. Flash message shows report path and findings count

**API Call**: `POST /sessions/{session_id}/report`

---

### 2. **ProjectAdmin - Generate Report Action**
**Location**: [server/admin.py](server/admin.py#L352-L441)

Generate reports from all confirmed findings in a project (across all audit sessions).

**Usage**:
1. Navigate to `/admin/project/list`
2. Select one or more projects
3. Click **"Generate Report"** in the actions dropdown
4. Uses the most recent completed audit session
5. Report URL is clickable in the flash message

**Features**:
- Automatically finds latest completed audit session
- Includes all confirmed findings from the project
- Shows warning if no completed sessions exist
- Generates downloadable HTML reports

---

### 3. **HypothesisAdmin - Confirm & Generate Report Action**
**Location**: [server/admin.py](server/admin.py#L1140-L1260)

Quick workflow: Confirm selected findings and immediately generate a report.

**Usage**:
1. Navigate to `/admin/hypothesis/list`
2. Select findings to confirm
3. Click **"Confirm & Generate Report"** in actions dropdown
4. Findings are marked as confirmed (confidence = 1.0)
5. Report is auto-generated and link provided

**Workflow**:
1. Confirms selected findings
2. Updates status to "confirmed" and confidence to 1.0
3. Finds latest completed audit session for the project
4. Generates HTML report
5. Provides clickable download link

---

### 4. **Auto-Generate Reports on Audit Completion**
**Location**: [server/api.py](server/api.py#L3432-L3527)

Automatically generates reports when audits complete successfully.

**Configuration**:
```bash
# Enable (default)
export AUTO_GENERATE_REPORT=true

# Disable
export AUTO_GENERATE_REPORT=false
```

**Behavior**:
- Triggers only for sync audits (`POST /audits/run-sync`)
- Generates report only if confirmed findings exist (confirmed_count > 0)
- Report path and URL included in API response
- Non-blocking: Audit success not affected by report generation failures

**Response Fields**:
```json
{
  "success": true,
  "message": "Audit completed for project 'MyProject'",
  "session_id": "audit_abc123...",
  "hypotheses_found": 15,
  "confirmed_count": 8,
  "findings": [...],
  "duration_seconds": 245.67,
  "report_path": "/home/user/.hound/reports/MyProject/audit_report_20260205_143022.html",
  "report_url": "/reports/MyProject/audit_report_20260205_143022.html"
}
```

---

### 5. **Report Static File Serving**
**Location**: [server/api.py](server/api.py#L215-L222)

Serves generated reports via HTTP for browser viewing.

**Setup**:
- Reports directory: `~/.hound/reports/`
- Mount point: `/reports`
- Access pattern: `http://localhost:8000/reports/{project_name}/{report_filename}`

**Example**:
```
http://localhost:8000/reports/MySecurityAudit/audit_report_20260205_143022.html
```

**Features**:
- Direct browser viewing of HTML reports
- Organized by project name
- Automatic directory creation
- Graceful fallback if mount fails

---

## Report Generation Workflow

### Standard Workflow (Admin Panel)
```
1. Run Audit
   └─> /admin/project/list
       └─> Select project → "Run Audit" action
       
2. Review Findings
   └─> /admin/hypothesis/list
       └─> Filter by project
       └─> Review vulnerability details
       
3. Confirm Findings (Option A: Manual)
   └─> Select findings → "Confirm" action
   
3. Confirm & Generate Report (Option B: One-Click)
   └─> Select findings → "Confirm & Generate Report" action
   └─> ✅ Done! Findings confirmed + Report generated
   
4. Generate Report (if using Option A)
   └─> /admin/auditsession/list
       └─> Select session → "Generate Report" action
       OR
   └─> /admin/project/list
       └─> Select project → "Generate Report" action
```

### Automated Workflow (API + Auto-Generate)
```
1. API Call: POST /audits/run-sync
   └─> Runs audit synchronously (may take 5-60 minutes)
   └─> Saves hypotheses to database
   └─> ✅ Auto-generates report if confirmed findings exist
   └─> Returns report_path and report_url in response

2. Access Report
   └─> Use report_url from API response
   └─> Or navigate to /reports/{project}/{filename}
```

---

## Report Configuration

### Default Settings
- **Format**: HTML (PDF and Markdown supported via CLI)
- **Title**: "Security Audit Report: {project_name}"
- **Auditors**: "Security Team"
- **Include All**: `false` (only confirmed findings)
- **Filter**: `status='confirmed' OR confidence >= 0.7`

### Report Location
```
~/.hound/reports/{project_name}/audit_report_{timestamp}.html
```

### Report Contents
1. **Executive Summary** (LLM-generated)
2. **Findings by Severity**
   - Critical
   - High
   - Medium
   - Low
3. **Code Snippets** (when available)
4. **Evidence and Reasoning**
5. **Remediation Guidance**
6. **Testing Methodology**

---

## API Reference

### Generate Report Endpoint
```http
POST /sessions/{session_id}/report
Content-Type: application/json

{
  "format": "html",
  "title": "Security Audit Report: MyProject",
  "auditors": "Security Team",
  "include_all": false
}
```

**Response**:
```json
{
  "session_id": "audit_abc123...",
  "project_name": "MyProject",
  "format": "html",
  "total_findings": 8,
  "output_path": "/home/user/.hound/reports/MyProject/audit_report_20260205_143022.html",
  "report_url": null
}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_GENERATE_REPORT` | `true` | Auto-generate reports on audit completion |
| `HOUND_ADMIN_KEY` | `""` | Admin panel authentication key |

---

## File Structure

```
~/.hound/
├── reports/
│   ├── ProjectA/
│   │   ├── audit_report_20260205_143022.html
│   │   └── audit_report_20260204_091544.html
│   ├── ProjectB/
│   │   └── audit_report_20260203_160012.html
│   └── ...
└── projects/
    ├── ProjectA/
    └── ProjectB/
```

---

## Troubleshooting

### "No completed audit sessions found"
**Cause**: Project has no completed audits
**Solution**: Run an audit first via "Run Audit" action

### "Failed to generate report"
**Causes**:
1. Missing hypotheses in database
2. LLM API timeout
3. Insufficient permissions to write report file

**Solutions**:
1. Check `/admin/hypothesis/list` for findings
2. Check LLM configuration in `config.yaml`
3. Verify `~/.hound/reports/` directory permissions

### Reports not accessible via URL
**Cause**: Static files mount failed
**Solution**: 
1. Check logs for mount errors
2. Verify `~/.hound/reports/` exists
3. Restart server

### Auto-generation not working
**Cause**: `AUTO_GENERATE_REPORT` disabled or no confirmed findings
**Solution**:
1. Set `export AUTO_GENERATE_REPORT=true`
2. Ensure audit found confirmed findings (confidence >= 0.7)

---

## Comparison: CLI vs Admin Panel

| Feature | CLI (`hound report`) | Admin Panel |
|---------|---------------------|-------------|
| Generate from session | ✅ | ✅ (via AuditSessionAdmin) |
| Generate from project | ✅ | ✅ (via ProjectAdmin) |
| Confirm & generate | ❌ Manual 2-step | ✅ One-click action |
| Auto-generate on audit | ❌ | ✅ Configurable |
| Format options | HTML, Markdown, PDF | HTML (others via API) |
| Include all findings | `--all` flag | `include_all` param |
| Custom auditors | `--auditors` flag | Fixed: "Security Team" |
| Browser viewing | ❌ Local file only | ✅ Via `/reports` URL |

---

## Future Enhancements

- [ ] PDF/Markdown format support in admin UI
- [ ] Custom report title/auditors in admin actions
- [ ] Email delivery integration
- [ ] Report versioning and history
- [ ] Client portal for self-service report generation
- [ ] Approval workflow before report finalization
- [ ] Report templates and customization

---

## Testing

### Manual Test: Full Workflow
```bash
# 1. Start server
cd /workspaces/hound
python server/start.py

# 2. Open admin panel
open http://localhost:8000/admin

# 3. Test report generation
# - Projects → Select → "Generate Report"
# - Audit Sessions → Select → "Generate Report"  
# - Findings → Select → "Confirm & Generate Report"

# 4. Verify reports
ls -lh ~/.hound/reports/*/

# 5. Test browser access
open http://localhost:8000/reports/ProjectName/audit_report_*.html
```

### API Test: Auto-Generation
```bash
# Run audit with auto-generate enabled
export AUTO_GENERATE_REPORT=true

curl -X POST http://localhost:8000/audits/run-sync \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "max_investigations": 20,
    "time_limit_minutes": 30
  }'

# Check response for report_path and report_url
```

---

## Security Considerations

1. **Authentication**: Admin actions require `HOUND_ADMIN_KEY` (if set)
2. **Report Access**: Reports served via `/reports` are publicly accessible
3. **Sensitive Data**: Reports may contain code snippets and vulnerability details
4. **Recommendation**: In production, add authentication to `/reports` mount point

---

## Related Documentation

- [API Reference](docs/API_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Report Generator](analysis/report_generator.py)
