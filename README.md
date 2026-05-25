# VA Security Visual Analytics

Interactive visual analytics dashboard for multi-source cybersecurity data.

## Run

```powershell
cd visual-analytics
python server.py
```

Open:

```text
http://127.0.0.1:8090/app/index.html
```

## Structure

- `visual-analytics/app/` - HTML, CSS and JavaScript dashboard.
- `visual-analytics/data/va_data.json` - prepared analytical layer used by the dashboard.
- `visual-analytics/scripts/build_data.py` - builds `va_data.json` from the original local evidence files.
- `visual-analytics/scripts/unified_layer_from_csv.py` - generic CSV-to-unified-layer builder.
- `visual-analytics/server.py` - local server and on-demand raw firewall drill-down API.

Large original evidence files are excluded from git by `.gitignore`.
