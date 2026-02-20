# ARQON Browser Guard (Chromium)

Local browser-side companion for ARQON API.

## Features

- URL pre-check on navigation.
- Download URL pre-check with automatic cancel on block.
- Warning interstitial with "Proceed once".
- Configurable endpoint/key/toggles in options page.

## Install (Developer mode)

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select folder: `browser-extension/chromium`.

## Required backend

Run ARQON API:

```powershell
arqon-agent --config config/default.yml run
```

Default endpoint: `http://127.0.0.1:8765`  
Default header: `X-ARQON-Key: change-me-arqon`

