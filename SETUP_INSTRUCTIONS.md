# PhantomScan Setup Instructions

Follow these steps when setting up PhantomScan on a new device.

## 1. Prerequisites

Install these first:

- Git
- Docker Desktop, if you want the easiest setup
- Python 3.12, for local backend development
- Node.js 20 or newer, for local frontend development

## 2. Clone The Project

```bash
git clone <repo-url>
cd phantomscan
```

## 3. Configure Environment Files

Create backend and frontend `.env` files from the examples.

On macOS/Linux:

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

On Windows PowerShell:

```powershell
Copy-Item backend/.env.example backend/.env
Copy-Item frontend/.env.example frontend/.env
```

Open `backend/.env` and set at least this required value:

```env
SECRET_KEY=replace-with-a-long-random-secret
```

You can generate a secret with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Optional values you can add later:

- `OPENROUTER_API_KEY` for AI features
- `NVD_API_KEY` for better CVE lookup limits
- Supabase values if you want Google/GitHub login

For local frontend development, keep `frontend/.env` like this unless your backend port changes:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

## 4. Run With Docker Compose

This is the easiest way because it starts the backend, frontend, PostgreSQL, and Redis together.

```bash
docker compose -f docker/docker-compose.yml up --build
```

After it starts, open:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`
- Swagger docs: `http://localhost:8000/docs`

To stop everything, press `Ctrl+C`, then run:

```bash
docker compose -f docker/docker-compose.yml down
```

## 5. Run Locally Without Docker

Use this if you want to develop backend and frontend directly on your machine.

Start the backend:

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment.

On macOS/Linux:

```bash
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install backend dependencies and run the API:

```bash
pip install -r requirements.txt
python -m playwright install chromium
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal, start the frontend:

```bash
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173`.

## 6. Useful Commands

From the project root:

```bash
npm run dev
npm run build
```

Frontend commands from `frontend/`:

```bash
npm run dev
npm run build
npm run typecheck
```

Backend test command from `backend/`:

```bash
pytest
```

## 7. Common Issues

- If port `8000` is busy, run the backend on another port and update `VITE_API_BASE_URL` and `VITE_WS_BASE_URL` in `frontend/.env`.
- If port `5173` is busy, stop the other Vite app or change the Vite dev server port.
- If login/auth endpoints fail, make sure `SECRET_KEY` is set in `backend/.env`.
- If browser-based scanning fails locally, rerun `python -m playwright install chromium` inside the backend virtual environment.
- Only scan targets you own or are authorized to test.
