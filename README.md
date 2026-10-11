# Meetly Workspace v2

Company workspace with chat, meetings and group calls. FastAPI + **SQLite3** on the server, one `index.html` for every screen, native WebRTC for media.

## Run

```bash
pip install fastapi "uvicorn[standard]" pydantic
export APP_SECRET="a-long-random-string"      # optional; otherwise generated and stored in the DB
uvicorn main:app --reload                      # open http://127.0.0.1:8000/
```

Keep `main.py` and `index.html` together. Camera and microphone need `localhost` or HTTPS. API docs: `/api/docs`.

| Env var | Purpose | Default |
|---|---|---|
| `APP_SECRET` | Session signing key | random, kept in `meta` table |
| `DB_PATH` | SQLite file | `meetly.db` beside `main.py` |

## Screens in `index.html` (hash routes)

| Route | Who | What |
|---|---|---|
| sign-in / join with office code / register company | everyone | Same page for all |
| `#/home` | all | Greeting, unread count, upcoming meetings, unread conversations |
| `#/dir` | all | Directory with search, department and access filters, Message and Call |
| `#/meetings` | all | Upcoming and past meetings: create, edit, delete, join, copy link |
| `#/teams` | all | Your teams: members, spaces, edit, leave. Managers and admins create teams |
| `#/profile` | all | Edit details, change password, desktop alerts |
| `#/r/<id>` | per access | Chat for a DM, team, space, meeting or group call. Search, edit, delete, load earlier, typing, call controls |
| `#/admin/dashboard` | admin | Headcount, online, teams, spaces, meetings, 7-day message chart |
| `#/admin/employees` | admin | Search, add, edit, change access, deactivate and reactivate, reset password, CSV export |
| `#/admin/teams` | admin | Every team: open, manage members, delete |
| `#/admin/meetings` | admin | Every meeting: edit, delete |
| `#/admin/workspace` | admin | Company details, office code, self-registration switch, rotate secret |
| `#/admin/audit` | admin | Searchable activity log |

Calls keep running while you move between pages.

## Roles

*Role* is the free-text job title. *Access* is `member`, `manager` or `admin`.

| Action | member | manager | admin |
|---|:-:|:-:|:-:|
| Chat, call, meetings, group calls, spaces in own teams | ✓ | ✓ | ✓ |
| Create teams, manage teams they own | | ✓ | ✓ |
| Manage or delete any team, delete any message | | | ✓ |
| All admin pages | | | ✓ |

## Database (SQLite, WAL, foreign keys on)

`workspaces` · `users` · `teams` · `team_members` · `rooms` (`dm`, `call`, `team`, `space`, `meeting`) · `room_members` · `messages` · `reads` (per-user unread marker) · `audit` · `meta`

Deleting a team or room cascades to its members and messages. Spaces past their expiry are hidden, then purged after 30 days.

## Security

- PBKDF2-SHA256 (200k) for passwords and the office secret; password rule: 8+ characters with a letter and a number.
- Signed tokens with a per-user version. Password reset, change or deactivation revokes sessions and closes open sockets.
- Admin-created and reset accounts must choose a new password at first sign-in.
- Lock-out for 10 minutes after 5 wrong passwords, plus IP rate limits on auth endpoints.
- All SQL is parameterised. Search input is escaped. The UI escapes all user text.
- Every admin action is written to the activity log.

## WebSocket (`/ws?token=…`)

Client sends: `open`, `chat`, `typing`, `call_join`, `call_leave`, `sig`, `ring`, `ping`.
Server sends: `chat`, `msg_edit`, `msg_del`, `typing`, `presence`, `call_state`, `ring`, `peers`, `peer_leave`, `sig`, `error`.

## Before large-scale use

| Gap | Recommendation |
|---|---|
| Socket state is in process memory | One worker per database, or add Redis pub/sub and move to PostgreSQL |
| STUN only | Add a TURN server (coturn) to `ICE` in `index.html` |
| Mesh calls, 8 people max | Add an SFU (LiveKit or mediasoup) for bigger meetings |
| Token in `localStorage` | Move to HTTP-only cookies with CSRF protection |
| No email | Add verification and self-service password reset |
| TLS | Serve behind Nginx or Caddy with HTTPS and `wss://` |
| Backups | Copy `meetly.db` with `sqlite3 meetly.db ".backup backup.db"` |