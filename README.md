# Meetly Workspace v6

FastAPI + **SQLite3** backend. Two pages: `index.html` (sign in, join, register company) and `dashboard.html` (the whole app after sign-in).

## Project structure

```
meetly-workspace/
├── main.py          # REST API, WebSocket signaling, SQLite
├── index.html       # login / join with office code / register company  ->  served at /
├── dashboard.html   # dashboard, chats, meetings, teams, people, admin  ->  served at /dashboard
├── call.html        # standalone full-screen call and meeting page  ->  served at /call/<id>
├── README.md
├── meetly.db*       # created on first run (SQLite + WAL files)
└── uploads/         # created on first run (shared files, local storage for testing)
```

## Run

```bash
pip install fastapi "uvicorn[standard]" pydantic
export APP_SECRET="a-long-random-string"     # optional
uvicorn main:app --reload                     # http://127.0.0.1:8000/
```

| Env var | Purpose | Default |
|---|---|---|
| `APP_SECRET` | Session signing key | generated, kept in DB |
| `DB_PATH` | SQLite file | `meetly.db` |
| `UPLOAD_DIR` | Where shared files are stored | `uploads/` |
| `PUBLIC_URL` | Public address used in meeting invitation links, e.g. `https://meet.example.com` | request address |
| `WORKSPACE_QUOTA_MB` | File storage limit per workspace | `2048` |

Upgrading from v2: keep your `meetly.db`. New columns and tables are added on startup. Replace `main.py` and `index.html`, and add `dashboard.html`.

## Credentials and account recovery

Every new account gets a **personal recovery key** (`MRK-XXXX-XXXX-XXXX-XXXX-XXXX`, 100 bits) and a downloadable **credential file** (JSON). The page will not continue until the file is downloaded.

| When | Who downloads | File contains |
|---|---|---|
| Company registered | Admin | email, password, recovery key, plus the office code and office secret for inviting staff |
| Employee joins with office code | Employee | email, password, recovery key |
| Admin adds an employee | Admin, hands it to the employee | email, temporary password, recovery key |
| Admin reissues credentials | Admin, hands it over | new temporary password, new recovery key |
| Recovery key regenerated (Profile) | The person | email, new recovery key (no password) |
| Password reset with a recovery key | The person | new password, **new** recovery key |

```json
{
  "schema": "meetly.credentials/v1",
  "app_url": "https://your-host",
  "issued_at": "2026-10-11T10:00:00Z",
  "issued_by": "workspace-registration",
  "workspace": { "name": "Acme Corp", "office_code": "ACME-5B50" },
  "account": { "name": "Ann A", "email": "a@x.com", "role": "Workspace Admin", "access": "admin" },
  "credentials": { "email": "a@x.com", "password": "…", "recovery_key": "MRK-7SJ9-YJ77-4EER-9WHR-U25U" },
  "workspace_invite": { "office_code": "ACME-5B50", "office_secret": "…" },
  "fingerprint": "57a14b320bd1a4af",
  "notes": ["…"]
}
```

`workspace_invite` appears only in the admin's file at registration. The password is the one set when the file was issued and can be out of date after a change. The recovery key does not change when the password changes.

**Forgot password** (`/#forgot`, or the link on the sign-in form): upload the credential file or type the email and recovery key, then choose a new password. The file is checked against its fingerprint in the browser. On success all sessions are signed out, the key is replaced, and a new credential file is downloaded.

**Safeguards:** only PBKDF2 hashes of the key are stored. Wrong keys lock recovery for that account for 30 minutes after 5 tries, and there is an IP rate limit. Unknown emails and wrong keys get the same error. A used key cannot be replayed. Keys are shown once and never retrievable: a person who loses both password and file needs an admin to reissue credentials. If the only admin loses both, create a second admin first. Employees from older versions show "No recovery key" in the admin list until they generate one in Profile or an admin reissues credentials.

## Calls and meetings: their own full-screen page

Every call and meeting opens in its **own window at `/call/<id>`** (`call.html`). The dashboard tab stays free for chat. Meeting invitation links point straight at this page, and if the person is signed out they sign in and land back in the call.

- **Join screen (meetings):** camera preview, mic level meter, mic and camera toggles, microphone, camera and speaker pickers, speaker test.
- **Voice calls** (direct, group, team, space) join instantly with audio only. **Meeting mode** turns a voice call into video for the group, **Voice mode** switches back. Meetings are always video.
- **Full screen:** the F key or the button. In full screen the bars hide until you move the mouse. Double-click any tile to full-screen just that tile.
- **Back to chat:** the call keeps running in its window. The dashboard shows an **in-call bar** (call name, timer, mute, return, leave) and a "Return to call" button in the chat. If you open a call link while already in a call you get a clear message, and a second window can take the call over.
- **Controls:** mute, camera, present (only the presenter sees Stop sharing), raise hand, reactions, people panel with connection quality, in-call chat, details panel, grid or speaker view, pin, hide own tile, add people (rings them and adds them to the group or invite list), settings, keyboard shortcuts (press `?`).
- **Host tools** (organizer, group owner, team owner, admin): mute one person or everyone, remove someone, **lock the call**, **end for everyone**.
- **Audio recording on your own device:** everyone in the call sees a red Recording badge and is told who is recording. The file downloads when you stop.
- **Production touches:** one call per browser (cross-window lock), reconnect and rejoin after a dropped connection, ICE restart on a stalled path, video bitrate limits that drop as the call grows, connection statistics with a "turn camera off" suggestion on poor links, screen wake lock, audio-unblock banner if the browser blocks autoplay, clear errors for blocked or missing microphones, leave-warning when closing the tab mid-call, and a shared call timer.
- Up to 8 people per live call.

## Meetings with invitations

Create a meeting with title, start, duration, agenda and people. Everyone invited gets a chat message like:

```
📅 Meeting invitation
Title: Weekly sync
Date: Mon, 12 Oct 2026
Time: 3:00 PM - 3:45 PM (GMT+5:30)
Duration: 45 min
Agenda:
  - Roadmap
  - Hiring plan
People (3): Ann A, Bob B, Cy C
Organizer: Ann A
Join: https://meet.example.com/call/ab12cd34
```

Edits send "Meeting updated" to people already invited and an invitation to newly added people. Removing someone or deleting the meeting sends "Meeting cancelled". People get a reminder 10 minutes before the start (chat notice plus a pop-up with a Join button). Create a meeting from inside a group or team chat and the invitation is posted once in that chat; people outside it get a direct message. Leave the start empty to start now and ring everyone. **Add to calendar** downloads an `.ics` file.

## Groups

**New group** creates a group chat (3 or more people, up to 50). From inside it you can start a voice call, schedule a meeting, add or remove members, rename it, or leave. Ownership passes on if the owner leaves.

## Operations

Call history for everyone (Dashboard, Recent calls) and for admins (Admin, Calls: duration, people, peak). Admin System tab shows uptime, live calls, database size and storage against the quota, and exports workspace data as JSON without passwords or keys. Every API request is logged as one JSON line with a request id (`X-Request-ID`). `/api/health` and `/api/ready` for monitoring. Chat is rate limited per user. Shutdown closes sockets cleanly so browsers reconnect. Back up the database with `sqlite3 meetly.db ".backup backup.db"`, and compress responses at your reverse proxy.

## Dashboard sections (`/dashboard#/...`)

| Route | What |
|---|---|
| `dashboard` | Quick actions, stats, upcoming meetings, unread chats, who is online, teams |
| `chats`, `chats/<id>` | Conversation list with previews, unread badges, filters, search; full chat view |
| `meetings` | Create, edit, delete, join with video, copy invite link |
| `teams` | Members, spaces, edit, leave |
| `people` | Directory with filters, Message and Call |
| `profile` | Details, password, desktop alerts |
| `admin/overview, employees, teams, meetings, workspace, audit` | Admin only |

## Chat features

Send, reply (quoted), emoji reactions, edit, **delete for me / delete for everyone** ("This message was deleted" placeholder), **clear chat for me**, clear for everyone (admin, team or room owner, not in direct chats), search, load earlier, date separators, typing indicator, read ticks in direct chats, unread counts that survive reload, desktop alerts, emoji picker, link detection.

**Files:** attach button, drag and drop, or paste an image. Preview and caption before sending, progress bar with cancel, **50 MB per file** (checked in the browser and again on the server while streaming). Images, video and audio play inline. Everything else downloads. Executable types (`.exe .bat .cmd .com .scr .msi .vbs .ps1 .jar .dll`) are blocked. Deleting a message, clearing a chat, or deleting a team or space also deletes its files from disk. The "Files and media" list is in the chat info panel.

## Calls (summary)

| Where | Type | Media |
|---|---|---|
| Direct chat, group call, team, space | **Voice call** | Audio only, avatars with a speaking ring |
| Meeting | **Video meeting** | Camera and audio; falls back to audio if no camera |

**Screen share** works in both. Only the person sharing sees **Stop sharing** (and it also stops if they end sharing from the browser bar). Everyone else sees "X is presenting" and a large presenter tile. People who join later see the share too. Calls keep running while you browse other sections.

## Storage

Files are on local disk through the small `LocalStorage` class in `main.py`. To move to S3, GCS or Azure, replace that class (`path`, `delete`) and the two places that open the file for write and read. File links use the session token in the URL for testing; switch to signed, short-lived URLs when you change storage.

## Database (SQLite, WAL, foreign keys)

`workspaces` `users` `teams` `team_members` `rooms` `room_members` `messages` (reply, file) `files` `reactions` `hidden` (delete-for-me) `reads` (read marker, cleared marker) `audit` `meta`

## Security

PBKDF2 passwords, versioned signed tokens (reset, change or deactivate revokes sessions), forced password change for admin-created accounts, 10-minute lock after 5 failed sign-ins, rate limits, parameterised SQL, escaped output, safe inline types only for files, access check on every file download.

## Before large-scale use

One server process only (socket state is in memory). Add a TURN server to `ICE` in `dashboard.html` for restrictive networks. Calls use peer-to-peer mesh, so keep them to 8 people or fewer, or add an SFU. HTTPS is required for camera, microphone and screen share outside localhost. Put Nginx or Caddy in front and allow request bodies of at least 50 MB (`client_max_body_size 55m;` in Nginx).
