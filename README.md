# GitDock

> Self-hosted Git repository manager & file vault with a stunning AMOLED dark UI.

![Node.js](https://img.shields.io/badge/Node.js-24-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-5-000?logo=express)

## What is GitDock?

GitDock is a lightweight, self-hosted Git server and file upload vault packed into a single `server.js` file. It features a modern AMOLED-black dashboard with smooth animations, commit history browsing, branch management, and session-based authentication — all without any build step or external database.

## Features

- **Git hosting** — Push/pull repos over HTTP with Basic auth
- **File vault** — Upload, download, and share files via the web UI
- **Commit history** — Browse commits, diffs, and file changes per repo
- **Branch selector** — Switch branches with a polished pill-style selector
- **Authentication** — Session-based login with scrypt password hashing
- **User profile** — Avatar (DiceBear), display name, password management
- **AMOLED dark theme** — Pure black UI with green/blue/purple accents
- **Responsive** — Works on desktop and mobile
- **Zero dependencies aside from Express, Multer, and adm-zip**

## Quick Start

```bash
# Clone
git clone https://github.com/c4g7-dev/GitDock.git
cd GitDock

# Install
npm install

# Run
PORT=3099 node server.js
```

Open `http://localhost:3099` — default login is `admin` / `admin`.

## Stack

| Layer     | Tech                          |
|-----------|-------------------------------|
| Runtime   | Node.js 24                    |
| Framework | Express 5                     |
| Auth      | scrypt (node:crypto), cookies |
| Storage   | File system + JSON            |
| UI        | Vanilla HTML/CSS/JS (inline)  |

## Project Structure

```
server.js       — The entire backend + embedded frontend
storage/
  repos/        — Bare git repositories
  files/        — Uploaded files
  users.json    — User credentials (auto-created)
```

## License

MIT
