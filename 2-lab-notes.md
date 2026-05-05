# WireGuard Docker Lab – Notes / Pitfalls

### 1) PUID / PGID (permissions issue)

* Always set:

  ```bash
  -e PUID=$(id -u)
  -e PGID=$(id -g)
  ```
* Otherwise → students may not be able to edit config files
* Especially problematic in WSL + VS Code

---

### 2) Config folder structure changed

* Old:

  ```bash
  /config/wg0.conf
  ```
* New:

  ```bash
  /config/wg_confs/wg0.conf
  ```
* 👉 Always edit `wg_confs/wg0.conf` in newer versions

---

### 3) Permissions on wg0.conf

* Default:

  ```bash
  -rw------- (600)
  ```
* This is **intentional** (private keys inside)
* If needed for simplicity:

  ```bash
  chmod 644 wg0.conf
  ```

---

### 4) VS Code + WSL issue

* `sudo code` ❌ doesn’t work (`code` not in root PATH)
* Use:

  * `nano` ✅
  * or fix ownership (`PUID/PGID`) ✅

---

### 5) Client config copy step (OUTDATED)

* Tutorial says:

  ```bash
  cp peer1.conf → wg0.conf
  ```
* New container:

  * auto-generates config
  * overwrites/ignores manual copy

👉 Safe to **skip this step entirely**

---

### 6) Container regenerates configs

* If config missing/invalid → container recreates it
* Stored in:

  ```bash
  /config/wg_confs/
  ```

---

### 7) After editing config

* Restart required:

  ```bash
  docker restart wireguard-server
  ```

---

### 8) Path differences

* Tutorial uses:

  ```bash
  /home/vedranm/...
  ```
* Students must change to their own home dir:

  ```bash
  /home/<username>/...
  ```

---

### 9) Mixed ownership (if PUID changed later)

Fix with:

```bash
chown -R <uid>:<gid> wireguard/
```

---

### 10) Lazy Wireguard

WireGuard is lazy — the tunnel only activates when a peer initiates a handshake. The client knows the server's endpoint (IP + port) so it can initiate. The server doesn't know the client's endpoint until the client reaches out first.

`docker exec wireguard-server ping 10.31.31.2` → fails, server doesn't know where the client is yet.

`docker exec wireguard-peer1 ping 10.31.31.1` → works, client initiates handshake, server learns client's endpoint.

`docker exec wireguard-server ping 10.31.31.2` → now works, server knows where to find the client.

**TL;DR:** Client knocks first, server learns where the client is, two-way traffic works after that.

---

## One-line summary (good to tell students)

> “If something doesn’t work, it’s usually permissions or the new `wg_confs` folder.”

---

If you want, I can condense this even further into a one-page cheat sheet you can share with students.
