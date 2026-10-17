# Vedant's Doc Vault: your offline, encrypted document locker

Like DigiLocker, but private. Photos and PDFs of your Aadhaar, PAN, marksheets, certificates,
bills and other papers are encrypted with your master password and stored **only on your own
device**. There are no accounts, no cloud and no tracking, and the app works with the internet off.

---

## 1. Install on Windows (2 minutes, no internet needed)

1. Keep this `DocVault` folder somewhere permanent, for example `Documents\DocVault`.
2. Double-click **`Start DocVault (Windows).bat`**. Microsoft Edge opens DocVault.
3. Click the **Install** icon at the right end of Edge's address bar (or `⋯` → *Apps* → *Install DocVault*).
4. From then on, open **DocVault from the Start menu**. It works fully offline, and you
   can close the small minimized "DocVault server" window.

> The `.bat` file starts a tiny server that only this PC can reach (`localhost`). It is needed only
> for the first install and for app updates. Your documents never pass through it.

## 2. Install on Android

An Android phone can only install a web app from an `https://` address, so the app's
**code** (never your documents) has to be hosted once. GitHub Pages is free:

1. On a PC, create a free account at <https://github.com>.
2. Click **New repository**, name it `docvault`, keep it **Public**, then click **Create**.
3. Click **uploading an existing file**, drag in **everything inside this `DocVault` folder**
   (including the `icons` folder), then click **Commit changes**.
4. Open the repository's **Settings** → **Pages**. Under *Branch*, choose `main` and `/ (root)`, then click **Save**.
   After about a minute your app is live at `https://YOUR-USERNAME.github.io/docvault/`.
5. On your phone, open that address in **Chrome**, then tap `⋮` → **Install app** (or *Add to Home screen*).
6. Open DocVault from your home screen. From now on it works with no internet.

> Publishing the code is safe: it holds no personal data. Each phone or PC keeps its own encrypted
> data inside the installed app. You can also install on Windows from this same address in Edge
> instead of using the `.bat` file.

## 3. Using it

- **+ Add**: take photos with the camera (front, back, every page) or pick images/PDFs.
  Quick buttons fill in common documents (Aadhaar, PAN, Passport…).
- Fill in the **category**, **who it belongs to** (you or a family member), the **document number** and the
  **expiry date**. Documents expiring within 60 days are highlighted.
- Search finds titles, numbers, tags, notes and file names.
- On a PC you can **drag & drop** or **paste** (Ctrl+V) files into the add screen.
- Tap a document to see all its pages, copy its number, or **Save / Share** a page.
  (A shared or saved copy is a normal, *unencrypted* file.)

## 4. Keep phone and PC in sync (offline)

1. On the device with the newer changes, go to **⚙️ → Export backup**. A file
   `DocVault-backup-YYYY-MM-DD.vault` is saved to Downloads.
2. Copy it to the other device by USB cable, pen drive, or any storage you like.
3. On the other device:
   - **First time:** on the "Create your DocVault" screen, choose **Restore from a backup file**.
     Both devices then use the same master password.
   - **Later:** go to **⚙️ → Import / merge backup**. The newer version of each document wins, and
     deletions carry over.

The backup file is fully encrypted, so it is safe to keep on a pen drive or even in a cloud folder.
It only opens with the master password that was in use when it was made.

## 5. Important safety notes

- 🔑 **There is no "forgot password".** Without the master password, nobody (not even you) can open
  the vault or its backups. Write it down and keep it somewhere safe.
- 💾 **Make a backup regularly** and keep a copy off the device. If the phone is lost or reset, the
  backup is your only copy. The app reminds you every 30 days.
- 🧹 DocVault's data lives in the browser's storage for the app. **Don't use "Clear data/storage"**
  for Chrome/Edge or for this site, because that erases the vault (backups are not affected).
- 🔒 The app locks itself after 5 minutes of inactivity (you can change this in ⚙️), and can also
  lock the moment you switch away from it.

## How the protection works (for the curious)

- A random 256-bit **AES-GCM** key encrypts every document's details, every file and every thumbnail.
- That key is stored only in encrypted form, protected by your master password through
  **PBKDF2-SHA256 with 600,000 iterations** and a random salt. Wrong passwords are rejected, and repeated
  wrong guesses add a growing delay.
- Each encrypted record is bound to its own ID, so records cannot be swapped around.
- The app's security policy (CSP) forbids connecting to any other website, so nothing can be sent anywhere.
- Changing the master password re-protects the key instantly. Old backups keep their old password.

## Files

| File | Purpose |
|---|---|
| `index.html`, `style.css`, `app.js` | The app |
| `sw.js`, `manifest.webmanifest`, `icons/` | Make it installable and offline |
| `Start DocVault (Windows).bat`, `windows/serve.ps1` | Windows launcher (local-only server) |
