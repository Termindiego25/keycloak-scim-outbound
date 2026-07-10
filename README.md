# 🔐 Keycloak SCIM Outbound Plugin

A lightweight **Keycloak extension** that provisions users and groups to external applications via the **SCIM v2** protocol. This plugin allows Keycloak to **push user lifecycle changes** (create, update, delete, deactivate) to external systems like **Passbolt**, **Nextcloud**, or any other SCIM-compliant service — all configurable directly from the **Keycloak Admin Console**.

---

## 🚀 Features

- 🔁 **Automatic user provisioning** — Create, update, or deactivate users in external SCIM targets.
- 👥 **Group-based filtering** — Provision only members of a specific Keycloak group.
- ⚙️ **UI configuration** — Configure endpoints, tokens, and mapping directly from *User Federation*.
- 🧩 **Customizable userName strategy**
  - `username` → use Keycloak username
  - `email` → use user's email as SCIM `userName`
  - `attribute` → use a custom Keycloak user attribute
- 🧱 **SCIM v2 compatible** — Works with `/Users`, optional `/Groups` sync, and `/ServiceProviderConfig` endpoints.
- 🔒 **Token-based authentication (Bearer)** — no password sync required.
- 📂 **LDAP/AD support** — Optional [LDAP/AD support](#-optional-ldap--active-directory-integration) via a built-in `LdapSyncNotifierMapper`.
- 🗂️ **Optional SCIM Group sync** — Push Keycloak group create/rename/delete and membership changes to SCIM `/Groups`. Opt-in, disabled by default. Supports both event-driven (admin console) and **LDAP-driven** membership changes.

---

## 🧰 Installation

### 1. Build the plugin

```bash
mvn clean package
```

This generates a `.jar` under:

```
target/keycloak-scim-outbound-<version>.jar
```

### 2. Deploy to Keycloak

Copy the JAR file to your Keycloak providers directory, for example:

```bash
cp target/keycloak-scim-outbound-<version>.jar /opt/keycloak/providers/
```

Then rebuild the provider cache:

```bash
/opt/keycloak/bin/kc.sh build
```

Finally, restart Keycloak:

```bash
/opt/keycloak/bin/kc.sh start
```

---

## ⚙️ Configuration

Once deployed:

1. Open the **Keycloak Admin Console**
2. Go to **User Federation → Add provider → keycloak-scim-outbound**
3. Fill in the following fields:

| Field | Description | Required |
| ----------------------------------- | ----------------------------------------------------------------------------- | -------- |
| **SCIM Base URL** | Base endpoint of your SCIM API, e.g. `https://app.example.com/scim/v2` | ✅ |
| **SCIM Token** | Bearer token for authenticating with the SCIM target | ✅ |
| **Filter Group (optional)** | Only users in this group will be provisioned | ❌ |
| **userName Strategy** | How to build SCIM `userName` (`username`, `email`, or `attribute`) | ✅ |
| **userName Attribute** | Custom user attribute name (only if strategy = `attribute`) | ❌ |
| **Deprovision Action** | What to do on delete / group removal: `deactivate` (PATCH `active=false`, default) or `delete` (`DELETE /Users/{id}`) | ✅ |
| **Sync Groups** | Enable SCIM `/Groups` sync. When `true`, group create/rename/delete and membership changes are pushed to the SCIM target. **Disabled by default.** | ❌ |
| **Sync Groups Filter (regex)** | Java regex pattern for the group names to include in LDAP-driven group sync (e.g. `admins\|developers\|team-.*`). Leave blank to scope to *Filter Group* only. Only used when *Sync Groups* is enabled. | ❌ |
| **LDAP Users Provisioning Mode** | How LDAP-driven user sync runs on *Synchronize changed users*: `Delta` (default, flush pending changes only) or `Full` (re-provision all *Filter Group* members). | ✅ |
| **LDAP Groups Provisioning Mode** | How LDAP-driven group sync runs on *Synchronize changed users*: `Delta` (default, flush pending member changes only) or `Full` (send a complete member-list replace for all in-scope groups). | ✅ |

---

## 🔄 Supported Events

| Event | Action |
| --------------------------------- | ------------------------------------------------------------------------------- |
| **REGISTER** | Create new SCIM user |
| **UPDATE_PROFILE / UPDATE_EMAIL** | Update SCIM user fields |
| **UPDATE_CREDENTIAL (password)** | Patch password if supported |
| **DELETE_ACCOUNT** | Deprovision SCIM user (deactivate or delete, per *Deprovision Action*) |
| **Admin CREATE/UPDATE/DELETE** | Sync CRUD operations |
| **Group membership add/remove** | Provision/deprovision users based on group membership (if `filterGroup` is set); also updates SCIM group member list (if `Sync Groups` is enabled) |
| **Group CREATE/UPDATE/DELETE** | Create, rename, or delete the corresponding SCIM group (only if `Sync Groups` is enabled) |

> ℹ️ **Lifecycle lookup & deprovisioning:** users are matched by SCIM `externalId` (the Keycloak user id) first, falling back to `userName` for users provisioned before `externalId` existed. The `externalId` is also backfilled on update for legacy users. Deprovisioning defaults to **deactivate** (`PATCH active=false`); set *Deprovision Action* to `delete` for providers that require a hard delete (e.g. VMware vCenter).

---

## 🗂️ SCIM Group Sync

Group sync is **opt-in** and disabled by default to avoid affecting existing deployments on SCIM targets that do not support `/Groups`.

### How to enable

In the provider configuration (*User Federation → keycloak-scim-outbound*):

1. Toggle **Sync Groups** to `true`.
2. Optionally fill **Sync Groups Filter (regex)** with a Java regex pattern for the group names you want to sync via the LDAP path (e.g. `admins|developers|team-.*`). Leave blank to scope LDAP-driven group sync to *Filter Group* only.
3. Save.

### What gets synced

| Source | Keycloak event / trigger | SCIM operation |
|---|---|---|
| Admin / event-driven | Group created | `POST /Groups` — creates an empty group with `externalId` = Keycloak group UUID and `displayName` = group name |
| Admin / event-driven | Group renamed | `PATCH /Groups/{id}` — updates `displayName` |
| Admin / event-driven | Group deleted | `DELETE /Groups/{id}` — found by `externalId` |
| Admin / event-driven | User added to group | `PATCH /Groups/{id}` — adds the user as a member (`op: add`) |
| Admin / event-driven | User removed from group | `PATCH /Groups/{id}` — removes the member using the SCIM path-filter form: `members[value eq "<userId>"]` (RFC 7644 §3.5.2) |
| LDAP sync (delta) | User's group membership changed in LDAP | `PATCH /Groups/{id}` — individual `add` or `remove` per changed member |
| LDAP sync (full) | *Synchronize all users* or Full mode | `PATCH /Groups/{id}` — complete `replace` of the entire member list |

Groups are matched in SCIM by `externalId` (Keycloak UUID) first, falling back to `displayName`. The `externalId` is set at creation time, so renames do not break the link.

### Sync execution order

When a sync sweep runs, **user sync always executes before group sync**. This guarantees that every in-scope user already has a SCIM ID by the time group sync resolves member IDs.

### Provisioning scope

- **User provisioning** is scoped to members of *Filter Group*.
- **Group sync (event-driven)** applies to any group matching the *Sync Groups Filter* regex, or *Filter Group* only when the filter is blank.
- **Group sync (LDAP-driven)** applies the same regex/blank-filter rule. Only users within the *Filter Group* provisioning scope are included when building the member list.

### Limitations

- **No retroactive full-sync on first enable**: enabling *Sync Groups* does not automatically push existing groups or their current members. Click **Synchronize all users** on the SCIM outbound provider after enabling to trigger an initial full sync.
- **SCIM group must exist before LDAP sync can update its members**: the LDAP sync path logs a warning and skips any group not found in the SCIM target. Create the group first (via an admin event or manually in the target) before relying on LDAP-driven member updates for it.
- **Permissions are not assigned**: creating a group via SCIM does not automatically grant it any permissions in the target system. Permission assignment must be done manually in the target after the group is created.
- **Top-level groups only**: nested Keycloak sub-groups fire the same `GROUP` events and are synced as flat groups in SCIM (SCIM v2 Groups do not have a native hierarchy).
- **Target must support `/Groups`**: not all SCIM implementations expose the Groups resource. Check your target's documentation or `ServiceProviderConfig` before enabling.

---

## 🪵 Logging

All plugin logs are prefixed with:

```
[keycloak-scim-outbound][<target>]
```

Example output:

```
2025-09-30T18:09:56Z [keycloak-scim-outbound][SCIM Keycloak] UPDATE targetUserName=scim@domain.com realm=domain OK
```

Enable Keycloak's log level for debugging (optional):

```bash
kc.sh start --log-level=org.keycloak.events=DEBUG,es.diegosr.keycloak_scim_outbound=DEBUG
```

---

## 🧪 Example targets

| Target | Base URL | Notes |
| -------------- | -------------------------------------------------- | -------------------------- |
| **Passbolt** | `https://your-passbolt-domain/scim/v2` | Works out of the box |
| **Nextcloud** | `https://cloud.example.com/apps/user_saml/scim/v2` | Requires SCIM app enabled |
| **Custom app** | Any compliant SCIM v2 endpoint | Supports `/Users` and `/Groups` resources |

---

## 🛠 Development

### Requirements

* Java 17+
* Maven 3.8+
* Keycloak 22+ (Quarkus distribution)

### Run in dev mode

```bash
kc.sh start-dev --spi-events-listener-keycloak-scim-outbound-enabled=true
```

---

## 🧩 Project structure

```
keycloak-scim-outbound/
├── pom.xml
└── src/main/java/es/diegosr/keycloak_scim_outbound/
    ├── ScimEventListenerProvider.java
    ├── ScimEventListenerProviderFactory.java
    ├── http/ScimClient.java
    ├── ldapsync/GroupMembershipState.java
    ├── ldapsync/LdapSyncNotifierMapper.java
    ├── ldapsync/LdapSyncNotifierMapperFactory.java
    ├── ldapsync/MembershipState.java
    ├── ldapsync/ScimGroupSync.java
    ├── ldapsync/ScimMembershipSync.java
    ├── ui/ScimTargetProviderFactory.java
    ├── ui/ScimTargetProvider.java
    └── util/ScimMapper.java
```

---

## 🔌 Optional LDAP / Active Directory Integration

By default this plugin reacts to Keycloak events (logins, admin actions, direct group membership changes). If your users are managed in an **LDAP or Active Directory** directory and group membership is driven by LDAP sync rather than by Keycloak events, those membership changes are invisible to the event listener — and users will not be provisioned or deprovisioned automatically.

The `ldapsync` package adds a dedicated **LDAP Storage Mapper** (`LdapSyncNotifierMapper`) that bridges this gap. It is entirely optional; if you are not using LDAP/AD federation you do not need it.

### When is this mapper needed?

Add `LdapSyncNotifierMapper` when **all** of the following are true:

- You have an LDAP or Active Directory user federation provider configured in Keycloak.
- Group membership for your users is controlled in LDAP/AD (not manually in Keycloak).
- You want SCIM provisioning to react to those LDAP-driven membership changes.

If group membership is managed directly in Keycloak (e.g. via the Admin Console or Admin API), the standard event listener already handles it and this mapper is not required.

### What does it do?

During every LDAP sync run, `LdapSyncNotifierMapper` compares each user's current group membership (as resolved from LDAP) against the last recorded state. When it detects a change it writes a small pending marker:

- **For `/Users`** — a marker on the user's local Keycloak attributes (`MembershipState`), picked up by `ScimMembershipSync`.
- **For `/Groups`** — a marker on the relevant group's local Keycloak attributes (`GroupMembershipState`), picked up by `ScimGroupSync` (only when *Sync Groups* is enabled).

Both sets of markers are flushed the next time a sync sweep runs.

### Sync trigger

Pending membership changes are flushed in two ways:

- **On demand** — clicking **Synchronize all users** or **Synchronize changed users** on the SCIM outbound provider in User Federation triggers an immediate flush for that specific target.
- **Automatically** — configure a **Sync Interval** directly in the admin console under *User Federation → your SCIM provider → Sync Settings*. Keycloak's native sync scheduler will call the sweep at that interval. No separate background timer is needed.

If a SCIM push fails (e.g. the target is temporarily unreachable), the pending marker is left in place and the push is retried on the next sweep.

### Provisioning modes (Delta vs. Full)

Both user sync and group sync support two modes, configurable per target under the *LDAP Users Provisioning Mode* and *LDAP Groups Provisioning Mode* settings:

| Mode | `/Users` behavior | `/Groups` behavior |
|---|---|---|
| **Delta** (default) | Flush only users with pending `NEW_ADDED` / `NEW_DELETED` entries | Flush only groups with pending member add/remove entries |
| **Full** | Re-provision every current member of *Filter Group*; deprovision any previously-sent users who left | Send a complete `PATCH replace` of the full member list for every in-scope group |

*Synchronize all users* always runs full mode regardless of this setting. *Synchronize changed users* uses the configured mode.

### How to add LdapSyncNotifierMapper

1. Open the **Keycloak Admin Console**.
2. Go to **User Federation** and select your existing LDAP provider.
3. Open the **Mappers** tab and click **Add mapper**.
4. Set **Mapper Type** to `ldap-sync-notifier` and give it a name (e.g. `SCIM Notifier`).
5. Save.

### Mapper ordering — important

`LdapSyncNotifierMapper` **must be placed after the built-in `group-ldap-mapper`** in the mapper list. Keycloak runs mappers in order during a sync; the group mapper must have already resolved the user's group membership from LDAP before the notifier mapper inspects it.

To check or adjust the order, go to **User Federation → your LDAP provider → Mappers** and verify that `group-ldap-mapper` appears above `LdapSyncNotifierMapper` in the list.

---

## 📜 License

This project is distributed under the [LICENSE](LICENSE).

---

## 👤 Author

**Termindiego25**
[www.diegosr.es](https://www.diegosr.es)

---

> 💡 *If this project helps you, consider giving it a ⭐ on GitHub!*
