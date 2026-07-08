# 🔐 Keycloak SCIM Outbound Plugin

A lightweight **Keycloak extension** that provisions users and groups to external applications via the **SCIM v2** protocol.

This plugin allows Keycloak to **push user lifecycle changes** (create, update, delete, deactivate) to external systems like **Passbolt**, **Nextcloud**, or any other SCIM-compliant service — all configurable directly from the **Keycloak Admin Console**.

---

## 🚀 Features

- 🔁 **Automatic user provisioning** — Create, update, or deactivate users in external SCIM targets.
- 👥 **Group-based filtering** — Provision only members of a specific Keycloak group.
- ⚙️ **UI configuration** — Configure endpoints, tokens, and mapping directly from *User Federation*.
- 🧩 **Customizable userName strategy**
  - `username` → use Keycloak username
  - `email` → use user’s email as SCIM `userName`
  - `attribute` → use a custom Keycloak user attribute
- 🧱 **SCIM v2 compatible** — Works with `/Users`, `/Groups`, and `/ServiceProviderConfig` endpoints.
- 🔒 **Token-based authentication (Bearer)** — no password sync required.
- 🗂️ **Optional SCIM Group sync** — Push Keycloak group create/rename/delete and membership changes to SCIM `/Groups`. Opt-in, disabled by default.

---

## 🧰 Installation

### 1. Build the plugin
```bash
mvn clean package
````

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

| Field                       | Description                                                           | Required |
| --------------------------- | --------------------------------------------------------------------- | -------- |
| **SCIM Base URL**           | Base endpoint of your SCIM API, e.g. `https://app.example.com/scim/v2` | ✅        |
| **SCIM Token**              | Bearer token for authenticating with the SCIM target                  | ✅        |
| **Filter Group (optional)** | Only users in this group will be provisioned                          | ❌        |
| **userName Strategy**       | How to build SCIM `userName` (`username`, `email`, or `attribute`)    | ✅        |
| **userName Attribute**      | Custom user attribute name (only if strategy = `attribute`)           | ❌        |
| **Deprovision Action**      | What to do on delete / group removal: `deactivate` (PATCH `active=false`, default) or `delete` (`DELETE /Users/{id}`) | ✅        |
| **Sync Groups**             | Enable SCIM `/Groups` sync. When `true`, group create/rename/delete and membership changes are pushed to the SCIM target. **Disabled by default.** | ❌        |
| **Sync Groups Filter**      | Comma-separated list of group names to sync (e.g. `admins,developers`). Leave blank to sync **all** groups. Names are validated against the realm on save. Only used when *Sync Groups* is enabled. | ❌        |

---

## 🔄 Supported Events

| Event                             | Action                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------- |
| **REGISTER**                      | Create new SCIM user                                                            |
| **UPDATE_PROFILE / UPDATE_EMAIL** | Update SCIM user fields                                                         |
| **UPDATE_CREDENTIAL (password)**  | Patch password if supported                                                     |
| **DELETE_ACCOUNT**                | Deprovision SCIM user (deactivate or delete, per *Deprovision Action*)          |
| **Admin CREATE/UPDATE/DELETE**    | Sync CRUD operations                                                            |
| **Group membership add/remove**   | Provision/deprovision users based on group membership (if `filterGroup` is set); also updates SCIM group member list (if `Sync Groups` is enabled) |
| **Group CREATE/UPDATE/DELETE**    | Create, rename, or delete the corresponding SCIM group (only if `Sync Groups` is enabled) |

> ℹ️ **Lifecycle lookup & deprovisioning:** users are matched by SCIM `externalId` (the Keycloak user id) first, falling back to `userName` for users provisioned before `externalId` existed. The `externalId` is also backfilled on update for legacy users. Deprovisioning defaults to **deactivate** (`PATCH active=false`); set *Deprovision Action* to `delete` for providers that require a hard delete (e.g. VMware vCenter).

---

## 🗂️ SCIM Group Sync

Group sync is **opt-in** and disabled by default to avoid affecting existing deployments on SCIM targets that do not support `/Groups`.

### How to enable

In the provider configuration (*User Federation → keycloak-scim-outbound*):

1. Toggle **Sync Groups** to `true`.
2. Optionally, fill **Sync Groups Filter** with the group names you want to sync, separated by commas (e.g. `admins,developers`). Leave it blank to sync all groups. Keycloak will reject names that do not exist in the realm when you save.
3. Save.

### What gets synced

| Keycloak event | SCIM operation |
|---|---|
| Group created | `POST /Groups` — creates an empty group with `externalId` = Keycloak group UUID and `displayName` = group name |
| Group renamed | `PATCH /Groups/{id}` — updates `displayName` |
| Group deleted | `DELETE /Groups/{id}` — found by `externalId` (stable, even after deletion) |
| User added to group | `PATCH /Groups/{id}` — adds the user as a member (`op: add`) |
| User removed from group | `PATCH /Groups/{id}` — removes the member using the SCIM path-filter form: `members[value eq "<userId>"]` (RFC 7644 §3.5.2) |

Groups are matched in SCIM by `externalId` (Keycloak UUID) first, falling back to `displayName`. The `externalId` is set at creation time, so renames do not break the link.

### Provisioning scope

Membership updates in SCIM only apply to **users that are already provisioned**. If a user was never pushed to the SCIM target (e.g. because they are outside the configured `Filter Group`), they will not have a SCIM id and will be silently skipped when updating group membership. No unintended users are created.

### Limitations

- **No initial full-sync**: enabling *Sync Groups* does not retroactively push existing groups or their current members. Only events that happen *after* enabling will be processed. To seed existing groups, trigger a group update or re-create them.
- **Permissions are not assigned**: creating a group via SCIM does not automatically grant it any permissions in the target system. Permission assignment must be done manually in the target after the group is created.
- **Top-level groups only**: nested Keycloak sub-groups fire the same `GROUP` events and are synced as flat groups in SCIM (SCIM v2 Groups do not have a native hierarchy).
- **Target must support `/Groups`**: not all SCIM implementations expose the Groups resource. Check your target's documentation or `ServiceProviderConfig` before enabling.

---

## 🪵 Logging

All plugin logs are prefixed with:

```
[keycloak-scim-outbound][<component>]
```

Example output:

```
2025-09-30T18:09:56Z [keycloak-scim-outbound][SCIM Keycloak] UPDATE targetUserName=scim@domain.com realm=domain OK
```

Enable Keycloak’s log level for debugging (optional):

```bash
kc.sh start --log-level=org.keycloak.events=DEBUG,es.diegosr.keycloak_scim_outbound=DEBUG
```

---

## 🧪 Example targets

| Target         | Base URL                                           | Notes                      |
| -------------- | -------------------------------------------------- | -------------------------- |
| **Passbolt**   | `https://your-passbolt-domain/scim/v2`             | Works out of the box       |
| **Nextcloud**  | `https://cloud.example.com/apps/user_saml/scim/v2` | Requires SCIM app enabled  |
| **Custom app** | Any compliant SCIM v2 endpoint                     | Supports `/Users` and `/Groups` resources |

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
    ├── ui/ScimTargetProviderFactory.java
    ├── ui/ScimTargetProvider.java
    └── util/ScimMapper.java
```

---

## 📜 License

This project is distributed under the [LICENSE](LICENSE).

---

## 👤 Author

**Termindiego25**
[www.diegosr.es](https://www.diegosr.es)

---

> 💡 *If this project helps you, consider giving it a ⭐ on GitHub!*
