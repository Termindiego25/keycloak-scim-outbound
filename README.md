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
- 🧱 **SCIM v2 compatible** — Works with `/Users`, and `/ServiceProviderConfig` endpoints. `/Groups` is not yet supported.
- 🔒 **Token-based authentication (Bearer)** — no password sync required.
- 📂 **LDAP/AD support** - Optional [LDAP/AD support](#-optional-ldap--active-directory-integration) via a built-in `LdapSyncNotifierMapper`

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
| --------------------------- | --------------------------------------------------------------------- | -------- |
| **SCIM Base URL** | Base endpoint of your SCIM API, e.g. `https://app.example.com/scim/v2` | ✅ |
| **SCIM Token** | Bearer token for authenticating with the SCIM target | ✅ |
| **Filter Group (optional)** | Only users in this group will be provisioned | ❌ |
| **userName Strategy** | How to build SCIM `userName` (`username`, `email`, or `attribute`) | ✅ |
| **userName Attribute** | Custom user attribute name (only if strategy = `attribute`) | ❌ |
| **Deprovision Action** | What to do on delete / group removal: `deactivate` (PATCH `active=false`, default) or `delete` (`DELETE /Users/{id}`) | ✅ |

---

## 🔄 Supported Events

| Event | Action |
| --------------------------------- | ------------------------------------------------------------------------------- |
| **REGISTER** | Create new SCIM user |
| **UPDATE_PROFILE / UPDATE_EMAIL** | Update SCIM user fields |
| **UPDATE_CREDENTIAL (password)** | Patch password if supported |
| **DELETE_ACCOUNT** | Deprovision SCIM user (deactivate or delete, per *Deprovision Action*) |
| **Admin CREATE/UPDATE/DELETE** | Sync CRUD operations |
| **Group membership add/remove** | Provision/deprovision users based on group membership (if `filterGroup` is set) |

> ℹ️ **Lifecycle lookup & deprovisioning:** users are matched by SCIM `externalId` (the Keycloak user id) first, falling back to `userName` for users provisioned before `externalId` existed. The `externalId` is also backfilled on update for legacy users. Deprovisioning defaults to **deactivate** (`PATCH active=false`); set *Deprovision Action* to `delete` for providers that require a hard delete (e.g. VMware vCenter).

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
| **Custom app** | Any compliant SCIM v2 endpoint | Supports `/Users` resource |

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
    ├── ldapsync/LdapSyncNotifierMapper.java
    ├── ldapsync/LdapSyncNotifierMapperFactory.java
    ├── ldapsync/MembershipState.java
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

During every LDAP sync run, `LdapSyncNotifierMapper` compares each user's current group membership (as resolved from LDAP) against the last recorded state. When it detects a change it writes a small pending marker to a local Keycloak user attribute. A background sweep — running every **5 minutes** via Keycloak's built-in timer, or immediately when you click **Synchronize** on the SCIM outbound provider — reads those markers and pushes the corresponding SCIM provisioning or deprovisioning calls.

> ℹ️ This mapper handles **LDAP-driven membership changes for user provisioning** (`/Users`). It does not manage SCIM `/Groups` resources; group objects in the SCIM target are not created or modified.

### How to add LdapSyncNotifierMapper

1. Open the **Keycloak Admin Console**.
2. Go to **User Federation** and select your existing LDAP provider.
3. Open the **Mappers** tab and click **Add mapper**.
4. Set **Mapper Type** to `ldap-sync-notifier` and give it a name (e.g. `SCIM Notifier`).
5. Save.

### Mapper ordering — important

`LdapSyncNotifierMapper` **must be placed after the built-in `group-ldap-mapper`** in the mapper list. Keycloak runs mappers in order during a sync; the group mapper must have already resolved the user's group membership from LDAP before the notifier mapper inspects it.

To check or adjust the order, go to **User Federation → your LDAP provider → Mappers** and verify that `group-ldap-mapper` appears above `LdapSyncNotifierMapper` in the list.

### The 5-minute sweep and manual sync

Pending membership changes are flushed in two ways:

- **Automatically** — a background task runs every 5 minutes and processes all pending entries across all realms and SCIM targets. No action is required.
- **On demand** — clicking **Synchronize all users** or **Synchronize changed users** on the SCIM outbound provider in User Federation triggers an immediate flush for that specific target.

If a SCIM push fails (e.g. the target is temporarily unreachable), the pending marker is left in place and the push is retried on the next sweep.

---

## 📜 License

This project is distributed under the [LICENSE](LICENSE).

---

## 👤 Author

**Termindiego25**
[www.diegosr.es](https://www.diegosr.es)

---

> 💡 *If this project helps you, consider giving it a ⭐ on GitHub!*
