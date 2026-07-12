# Testing Guide -- keycloak-scim-outbound (ldap-groups-review)

This document describes the full test plan for the LDAP-driven SCIM group and user
membership sync introduced in the `ldap-groups-review` branch. It covers what to test,
why each area matters, how to set up the test infrastructure, and what assertions to
make in each test class.

---

## Table of Contents

1. [Background and Architecture](#1-background-and-architecture)
2. [Test Infrastructure Setup](#2-test-infrastructure-setup)
3. [Area 1 -- PATCH JSON Generation](#3-area-1--patch-json-generation)
4. [Area 2 -- Full and Delta State Transitions](#4-area-2--full-and-delta-state-transitions)
5. [Area 3 -- Partial Lookup Failures](#5-area-3--partial-lookup-failures)
6. [Area 4 -- Lifecycle Cleanup](#6-area-4--lifecycle-cleanup)
7. [Area 5 -- Event-Driven Configuration](#7-area-5--event-driven-configuration)
8. [Area 6 -- Filter Configuration](#8-area-6--filter-configuration)
9. [Suggested Directory Layout](#9-suggested-directory-layout)
10. [Key Invariants the Tests Must Enforce](#10-key-invariants-the-tests-must-enforce)

---

## 1. Background and Architecture

### What the code does

The `ldap-groups-review` branch adds SCIM `/Groups` provisioning on top of the existing
`/Users` provisioning. When Keycloak syncs users from LDAP, group membership changes are
captured as state attributes on `GroupModel` and `UserModel`. A sweep job then reads
those attributes and pushes the corresponding SCIM PATCH calls to configured targets.

### Key classes

| Class | Role |
|---|---|
| `ScimGroupSync` | Flushes pending SCIM `/Groups` changes; entry point for all group sync paths |
| `ScimMembershipSync` | Flushes pending SCIM `/Users` changes |
| `GroupMembershipState` | State record stored as a multi-valued attribute on `GroupModel` |
| `MembershipState` | Parallel state record stored on `UserModel` |
| `ScimMapper` | Builds all SCIM v2 JSON payloads (pure, stateless) |
| `LdapSyncNotifierMapper` | Writes state attributes when LDAP sync fires membership events |
| `ScimClient` | HTTP client that sends SCIM requests to a remote target |
| `ScimTargetProviderFactory` | Holds all configuration keys (`CFG_*`) and reads component config |

### State model

Each `GroupModel` carries two multi-valued attributes:

- `scimGroupSync.membershipState` -- one JSON entry per `(componentId, userId)` pair:
  ```
  {"c":"<componentId>","u":"<userId>","s":"<STATE>"}
  ```
  where `STATE` is `NEW_ADDED`, `SENT`, or `NEW_DELETED`.

- `scimGroupSync.pending` -- work-queue flag; one value `<componentId>:1` per target
  that has at least one non-`SENT` entry for this group.

`UserModel` uses the parallel `MembershipState` attributes (`ldapSyncNotifier.*`).

### Sync modes

`CFG_LDAP_GROUP_PROV_MODE` controls which path `ScimGroupSync` takes:

| Mode | Constant | Behaviour |
|---|---|---|
| `Delta (add members)` | `MODE_DELTA_ONLY` | Flushes `NEW_ADDED` only; no cross-check |
| `Delta (add and remove members)` | `MODE_DELTA_DEPROVISION` | Flushes `NEW_ADDED` + `NEW_DELETED`; runs cross-check |
| `Full` | `MODE_FULL` | Sends a complete `PATCH replace` for all in-scope groups |

---

## 2. Test Infrastructure Setup

### Dependencies

Add the following to `pom.xml` in the `<dependencies>` block with `<scope>test</scope>`:

```xml
<!-- JUnit 5 -->
<dependency>
  <groupId>org.junit.jupiter</groupId>
  <artifactId>junit-jupiter</artifactId>
  <version>5.11.0</version>
  <scope>test</scope>
</dependency>

<!-- Mockito -->
<dependency>
  <groupId>org.mockito</groupId>
  <artifactId>mockito-core</artifactId>
  <version>5.12.0</version>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.mockito</groupId>
  <artifactId>mockito-junit-jupiter</artifactId>
  <version>5.12.0</version>
  <scope>test</scope>
</dependency>
```

Keycloak SPI classes (`KeycloakSession`, `RealmModel`, `GroupModel`, `UserModel`,
`ComponentModel`, `UserStoragePrivateUtil`) are already on the compile classpath and
are available in test scope without additional declarations.

Enable JUnit Platform in the Surefire plugin:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-surefire-plugin</artifactId>
  <version>3.3.1</version>
</plugin>
```

### Common mock setup

Most test classes need the same small set of mocks. Extract a shared base class or a
JUnit 5 `@BeforeEach` helper:

```java
// Shared fields used across multiple test classes
KeycloakSession session;
RealmModel      realm;
ComponentModel  target;
ScimClient      client;   // mock the HTTP layer
GroupModel      group;
UserModel       user;

@BeforeEach
void setUpMocks() {
    session = mock(KeycloakSession.class);
    realm   = mock(RealmModel.class);
    target  = mock(ComponentModel.class);
    client  = mock(ScimClient.class);
    group   = mock(GroupModel.class);
    user    = mock(UserModel.class);

    // Wire realm to return the target component
    when(realm.getComponentsStream()).thenReturn(Stream.of(target));
    when(target.getProviderId()).thenReturn(ScimTargetProviderFactory.ID);
    when(target.getId()).thenReturn("target-1");
    when(target.getName()).thenReturn("Test Target");

    // Minimal valid config
    lenient().when(ScimTargetProviderFactory.get(target, CFG_BASE_URL, null))
             .thenReturn("https://scim.example.com");
    lenient().when(ScimTargetProviderFactory.get(target, CFG_TOKEN, null))
             .thenReturn("token-abc");
    lenient().when(ScimTargetProviderFactory.get(target, CFG_SYNC_GROUPS, "false"))
             .thenReturn("true");
}
```

> **Note on `ScimClient`:** `ScimGroupSync` constructs `ScimClient` internally via
> `new ScimClient(base, token)`. To inject a mock, either extract a factory method and
> override it in a test subclass, or use a constructor-capturing argument captor on a
> spy. The simplest approach is to make `ScimClient` injectable via a package-private
> factory hook added specifically for testing.

### Attribute helpers

`GroupMembershipState.toValue()` and `GroupMembershipState.parse()` are the
serialization boundary. Use them directly in tests -- do not hand-craft JSON strings:

```java
String addEntry  = new GroupMembershipState("target-1", "user-1", NEW_ADDED).toValue();
String sentEntry = new GroupMembershipState("target-1", "user-1", SENT).toValue();
String delEntry  = new GroupMembershipState("target-1", "user-1", NEW_DELETED).toValue();
```

---

## 3. Area 1 -- PATCH JSON Generation

**Test class:** `ScimMapperTest`

`ScimMapper` is a pure static utility with no dependencies. Tests require no mocks --
just call the method and assert the returned JSON string.

### Why this matters

Every SCIM operation the plugin sends is built by `ScimMapper`. A malformed payload
causes silent failures at the remote server. These tests catch regressions in the JSON
structure independently of the sync logic.

### Test cases

#### Group member add

```
buildGroupMemberPatch("add", "<id>", *)
```

Assert:
- `schemas` contains `urn:ietf:params:scim:api:messages:2.0:PatchOp`
- Single operation with `op=add`, `path=members`
- `value` is an array containing `{"value":"<id>"}`
- The `removeForm` argument is ignored for adds

#### Group member remove -- RFC 7644 path filter (default)

```
buildGroupMemberPatch("remove", "<id>", REMOVE_FORM_RFC_PATH_FILTER)
```

Assert:
- `op=remove`
- `path` is `members[value eq "<id>"]`
- **No** `value` field present in the operation

#### Group member remove -- non-RFC value array

```
buildGroupMemberPatch("remove", "<id>", REMOVE_FORM_NON_RFC_VALUE_ARRAY)
```

Assert:
- `op=remove`
- `path=members`
- `value` is `[{"value":"<id>"}]`

#### Group member replace -- multiple members

```
buildGroupMemberReplace(List.of("id-1", "id-2", "id-3"))
```

Assert:
- Single operation with `op=replace`, `path=members`
- `value` array contains exactly three entries, each with a `value` field
- Order matches the input list

#### Group member replace -- empty list

```
buildGroupMemberReplace(List.of())
```

Assert:
- `value` is `[]` (valid empty-group replace, not omitted)

#### Create group

```
buildCreateGroup("Engineering", "kc-group-uuid-1")
```

Assert:
- `schemas` contains `urn:ietf:params:scim:schemas:core:2.0:Group`
- `externalId` equals `"kc-group-uuid-1"`
- `displayName` equals `"Engineering"`

#### Special characters in member ID

Pass a member ID containing `"`, `\`, and newline characters.

Assert:
- The returned JSON string is valid (parseable)
- The ID round-trips correctly through `esc()`

#### Patch user -- with externalId

```
buildPatchUser(user, "kc-user-uuid-1")
```

Assert:
- First operation is `{"op":"add","path":"externalId","value":"kc-user-uuid-1"}`
- Followed by `replace` operations for `name.givenName`, `name.familyName`,
  `emails[primary eq true].value`, and `active`

#### Patch user -- without externalId

```
buildPatchUser(user, null)
```

Assert:
- No `externalId` operation present
- Only the four `replace` operations

#### Deactivate patch

```
buildDeactivatePatch()
```

Assert:
- Single operation: `{"op":"replace","path":"active","value":false}`

---

## 4. Area 2 -- Full and Delta State Transitions

**Test classes:** `ScimGroupSyncStateTest`, `ScimMembershipSyncStateTest`

### Why this matters

The state machine is the core correctness guarantee of the plugin. A wrong transition
can cause duplicate SCIM calls, missed removals, or permanent pending loops. These tests
verify that every state entry ends up in the right state after a sync run, and that the
pending flag is managed correctly.

### Group delta flush (`processPendingGroupMembershipChanges`)

For each test: pre-load the group attribute with a specific state, configure the mode,
stub `client.patchGroup()` to return `true`, and assert the attribute value written
back to the `GroupModel`.

| Test name | Pre-state | Mode | PATCH result | Expected post-state |
|---|---|---|---|---|
| `addFlushedInDeltaOnly` | `NEW_ADDED` | `Delta (add members)` | success | `SENT`; pending flag cleared |
| `deleteSkippedInDeltaOnly` | `NEW_DELETED` | `Delta (add members)` | -- | `NEW_DELETED` unchanged; pending flag still set |
| `deleteSkippedInDeltaOnly_noPatchCall` | `NEW_DELETED` | `Delta (add members)` | -- | `patchGroup` never called |
| `deleteFlushedInDeltaDeprovision` | `NEW_DELETED` | `Delta (add and remove members)` | success | Entry removed; pending flag cleared |
| `mixedEntriesBothFlushed` | `NEW_ADDED` + `NEW_DELETED` | `Delta (add and remove members)` | both success | `NEW_ADDED` -> `SENT`; `NEW_DELETED` removed |
| `sentEntrySkipped` | `SENT` | any | -- | No PATCH call; pending flag cleared |
| `patchFailureRetained` | `NEW_ADDED` | any | failure | `NEW_ADDED` unchanged; pending flag still set |
| `noPendingGroups_noPatchCall` | none | any | -- | `patchGroup` never called |
| `otherTargetEntryUntouched` | `NEW_ADDED` for target-2 | any (target-1 filter) | -- | target-2 entry unchanged |

#### Cross-check invocation

In `MODE_DELTA_DEPROVISION`, verify that `crossCheckGroupMembers` is invoked (i.e. that
`client.getGroupMembers()` is called) after the pending flush. In `MODE_DELTA_ONLY`,
verify it is **not** called.

### Group full sync (`processFullGroupSync`)

| Test name | Setup | Expected behaviour |
|---|---|---|
| `allMembersResolved_replaceSent` | 2 members, both resolvable | `patchGroup(replace)` called with both SCIM IDs; both entries -> `SENT` |
| `replaceFails_stateUntouched` | replace returns false | All entries left unchanged |
| `otherTargetEntriesSurvive` | Group has entries for target-1 and target-2; only target-1 synced | target-2 entries identical before and after |
| `newMemberWithNoEntry_sentWritten` | Member has no prior state entry | New `SENT` entry written after successful replace |
| `outOfScopeNewDeletedDropped` | Member out of `CFG_FILTER_GROUP` scope with `NEW_DELETED` entry | `NEW_DELETED` entry removed (implicit in replace) |
| `outOfScopeNewAddedPreserved` | Member out of scope with `NEW_ADDED` entry | `NEW_ADDED` entry preserved defensively |
| `pendingFlagClearedWhenAllSent` | All entries become `SENT` | Pending flag removed |
| `pendingFlagRetainedWhenNonSentRemains` | One entry stays `NEW_ADDED` after partial failure | Pending flag still present |

### User delta flush (`processPendingMembershipChanges`)

Mirror the group delta cases above for `MembershipState`. Additional assertions:

- State reads and writes go through `UserStoragePrivateUtil.userLocalStorage()`, not
  `session.users()`. Mock `userLocalStorage(session)` to return a separate
  `UserProvider` mock and verify that `setAttribute` is called on the local-storage
  user, not on the federated user object.
- `clearPendingFlag` must also write through local storage.

### User full sync (`processFullUserSync`)

| Test name | Expected behaviour |
|---|---|
| `currentMember_upsertSucceeds` | Entry -> `SENT` |
| `currentMember_upsertFails` | Entry left untouched |
| `previouslySentUserNoLongerMember_deprovisionSucceeds` | `SENT` entry **removed entirely** |
| `previouslySentUserNoLongerMember_deprovisionFails` | `SENT` entry left as-is for retry |
| `noFilterGroup_skipped` | Method returns without any SCIM calls |
| `filterGroupNotFound_skipped` | Method returns without any SCIM calls |

---

## 5. Area 3 -- Partial Lookup Failures

**Test class:** `ScimGroupSyncResolutionSafetyTest`

### Why this matters

The code explicitly documents (as "issue 3") that a transient SCIM lookup failure must
never trigger a destructive remote operation. These tests verify the abort-on-failure
guards in `processFullGroupSync` and `crossCheckGroupMembers`.

### Test cases

#### Full sync aborts on unresolvable member

Setup: a group with two members. The first member resolves fine; the second returns
`Optional.empty()` from `resolveScimUserId`.

Assert:
- `client.patchGroup()` is **never called** for this group
- `failures` counter is incremented (verify via log capture or a spy)
- Other groups in the same sync run are still processed

#### Cross-check aborts removals on unresolvable local member

Setup: remote group has members `[scim-1, scim-2]`. Local KC group has two members;
one of them cannot be resolved to a SCIM ID.

Assert:
- No `patchGroup("remove", ...)` call is made for this group
- Groups where all members resolve are still cross-checked normally

#### Cross-check skips group not found remotely

Setup: `resolveScimGroupId` returns `Optional.empty()` (group not in SCIM yet).

Assert:
- `client.getGroupMembers()` is never called
- No auto-create attempt (verify `client.createGroup()` is not called)
- No exception thrown

#### Ambiguous externalId falls back to displayName

Setup: `client.findGroupByExternalId()` returns `totalResults=2`.

Assert:
- `client.findGroupIdByDisplayName()` is called as fallback
- If displayName lookup succeeds, the returned ID is used

#### Both lookups fail -- group skipped gracefully

Setup: `findGroupByExternalId()` returns 0 results; `findGroupIdByDisplayName()`
returns `Optional.empty()`.

Assert:
- `upsertScimGroup` returns `Optional.empty()`
- The group is skipped without exception
- No PATCH call is made

#### Name-only lookup strategy skips externalId call

Setup: `CFG_LOOKUP_STRATEGY = "name only"`.

Assert:
- `client.findGroupByExternalId()` is **never called**
- `client.findGroupIdByDisplayName()` is called directly

---

## 6. Area 4 -- Lifecycle Cleanup

**Test class:** `ScimGroupSyncDeprovisionTest`

### Why this matters

`deprovisionOutOfScopeGroups` is the only legitimate caller of `clearGroupState`. If
state is cleared incorrectly (e.g. from a sync path), membership history is lost and
future delta syncs will miss changes. These tests verify the deprovision sweep in
isolation and guard the `clearGroupState` call site.

### Test cases

#### Out-of-scope group -- remote DELETE succeeds

Setup: group has `GroupMembershipState` entries for target-1; `isGroupInScope` returns
false; `client.deleteGroup()` returns true.

Assert:
- `client.deleteGroup()` called with the correct SCIM group ID
- `scimGroupSync.membershipState` attribute is cleared on the `GroupModel`
- `scimGroupSync.pending` attribute is cleared on the `GroupModel`

#### Out-of-scope group -- remote DELETE fails

Setup: same as above but `client.deleteGroup()` returns false.

Assert:
- KC attributes are **not** cleared (retry on next cycle)

#### Out-of-scope group -- not found remotely

Setup: `resolveScimGroupId` returns `Optional.empty()`.

Assert:
- `client.deleteGroup()` is never called
- KC attributes **are** cleared (KC-only cleanup)

#### In-scope group -- not touched

Setup: group has state entries; `isGroupInScope` returns true.

Assert:
- `client.deleteGroup()` never called
- Attributes unchanged

#### Group with no state for this target -- not included

Setup: group has no `GroupMembershipState` entries for target-1.

Assert:
- Group is not included in the deprovision scan for target-1

#### `CFG_SYNC_GROUPS = false` -- target skipped

Setup: `CFG_SYNC_GROUPS` returns `"false"` for the target.

Assert:
- No SCIM calls made; no attribute writes

#### Sync paths never call `clearGroupState`

This is a structural invariant. Verify it with a test that runs
`processPendingGroupMembershipChanges` and `processFullGroupSync` with a successful
PATCH response, then asserts that the group's `membershipState` attribute is **not**
empty after the call (i.e. `SENT` entries survive; the attribute is not wiped).

---

## 7. Area 5 -- Event-Driven Configuration

**Test class:** `LdapSyncNotifierMapperTest`

### Why this matters

The sync sweep only processes what `LdapSyncNotifierMapper` has written. If state is
not written correctly on membership events, the sweep either misses changes or processes
stale data.

### Test cases

#### User added to filter group

Simulate a `GROUP_MEMBERSHIP` add event for a user in the configured filter group.

Assert:
- A `MembershipState(componentId, groupId, NEW_ADDED)` entry is written to
  `ldapSyncNotifier.filterGroupMembership`
- A pending flag `<componentId>:1` is written to `ldapSyncNotifier.pending`
- Write goes through `UserStoragePrivateUtil.userLocalStorage()`

#### User removed from filter group

Simulate a `GROUP_MEMBERSHIP` remove event.

Assert:
- A `MembershipState(componentId, groupId, NEW_DELETED)` entry is written
- Pending flag is set

#### Re-add after SENT -- replaces with NEW_ADDED

Pre-load the user with a `SENT` entry for `(target-1, group-1)`.
Simulate an add event.

Assert:
- The `SENT` entry is replaced with `NEW_ADDED`
- No duplicate entries

#### Remove after NEW_ADDED -- replaces with NEW_DELETED (cancel-out)

Pre-load the user with a `NEW_ADDED` entry.
Simulate a remove event.

Assert:
- `NEW_ADDED` is replaced with `NEW_DELETED`

#### Add after NEW_DELETED -- replaces with NEW_ADDED (cancel-out)

Pre-load the user with a `NEW_DELETED` entry.
Simulate an add event.

Assert:
- `NEW_DELETED` is replaced with `NEW_ADDED`

#### Event for non-filter group -- no state written

Simulate an event for a group that does not match `CFG_FILTER_GROUP`.

Assert:
- No `MembershipState` attribute is written
- No pending flag is set

#### Entries for other targets are preserved

Pre-load the user with a `SENT` entry for `target-2`.
Simulate an add event for `target-1`.

Assert:
- The `target-2` entry is unchanged

---

## 8. Area 6 -- Filter Configuration

**Test class:** `ScimGroupSyncFilterTest`

### Why this matters

`isGroupInScope` and `resolveInScopeGroups` determine which KC groups are included in
every sync path. A misconfigured filter silently excludes or includes the wrong groups.
`isGroupInScope` is package-private and can be called directly from the test class
(same package).

### `isGroupInScope` unit tests

These require only a `ComponentModel` mock. No session or realm needed.

| Test name | `CFG_SYNC_GROUPS_FILTER` | `CFG_SYNC_GROUPS_FILTER_REGEX` | Input | Expected |
|---|---|---|---|---|
| `filterGroup_exactMatch` | _(blank)_ | false | `"engineering"` (matches `CFG_FILTER_GROUP`) | `true` |
| `filterGroup_noMatch` | _(blank)_ | false | `"hr"` | `false` |
| `commaList_firstEntry` | `"engineering,hr"` | false | `"engineering"` | `true` |
| `commaList_secondEntry` | `"engineering,hr"` | false | `"hr"` | `true` |
| `commaList_noMatch` | `"engineering,hr"` | false | `"finance"` | `false` |
| `commaList_whitespace` | `" engineering , hr "` | false | `"engineering"` | `true` |
| `regex_match` | `"eng.*"` | true | `"engineering"` | `true` |
| `regex_noMatch` | `"eng.*"` | true | `"hr"` | `false` |
| `regex_invalid` | `"[invalid"` | true | `"anything"` | `false` (no exception) |
| `nullGroupName` | any | any | `null` | `false` |

### `resolveInScopeGroups` integration tests

These require `KeycloakSession`, `RealmModel`, and a `GroupProvider` mock.

| Test name | Config | KC groups in realm | Expected result |
|---|---|---|---|
| `noFilter_findsFilterGroup` | `CFG_FILTER_GROUP=engineering`, no `CFG_SYNC_GROUPS_FILTER` | `engineering` exists | Returns `[engineering]` |
| `noFilter_noFilterGroup` | Both configs blank | -- | Returns empty list |
| `commaList_findsBothGroups` | `CFG_SYNC_GROUPS_FILTER=engineering,hr` | both exist | Returns both `GroupModel` instances |
| `commaList_oneNotFound` | `CFG_SYNC_GROUPS_FILTER=engineering,missing` | only `engineering` exists | Returns `[engineering]` only |
| `regex_matchesSubset` | `CFG_SYNC_GROUPS_FILTER=eng.*`, regex=true | 5 groups, 3 match | Returns exactly those 3 |
| `regex_invalid_returnsEmpty` | `CFG_SYNC_GROUPS_FILTER=[invalid`, regex=true | any | Returns empty list; no exception |

---

## 9. Suggested Directory Layout

```
src/
  test/
    java/
      es/diegosr/keycloak_scim_outbound/
        util/
          ScimMapperTest.java
        ldapsync/
          ScimGroupSyncStateTest.java
          ScimGroupSyncResolutionSafetyTest.java
          ScimGroupSyncDeprovisionTest.java
          ScimGroupSyncFilterTest.java
          ScimMembershipSyncStateTest.java
          LdapSyncNotifierMapperTest.java
```

Place test classes in the same package as the production class they test. This grants
access to package-private methods (e.g. `isGroupInScope`) without reflection.

---

## 10. Key Invariants the Tests Must Enforce

These are documented in the production code comments and represent the non-negotiable
correctness guarantees of the implementation. Every test run must validate them.

### Invariant 1 -- `clearGroupState` is called only from `deprovisionOutOfScopeGroups`

After a successful `processPendingGroupMembershipChanges` or `processFullGroupSync` run,
the `scimGroupSync.membershipState` attribute must **not** be empty. `SENT` entries
must survive. Test this by asserting that `group.setAttribute(ATTRIBUTE_NAME, ...)` is
called with a non-empty list after a successful sync.

### Invariant 2 -- Pending flag cleared only when no non-SENT entries remain

If a group has both a `SENT` entry and a `NEW_ADDED` entry for the same target, the
pending flag must remain set after a sync run that only processes the `NEW_ADDED`
entry. Test the exact boundary: one remaining `NEW_ADDED` -> flag present; zero
remaining non-SENT -> flag absent.

### Invariant 3 -- Resolution failure never triggers a destructive PATCH

If any member's SCIM ID cannot be resolved during `processFullGroupSync` or
`crossCheckGroupMembers`, no `patchGroup` call is made for that group. Test with one
unresolvable member among several resolvable ones and assert zero `patchGroup` calls.

### Invariant 4 -- State writes for users go through local storage

`UserStoragePrivateUtil.userLocalStorage(session)` must be the write path for all
`MembershipState` and `ldapSyncNotifier.pending` attribute writes. Direct writes on
a federated `UserModel` would throw `ReadOnlyException` at runtime. Verify in tests
that `setAttribute` is called on the local-storage user object, not on the federated
one returned by `session.users()`.

### Invariant 5 -- Entries for other targets are never modified

Every sync run is scoped to one or more `componentId` values. Entries whose
`componentId` does not match the current target must be identical before and after the
run. Capture the full attribute list before and after and assert equality for
non-target entries.

### Invariant 6 -- Cross-check only runs in `MODE_DELTA_DEPROVISION`

`client.getGroupMembers()` must never be called when the mode is `MODE_DELTA_ONLY` or
`MODE_FULL`. Verify with a `verify(client, never()).getGroupMembers(...)` assertion in
those mode tests.
