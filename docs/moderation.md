# Moderation guide

Roles are ordered: `user` < `moderator` < `sysop`. Moderation power is scoped per area
(`acl_moderate`), so a moderator of "Tech" cannot touch "General" unless the ACL says so.

## In-session

| Action | Where | Who |
| --- | --- | --- |
| Hide/delete a post (with reason) | post view, `d` | area moderator |
| Restore a soft-deleted post | post view, `d` again / confirm | area moderator |
| Lock / unlock a thread | post view, `l` | area moderator |
| Sticky / unsticky | post view, `s` | area moderator |
| Move a thread to another area | post view, `m` | moderator of both areas |
| Hide a one-liner | one-liners, `d` | moderator |
| Promote a probationary caller early | sysop → users → promote | moderator+ (audited) |
| Suspend an account | sysop → users → suspend | sysop |
| Broadcast a notice | sysop → broadcast | sysop |

Every one of these writes an `audit_log` row: actor, action, target, before/after detail JSON,
and the caller's HMAC'd IP. The in-BBS sysop menu shows the tail; `bbs admin audit --limit 100`
prints the same from a shell.

## From the shell

```sh
bbs admin user list
bbs admin user promote HANDLE            # end probation early
bbs admin user status HANDLE suspended   # or active
bbs admin user role HANDLE --role moderator
bbs admin ban add --handle HANDLE --reason "spam" --expires 720h
bbs admin ban list
bbs admin audit --limit 50
bbs admin prune --dry-run                # what retention would delete
```

## Probation (D3/D9)

New accounts start in `probation`: posts are rate-limited, links are rejected, uploads are
disabled. They become `active` automatically at **3 days and 10 posts** (both configurable) or
immediately when a moderator promotes them. Probation is enforced in the service layer, so a
crafted client cannot bypass it.

## Reading an audit row

```json
{"at":"2025-11-15T21:04:05Z","actor":"sysop","action":"post.delete","target_kind":"post",
 "target_id":"42","detail":"{\"reason\":\"spam\",\"body_sha256\":\"…\"}"}
```

`ip_hash` is `HMAC-SHA256(host key material, client IP)` — stable for correlation, useless as PII.

## Escalation checklist for abuse

1. Confirm from audit log + reports.
2. Hide the content (keeps evidence) rather than hard-deleting.
3. Suspend the handle; ban the IP hash only if it is not a shared NAT.
4. Post a short bulletin if callers were affected.
5. File a note in the moderation log; repeated patterns usually mean a registration-probation
   tweak, not more bans.
