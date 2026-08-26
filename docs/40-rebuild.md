# R40 — destroy, then apply, and what actually came back

Run against the live account, not described. `terraform destroy -auto-approve` followed by
`terraform apply -auto-approve`, with **no dashboard click anywhere in the cycle**.

```
Destroy complete! Resources: 12 destroyed.
Apply complete!   Resources: 12 added, 0 changed, 0 destroyed.
```

The destroy was real, and the two kinds of "down" it produced are worth a line each:

| Hostname | During the outage | Why |
|---|---|---|
| `meridian-clinic.pages.dev` | **530** | the wildcard `*.pages.dev` still resolves; there was no project behind it |
| `staff.` / `api.` | **000** | preview aliases have no DNS at all once the project is gone — `curl` cannot connect |

## What changed underneath, which is the whole difficulty

A rebuild is not "run two commands". Six identifiers the running system depends on are
**created by Cloudflare**, not chosen by me, so every one of them is different afterwards:

| Identifier | Before | After | Changed |
|---|---|---|---|
| KV namespace id | `10075544566e4eed…` | `7395a0ed96bc4fdb…` | yes |
| Access AUD, admin | `37c21b3303870bfd…` | `d9acd8fc5da8a0dd…` | yes |
| Access AUD, partner | `c891caed2608eb2c…` | `31e89c0383a465c2…` | yes |
| Turnstile sitekey | `0x4AAAAAAEcXqRN2…` | `0x4AAAAAAEcsS9z8…` | yes |
| Partner client id | `223a4a0ad12fb2bf…` | `525cfb65b48fbf75…` | yes |
| Reviewer client id | `8bb71d0784fa987b…` | `fe7445842747b22d…` | yes |
| `pages.dev` hostname | `meridian-clinic…` | `meridian-clinic…` | **no** — the project name is in config, so the hostname is mine |

Plus two secrets not shown: the Turnstile secret key and both service-token secrets.

**Every one of those is a value most builds copy out of a dashboard by hand.** That is the
failure mode R40 is actually testing for, and it is not a loud one. A stale AUD does not error
at deploy; it produces `wrong_audience` on every single request afterwards, which reads as a
broken deployment rather than a stale config. So the rebuild reads them out of the state that
just created them — `scripts/sync-env-from-terraform.sh` — and refuses to write at all if the
two AUD tags ever come back identical, because that is the R22 vulnerability arriving as a
config bug rather than a code one.

## The five commands, and why the middle two are ordered

```bash
cd terraform && ./tf.sh destroy -auto-approve && ./tf.sh apply -auto-approve && cd ..
pnpm run env:sync        # the six identifiers above, from terraform output
pnpm run pages:secrets   # BEFORE deploying
pnpm run pages:deploy    # then --branch staff and --branch api
                         # restart the origin and the tunnel supervisor
```

**`pages:secrets` before `pages:deploy` is not stylistic.** Pages binds secrets to a deployment
at deploy time. Deploy first and the Function runs with an empty `EDGE_HMAC_SECRET`, which
produces `error code: 1101` on every request and `DataError: Imported HMAC key length (0)` in
the deployment tail — a symptom that names no layer and cost an hour the first time. The script
also sets both the production *and* preview environments, because `staff.` and `api.` are
preview aliases carrying preview bindings; setting production alone leaves two of three surfaces
broken in exactly that way.

The tunnel supervisor has to be restarted too, and for a reason specific to this path: it
publishes the quick tunnel URLs into KV, and KV is one of the things that was just destroyed.
The new namespace is empty, so until the supervisor republishes, the Function has no origin to
forward to.

## Measured

**291 seconds from `apply` to fully verified** — infrastructure, env sync, secrets, three
deployments, origin and supervisor restarted, and every surface checked. The destroy itself took
seconds; the rebuild is dominated by three sequential Pages deployments and by waiting for three
quick tunnels to register.

Verified afterwards, not assumed:

```
meridian-clinic.pages.dev        200
staff.meridian-clinic.pages.dev  302     (Access enforcing at the edge)
api.meridian-clinic.pages.dev    403     (origin refusing an unauthenticated call)

GET /admin at the unprotected canonical host
  -> {"error":"forbidden","reason":"no_token"}

reviewer token (NEW credentials) -> partner API
  -> {"results":[{"id":"lr-001", …}]}
```

## The honest caveats

**Two things did not come back on their own, and both are named elsewhere rather than hidden
here.** The reviewer's credentials changed, so the handout had to be regenerated — correct
behaviour for a Cloudflare-issued credential, and the argument for generating that file rather
than pasting the values into a document. And the quick tunnel hostnames changed, as they do on
every restart; that is the free path's cost, not the rebuild's.

**What this cycle does not prove** is that the *data* survives. There is none here worth the
name — the KV namespace holds rate-limit counters and origin URLs, both of which are
regenerated. A real clinic's appointment records would not be in Terraform's blast radius, and
a `destroy` that took them with it would be a catastrophe rather than a demonstration. The
right reading of this section is "the security posture rebuilds from code", not "the system is
disposable".
