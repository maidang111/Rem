A Dependabot security alert affects {package}, which is a
policy-sensitive, high-blast-radius dependency in the {repo} repository. It is used
in many places, so a blind version bump is risky and must be carefully reviewed.

{details}

Task (careful-review upgrade -- do NOT blindly bump):
1. First audit the blast radius: find everywhere {package} is imported/used across
   {repo} and summarize the surface area that could be affected by the upgrade.
2. Read the upstream changelog/release notes between the current version and
   {patched_version}; list any breaking changes or deprecations that touch how this
   repo uses the package.
3. Upgrade {package} to EXACTLY {patched_version} -- the first patched
   version -- in {manifest_path} and any lockfile, then adapt every affected call
   site. This is a minimal-bump policy: do NOT upgrade to the latest release or to any
   version higher than {patched_version}, and do NOT cross a major version unless
   {patched_version} itself is that major version. If {patched_version} is
   not installable, choose the SMALLEST released version that is >= {patched_version}
   and satisfies the advisory, and call out in the PR why.
4. Cascade check: determine how many OTHER packages this upgrade forces to change
   version (transitive/peer dependency bumps beyond {package} itself). If it
   cascades to MORE than {max_cascade} other packages, STOP -- do not silently proceed.
   Open the PR as a draft flagged for human review, list every cascaded package and the
   reason, and do not merge.
5. Run the full test suite and linters; do not paper over failures.
6. Open a pull request against the default branch of {repo} that references {ghsa_id},
   explains the blast-radius findings and breaking changes, and explicitly requests
   human review before merge. Do not auto-merge. Apply the label `{label_review}` to the PR
   (create the label in {repo} if it does not already exist).

Only touch what is needed to remediate this advisory and adapt to the upgrade.
