A Dependabot security alert needs to be fixed in the {repo} repository.

{details}

Task:
1. In the {repo} repository, upgrade {package} to EXACTLY {patched_version}
   -- the first patched version -- in {manifest_path} and any lockfile. This is a
   minimal-bump policy: do NOT upgrade to the latest release or to any version higher than
   {patched_version}, and do NOT cross a major version unless {patched_version}
   itself is that major version. If {patched_version} is not installable, use the
   SMALLEST released version that is >= {patched_version} and satisfies the advisory.
2. Cascade check: determine how many OTHER packages this upgrade forces to change
   version (transitive/peer dependency bumps beyond {package} itself). If it
   cascades to MORE than {max_cascade} other packages, STOP -- do not silently proceed.
   Open the PR as a draft flagged for human review, list every cascaded package and the
   reason, and do not merge.
3. Resolve any breaking changes the upgrade introduces so the project still builds.
4. Run the project's test suite / linters and make sure they pass.
5. Open a pull request against the default branch of {repo} with a clear description that
   references {ghsa_id}. Label the PR (create the label in {repo} if it does not
   already exist): use `{label_routine}` for a clean minimal bump; but if the cascade check
   tripped, or the upgrade required non-trivial code changes to resolve breaking changes,
   use `{label_review}` instead and request human review before merge.

Only touch what is needed to remediate this advisory.
