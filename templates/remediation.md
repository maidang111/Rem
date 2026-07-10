Work in the repository {repo} (a fork of Apache Superset).

Task: remediate the issue below by making the required code changes,
then open a pull request against the main branch of {repo}.

Issue: {issue_title}
{issue_body}
Reference: {issue_url}

Constraints:
- Change only the files required for this fix. No drive-by refactors,
  formatting changes, or unrelated edits.
- Run the relevant lint and tests in your environment before opening the PR.
- The PR description must state: what was vulnerable or broken, what
  changed, and how the fix was verified.
- If the fix cannot be completed within these constraints, do not open
  a partial PR — stop and report why.

Deliverable: an open pull request URL against {repo}.
- The PR description must begin with the line "Fixes {issue_url}" so the
  pull request is linked to the originating issue.