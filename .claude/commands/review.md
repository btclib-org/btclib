---
description: Review a pull request against REVIEWING.md, the organization's standard
argument-hint: <pull request number>
---

# Review a pull request

Review the pull request named in $ARGUMENTS. With no argument, review the
diff of the current branch against `origin/main`.

`REVIEWING.md`, in this repository's root, is the standard, and reading it
is the first step rather than a reference to consult afterwards: it states
what is under review, what to look for and in what order, what a finding
must contain and how it labels its severity, what becomes of everything
noticed that the diff is not about, and what a verdict is for. Follow it
in preference to the review habits you would otherwise bring.

Two files it leans on, worth loading with it:

- `CONTRIBUTING.md` for the rules a finding cites and, in its last
  section, for the gates of this tree;
- `CLAUDE.md` for what a session has to know before it touches the
  tree.

Run the gates on the sha under review before writing the verdict, unless
they have already been run on it and that run is on the record — which is
the case `REVIEWING.md` sets out, and it says what relying on one costs.
Read exit codes rather than filtered output. Write nothing to the branch:
no edit, no push, no amend, no merge, and `git status --porcelain` empty
at the end. Where a gate was not run, the summary says so in those words
rather than leaving it to be assumed.
