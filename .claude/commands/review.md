---
description: Review a pull request against REVIEWING.md, this repository's standard
argument-hint: <pull request number>
---

# Review a pull request

Review the pull request named in $ARGUMENTS. With no argument, review the
diff of the current branch against `origin/main`.

`REVIEWING.md`, in this repository's root, is the standard, and reading it
is the first step rather than a reference to consult afterwards: it states
what is under review, what to look for and in what order, what a finding
must contain and how it labels its severity, what becomes of everything
noticed that the diff is not about, and the two forms the verdict takes.
Follow it in preference to the review habits you would otherwise bring.

Two files it leans on, worth loading with it:

- `CLAUDE.md` for the gates and for what a review of *this* tree has to
  know, the two arithmetic paths under `curves/` and `ecc/` above all;
- `CONTRIBUTING.md` for the rules a finding cites, so that a finding
  names the line that states one.

Run the gates on the sha under review before writing the verdict, and
read exit codes rather than filtered output.
