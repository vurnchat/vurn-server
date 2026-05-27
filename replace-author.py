#!/usr/bin/env python3
import sys
from git_filter_repo import FilterRepo

NEW_NAME = b"vurnchat"
NEW_EMAIL = b"vurnchat@proton.me"

# Expect limit as first argument
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 0

def author_callback(commit, metadata):
    # metadata["commit_index"] counts from HEAD (0 = newest)
    if metadata.get("commit_index", 0) < LIMIT:
        commit.author_name = NEW_NAME
        commit.author_email = NEW_EMAIL
        commit.committer_name = NEW_NAME
        commit.committer_email = NEW_EMAIL

if __name__ == "__main__":
    FilterRepo(commit_callback=author_callback, commit_callback_args=[str(LIMIT)]).run()
