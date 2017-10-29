#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function

"""Check labels of Github Issues

How
===

    ./labels.py --github-project=YOUR_USER/YOUR_PROJECT

Details
-------

* You will be prompted for the passwords needed to access Github if needed. If your gitconfig has
  a section with github.user or github.password, those values will automatically be used. It is recommended
  that you use a token (see https://github.com/settings/applications) instead of saving a real password:

  git config --local github.password TOKEN_VALUE

License
=======

 License: http://www.wtfpl.net/

Requirements
============

 * Python 2.7
 * PyGithub
"""
from __future__ import absolute_import, unicode_literals

from itertools import chain
from getpass import getpass, getuser
import argparse
import re
import sys
import yaml
import collections

from github import Github, GithubObject, UnknownObjectException

if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--github-username',
                        action="store",
                        help="Github username (default: %(default)s)")
    parser.add_argument('--github-api-url',
                        action="store",
                        default="https://api.github.com",
                        help="Github API URL (default: %(default)s)")
    parser.add_argument('--github-project',
                        action="store",
                        help="Github Project: e.g. username/project")
    parser.add_argument('--trac-hub-config',
                        type=argparse.FileType('r'),
                        help="YAML configuration file in trac-hub style")
    args = parser.parse_args()

    github_password = None
    if args.trac_hub_config:
        config = yaml.load(args.trac_hub_config)
        if "github" in config:
            if not args.github_project and "repo" in config["github"]:
                args.github_project = config["github"]["repo"]
            if "token" in config["github"]:
                github_password = config["github"]["token"]
    else:
        config = {}

    if not args.github_project:
        parser.error("Github Project must be specified")
    if not github_password:
        github_password = getpass("Github password: ")

    gh = Github(args.github_username, github_password, base_url=args.github_api_url)
    repo = gh.get_repo(args.github_project)
    gh_labels = {i.name: i for i in repo.get_labels()}
    usage = collections.defaultdict(int)
    for i in chain(repo.get_issues(state="open"),
                   repo.get_issues(state="closed")):
        print(i.title, [l.name for l in i.labels])
        for l in i.labels:
            usage[l.name] += 1
    for l, u in usage.items():
        if u < 3:
            print("deleting", l, gh_labels[l])
#            gh_labels[l].delete()
