#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function

"""Migrate Trac tickets to Github Issues

What
====

This script migrates issues from Trac to Github:

* Component & Issue-Type are converted to labels
* Comments to issues are copied over
* Basic conversion of Wiki Syntax in comments and descriptions
* All titles will be suffixed with `(Trac #<>)` for ease of searching
* All created issues will have the full Trac attributes appended to the issue body in JSON format

How
===

    ./migrate.py --trac-url=https://USERNAME:PASSWORD@trac.example.org --github-project=YOUR_USER/YOUR_PROJECT

Details
-------

* You will be prompted for the passwords needed to access Github and Trac if needed. If your gitconfig has
  a section with github.user or github.password, those values will automatically be used. It is recommended
  that you use a token (see https://github.com/settings/applications) instead of saving a real password:

  git config --local github.password TOKEN_VALUE

* You may use the --username-map option to specify a text file containing tab-separated lines with
  Trac username and equivalent Github username pairs. It is likely that you would not want to include
  usernames for people who are no longer working on your project as they may receive assignment notifications
  for old tickets. The Github API does not provide any way to suppress notifications.

License
=======

 License: http://www.wtfpl.net/

Requirements
============

 * Python 2.7
 * Trac with xmlrpc plugin enabled
 * PyGithub
"""
from __future__ import absolute_import, unicode_literals

from itertools import chain
from datetime import datetime
from getpass import getpass, getuser
from time import mktime
from urlparse import urljoin, urlsplit, urlunsplit
from warnings import warn
import argparse
import json
import re
import subprocess
import sys
import xmlrpclib
import yaml

from github import Github, GithubObject


def convert_value_for_json(obj):
    """Converts all date-like objects into ISO 8601 formatted strings for JSON"""

    if hasattr(obj, 'timetuple'):
        return datetime.fromtimestamp(mktime(obj.timetuple())).isoformat()+"Z"
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        return obj


def sanitize_url(url):
    scheme, netloc, path, query, fragment = urlsplit(url)

    if '@' in netloc:
        # Strip HTTP basic authentication from netloc:
        netloc = netloc.rsplit('@', 1)[1]

    return urlunsplit((scheme, netloc, path, query, fragment))


def make_blockquote(text):
    return re.sub(r'^', '> ', text, flags=re.MULTILINE)


class Migrator():
    def __init__(self, trac_url, github_username=None, github_password=None, github_project=None,
                 github_api_url=None, username_map=None, config=None):
        trac_api_url = trac_url + "/login/rpc"
        print("TRAC api url: %s" % trac_api_url, file=sys.stderr)
        self.trac = xmlrpclib.ServerProxy(trac_api_url)
        self.trac_public_url = sanitize_url(trac_url)

        self.github = gh = Github(github_username, github_password, base_url=github_api_url)
        self.github_repo = self.github.get_repo(github_project)

        self.username_map = {i: gh.get_user(j) for i, j in username_map.items()}
        self.label_map = config["labels"]
        self.rev_map = {}
        self.use_import_api = True

    def convert_ticket_id(self, trac_id):
        trac_id = int(trac_id)
        if trac_id in self.trac_issue_map:
            return "#%s" % self.trac_issue_map[trac_id].number
        else:
            return urljoin(self.trac_public_url, '/ticket/%d' % trac_id)

    def fix_wiki_syntax(self, markup):
#        markup = re.sub(r'(?:refs #?|#)(\d+)', lambda i: self.convert_ticket_id(i.group(1)),
#                        markup)
        markup = re.sub(r'#!CommitTicketReference.*rev=([^\s]+)\n', lambda i: i.group(1),
                        markup, flags=re.MULTILINE)

        markup = markup.replace("{{{\n", "\n```text\n")
        markup = markup.replace("{{{", "```")
        markup = markup.replace("}}}", "```")

        markup = markup.replace("[[BR]]", "\n")

        markup = re.sub(r'\[changeset:"([^"/]+?)(?:/[^"]+)?"]', r"changeset \1", markup)

        return markup

    def get_gh_milestone(self, milestone):
        if milestone:
            if milestone not in self.gh_milestones:
                m = self.trac.ticket.milestone.get(milestone)
                print("Adding milestone", m, file=sys.stderr)
                desc = self.fix_wiki_syntax(m["description"])
                due = datetime.fromtimestamp(mktime((m["due"]).timetuple()))
                status = "closed" if m["completed"] else "open"
                gh_m = self.github_repo.create_milestone(milestone, state=status, description=desc)#, due_on=due)
                self.gh_milestones[gh_m.title] = gh_m
            return self.gh_milestones[milestone]
        else:
            return GithubObject.NotSet

    def get_gh_label(self, label, color='FFFFFF'):
        if label not in self.gh_labels:
            self.gh_labels[label] = self.github_repo.create_label(label, color=color)
        return self.gh_labels[label]

    def run(self):
        self.load_github()
        self.migrate_tickets()

    def load_github(self):
        print("Loading information from Github…", file=sys.stderr)

        repo = self.github_repo
        self.gh_milestones = {i.title: i for i in chain(repo.get_milestones(),
                                                        repo.get_milestones(state="closed"))}
        self.gh_labels = {i.name: i for i in repo.get_labels()}
        self.gh_issues = {i.title: i for i in chain(repo.get_issues(state="open"),
                                                    repo.get_issues(state="closed"))}

    def get_github_username(self, trac_username):
        if trac_username in self.username_map:
            return self.username_map[trac_username]
        else:
            warn("Cannot map Trac username >{0}< to GitHub user. Will add username >{0}< as label.".format(trac_username))
            return GithubObject.NotSet

    def get_mapped_labels(self, attribute, value):
        if value is None or value.strip() == "":
            return []
        if attribute in self.label_map:
            result = self.label_map[attribute].get(value, [])
            if not isinstance(result, list):
               result = [result]
        else:
            result = [value]
        if "#color" in self.label_map[attribute]:
            for l in result:
                self.get_gh_label(l, self.label_map[attribute]["#color"])
        return result

    def get_trac_comments(self, trac_id):
        changelog = self.trac.ticket.changeLog(trac_id)
        comments = {}
        for time, author, field, old_value, new_value, permanent in changelog:
            if field == 'comment':
                if not new_value:
                    continue
                body = '%s commented:\n\n%s\n\n' % (author,
                                                    make_blockquote(self.fix_wiki_syntax(new_value)))
            else:
                if "\n" in old_value or "\n" in new_value:
                    body = '%s changed %s from:\n\n%s\n\nto:\n\n%s\n\n' % (author, field,
                                                                           make_blockquote(old_value),
                                                                           make_blockquote(new_value))
                else:
                    body = '%s changed %s from "%s" to "%s"' % (author, field, old_value, new_value)
            comments.setdefault(time.value, []).append(body)
        return comments

    def import_issue(self, title, assignee, body, milestone, labels, attributes, comments):
        post_parameters = {
            "issue": {
              "title": title,
              "body": body,
              "labels": labels
            },
            "comments": []
        }
        if assignee is not GithubObject.NotSet:
            if isinstance(assignee, (str, unicode)):
                post_parameters["issue"]["assignee"] = assignee
            else:
                post_parameters["issue"]["assignee"] = assignee._identity
        if milestone is not GithubObject.NotSet:
            post_parameters["issue"]["milestone"] = milestone._identity
        post_parameters["issue"]["closed"] = attributes['status'] == "closed"
        post_parameters["issue"]["created_at"] = convert_value_for_json(attributes['time'])
        post_parameters["issue"]["updated_at"] = convert_value_for_json(attributes['changetime'])

        for time, values in sorted(comments.items()):
            if len(values) > 1:
                fmt = "\n* %s" % "\n* ".join(values)
            else:
                fmt = "".join(values)
            post_parameters["comments"].append({"body": fmt, "created_at": convert_value_for_json(attributes["time"])})
        headers, data = self.github_repo._requester.requestJsonAndCheck(
            "POST",
            self.github_repo.url + "/import/issues",
            input=post_parameters,
            headers={'Accept': 'application/vnd.github.golden-comet-preview+json'}
        )
        return data["id"]

    def migrate_tickets(self):
        print("Loading information from Trac…", file=sys.stderr)

        get_all_tickets = xmlrpclib.MultiCall(self.trac)

        for ticket in self.trac.ticket.query("max=0&order=id"):
            get_all_tickets.ticket.get(ticket)

        # Take the memory hit so we can rewrite ticket references:
        all_trac_tickets = list(get_all_tickets())
        self.trac_issue_map = trac_issue_map = {}

        print ("Creating GitHub tickets…", file=sys.stderr)
        for trac_id, time_created, time_changed, attributes in all_trac_tickets:
            title = "%s (Trac #%d)" % (attributes['summary'], trac_id)

            # Intentionally do not migrate description at this point so we can rewrite
            # ticket ID references after all tickets have been created in the second pass below:
            body = "Migrated from %s\n" % urljoin(self.trac_public_url, "/ticket/%d" % trac_id)
            text_attributes = {k: convert_value_for_json(v) for k, v in attributes.items()}
            body += "```json\n" + json.dumps(text_attributes, indent=4) + "\n```\n"

            milestone = self.get_gh_milestone(attributes['milestone'])

            assignee = self.get_github_username(attributes['owner'])

            labels = ['Migrated from Trac', 'Incomplete Migration']

            # User does not exist in GitHub -> Add username as label
            if (assignee is GithubObject.NotSet and (attributes['owner'] and attributes['owner'].strip())):
                labels.extend([attributes['owner']])

            for attr in ('type', 'component', 'resolution', 'priority'):
                labels += self.get_mapped_labels(attr, attributes.get(attr))
            ghlabels = map(self.get_gh_label, labels)

            for i, j in self.gh_issues.items():
                if i == title:
                    gh_issue = j
                    if (assignee is not GithubObject.NotSet and
                        (not gh_issue.assignee
                         or (gh_issue.assignee.login != assignee.login))):
                        gh_issue.edit(assignee=assignee)
                    break
            else:
                if self.use_import_api:
                    body = "%s\n\n%s" % (self.fix_wiki_syntax(attributes['description']), body)
                    gh_issue = self.import_issue(title, assignee, body,
                                                 milestone, labels,
                                                 attributes, self.get_trac_comments(trac_id))
                    print ("\tInitiated issue: %s (%s)" % (title, gh_issue), file=sys.stderr)
                else:
                    gh_issue = self.github_repo.create_issue(title, assignee=assignee, body=body,
                                                             milestone=milestone, labels=ghlabels)
                    print ("\tCreated issue: %s (%s)" % (title, gh_issue.html_url), file=sys.stderr)
                self.gh_issues[title] = gh_issue

            trac_issue_map[int(trac_id)] = gh_issue

        print("Migrating descriptions and comments…", file=sys.stderr)

        incomplete_label = self.get_gh_label('Incomplete Migration')

        for trac_id, time_created, time_changed, attributes in all_trac_tickets:
            if self.use_import_api:
                gh_issue = self.github_repo.get_issue(trac_issue_map[int(trac_id)])
            else:
                gh_issue = trac_issue_map[int(trac_id)]

            if incomplete_label.url not in [i.url for i in gh_issue.labels]:
                continue

            gh_issue.remove_from_labels(incomplete_label)

            print("\t%s (%s)" % (gh_issue.title, gh_issue.html_url),file=sys.stderr)

            if not self.use_import_api:
                gh_issue.edit(body="%s\n\n%s" % (self.fix_wiki_syntax(attributes['description']), gh_issue.body))
                for time, values in sorted(self.get_trac_comments(trac_id).items()):
                    if len(values) > 1:
                        fmt = "\n* %s" % "\n* ".join(values)
                    else:
                        fmt = "".join(values)
                    gh_issue.create_comment("Trac update at %s: %s" % (time, fmt))

                if attributes['status'] == "closed":
                    gh_issue.edit(state="closed")


def check_simple_output(*args, **kwargs):
    return "".join(subprocess.check_output(shell=True, *args, **kwargs)).strip()


def get_github_credentials():
    github_username = getuser()
    github_password = None

    try:
        github_username = check_simple_output('git config --get github.user')
    except subprocess.CalledProcessError:
        pass

    if not github_password:
        try:
            github_password = check_simple_output('git config --get github.password')
        except subprocess.CalledProcessError:
            pass

        if github_password is not None and github_password.startswith("!"):
            github_password = check_simple_output(github_password.lstrip('!'))

    return github_username, github_password


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)

    github_username, github_password = get_github_credentials()

    parser.add_argument('--trac-username',
                        action="store",
                        default=getuser(),
                        help="Trac username (default: %(default)s)")

    parser.add_argument('--trac-url',
                        action="store",
                        help="Trac base URL (`USERNAME` and `PASSWORD` will be expanded)")

    parser.add_argument('--github-username',
                        action="store",
                        default=github_username,
                        help="Github username (default: %(default)s)")

    parser.add_argument('--github-api-url',
                        action="store",
                        default="https://api.github.com",
                        help="Github API URL (default: %(default)s)")

    parser.add_argument('--github-project',
                        action="store",
                        help="Github Project: e.g. username/project")

    parser.add_argument('--username-map',
                        type=argparse.FileType('r'),
                        help="File containing tab-separated Trac:Github username mappings")

    parser.add_argument('--trac-hub-config',
                        type=argparse.FileType('r'),
                        help="YAML configuration file in trac-hub style")

    args = parser.parse_args()

    if args.trac_hub_config:
        config = yaml.load(args.trac_hub_config)
        if "github" in config:
            if not args.github_project and "repo" in config["github"]:
                args.github_project = config["github"]["repo"]
            if not github_password and "token" in config["github"]:
                github_password = config["github"]["token"]
    else:
        config = {}

    if not args.github_project:
        parser.error("Github Project must be specified")
    trac_url = args.trac_url.replace("USERNAME", args.trac_username)
    if "PASSWORD" in trac_url:
        trac_url = trac_url.replace("PASSWORD", getpass("Trac password: "))
    if not github_password:
        github_password = getpass("Github password: ")

    try:
        import bpdb as pdb
    except ImportError:
        import pdb

    if args.username_map:
        user_map = filter(None, (i.strip() for i in args.username_map.readlines()))
        user_map = [re.split("\s+", j, maxsplit=1) for j in user_map]
        user_map = dict(user_map)
    elif "users" in config:
        user_map = config["users"]
    else:
        user_map = {}

    try:
        m = Migrator(trac_url=trac_url, github_username=args.github_username, github_password=github_password,
                     github_api_url=args.github_api_url, github_project=args.github_project,
                     username_map=user_map, config=config)
        m.run()
    except Exception as e:
        print("Exception: %s" % e, file=sys.stderr)

        tb = sys.exc_info()[2]

        sys.last_traceback = tb
        pdb.pm()
        raise
