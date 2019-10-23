#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
from __future__ import absolute_import, unicode_literals

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

 * Python 3.7
 * Trac with xmlrpc plugin enabled
 * PyGithub
"""

from itertools import chain
from datetime import datetime
from getpass import getpass, getuser
from urllib.parse import urljoin, urlsplit, urlunsplit
from warnings import warn
import argparse
import json
import re
import subprocess
import sys
import xmlrpc.client as xmlrpclib
import yaml
import ssl
import time
# import logging
# logging.basicConfig(level=logging.DEBUG)
from pathlib import Path

from github import Github, GithubObject, UnknownObjectException

# github sometimes hangs if we try to set the owner directly on import
# currently we need to run this script twice to fix the owners
# when setting the variable to true, no second run is needed
ASSIGN_IMMEDIATELY = False

# This is for making the attachment links be to the raw file
ATTACHMENTS_GITHUB_SITE = "https://raw.githubusercontent.com"
ATTACHMENTS_GITHUB_PATH = "master"

# Alternativel settings for if you want your attachments to be displayed
# in the context of the repo where they are stored
# ATTACHMENTS_GITHUB_SITE = "https://github.com"
# ATTACHMENTS_GITHUB_PREFIX = "blob/master"

def convert_value_for_json(obj):
    """Converts all date-like objects into ISO 8601 formatted strings for JSON"""

    if hasattr(obj, 'timetuple'):
        return datetime.fromtimestamp(time.mktime(obj.timetuple())).isoformat()+"Z"
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
    def __init__(
            self,
            trac_url,
            github_username=None,
            github_password=None,
            github_project=None,
            github_api_url=None,
            username_map=None,
            config=None,
            should_verify_ssl=False,
            should_reassign_existing_issues=False,
            is_dry_run=False,
            should_import_attachments=False,
            attachments_local_path=None,
            attachments_github_repo=None,
    ):
        if trac_url[-1]!='/':
            trac_url=trac_url+'/'
        trac_api_url = trac_url + "xmlrpc"
        print("TRAC api url: %s" % trac_api_url, file=sys.stderr)
        # Allow self-signed SSL Certs (idea copied from tracboat)
        context = None if should_verify_ssl else ssl._create_unverified_context()
        self.trac = xmlrpclib.ServerProxy(trac_api_url, context=context)
        self.trac_public_url = sanitize_url(trac_url)

        self.github = gh = Github(github_username, github_password, base_url=github_api_url)
        self.github_repo = self.github.get_repo(github_project)

        def get_user_or_null(username):
            try:
                return gh.get_user(username)
            except UnknownObjectException:
                return username
            
        self.username_map = {i: get_user_or_null(j) for i, j in username_map.items()}
        if "labels" in config:
            self.label_map = config["labels"]
        else:
            self.label_map = {}
        self.rev_map = {}
        if "github" in config and "revisions" in config["github"]:
            for l in open(config["github"]["revisions"]):
                key, val = l.split()
                self.rev_map[key] = val
        self.use_import_api = True
        # Modify behavior of migrate_tickets()
        self.should_reassign_existing_issues = should_reassign_existing_issues
        self.is_dry_run = is_dry_run
        self.should_import_attachments = should_import_attachments
        self.attachments_local_path = Path(attachments_local_path)
        self.attachments_github_repo = attachments_github_repo

        
    def convert_revision_id(self, rev_id):
        if rev_id in self.rev_map:
            return "[%s](../commit/%s) (aka r%s)" % (self.rev_map[rev_id][:7], self.rev_map[rev_id], rev_id)
        return "[%s](../commit/%s)" % (rev_id[:7], rev_id)

    def fix_wiki_syntax(self, markup):
        
        #also handle option > prefix, e.g. when the trac description was later modified, 
        #and handle syntax hilighting, e.g. "> {{{#!json " gets converted to  > "```json"
        markup = re.sub(r"(|> ){{{(|#!)(|[^#!]*)\n", r"\n\1```\3\n", markup)
        
        markup = markup.replace("{{{\n", "\n```text\n")
        markup = markup.replace("{{{", "```")
        markup = markup.replace("}}}", "```")
        markup = markup.replace("[[BR]]", "\n")

        markup = re.sub(r'^ [-\*] ', '* ', markup)
        markup = re.sub(r'\n [-\*] ', '\n* ', markup)

        markup = re.sub(r'\[changeset:"([^"/]+?)(?:/[^"]+)?"[^\]]*]', lambda i: self.convert_revision_id(i.group(1)), markup)
        markup = re.sub(r'\[(\d+)\]', lambda i: self.convert_revision_id(i.group(1)), markup)
        return markup

    def get_gh_milestone(self, milestone):
        if milestone and not self.is_dry_run:
            if milestone not in self.gh_milestones:
                m = self.trac.ticket.milestone.get(milestone)
                print("Adding milestone", m, file=sys.stderr)
                desc = self.fix_wiki_syntax(m["description"])
                # due = datetime.fromtimestamp(time.mktime((m["due"]).timetuple()))
                status = "closed" if m["completed"] else "open"
                gh_m = self.github_repo.create_milestone(milestone, state=status, description=desc)#, due_on=due)
                self.gh_milestones[gh_m.title] = gh_m
            return self.gh_milestones[milestone]
        else:
            return GithubObject.NotSet

    def get_gh_label(self, label, color):
        if label.lower() not in self.gh_labels:
            self.gh_labels[label.lower()] = self.github_repo.create_label(label, color=color)
        return self.gh_labels[label.lower()]

    def run(self, ticket_range=None):
        self.load_github()
        self.migrate_tickets(ticket_range)

    def load_github(self):
        print("Loading information from Github…", file=sys.stderr)

        repo = self.github_repo
        self.gh_milestones = {i.title: i for i in chain(repo.get_milestones(),
                                                        repo.get_milestones(state="closed"))}
        self.gh_labels = {i.name.lower(): i for i in repo.get_labels()}
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
        color = 'FFFFFF'
        if attribute in self.label_map:
            color = self.label_map[attribute].get("#color", color)
            result = self.label_map[attribute].get(value, [])
            if not isinstance(result, list):
               result = result.split(", ")
        else:
            result = value.split(", ")
        r = []
        for l in result:
            if "," in l or " " in l:
                warn("Skipping invalid label value '%s' for attribute '%s'." % (l, attribute))
            else:
                self.get_gh_label(l, color)
                r.append(l)
        return r

    def get_trac_comments(self, trac_id):
        changelog = self.trac.ticket.changeLog(trac_id)
        comments = {}
        for time, author, field, old_value, new_value, permanent in changelog:
            if author in self.username_map:
                try:
                    author = self.username_map[author].login
                except AttributeError:
                    author = self.username_map[author]
            if field == 'comment':
                if not new_value:
                    continue
                if '#!CommitTicketReference' in new_value:
                    lines = new_value.splitlines()
                    body = '@%s committed %s\n%s' % (author, self.fix_wiki_syntax(lines[0][3:]), lines[3])
                else:
                    body = '@%s commented:\n\n%s\n\n' % (author,
                                                         make_blockquote(self.fix_wiki_syntax(new_value)))
            else:
                if "\n" in old_value or "\n" in new_value:
                    body = '@%s changed %s from:\n\n%s\n\nto:\n\n%s\n\n' % (author, field,
                                                                           make_blockquote(self.fix_wiki_syntax(old_value)),
                                                                           make_blockquote(self.fix_wiki_syntax(new_value)))
                else:
                    body = '@%s changed %s from "%s" to "%s"' % (author, field, old_value, new_value)
            comments.setdefault(time.value, []).append(body)
        return comments

    def get_trac_attachments_as_comments(self, trac_id):
        """Return comments for each attachment and store data as files

        For all the attachments to a given ticket, do two things.
        First, save the attachment data with the correct filenames in
        the 'tickets/NNNNN/' subdirectory of
        `self.attachments_local_path`, where NNNNN is zero-padded
        `trac_id` (only save to the file if it does not already
        exist).  Second, return a dict of comments containing links to
        the attachment files in the GitHub repo
        `self.attachments_github_repo`, which should be configured as
        a git remote for `self.attachments_local_path` (the user is
        responsible for git-pushing the saved attachment data to
        GitHub).  The returned dict of comments is keyed on
        modification time and is designed to be merged with the
        results of `get_trac_comments`
        """
        attachment_list = self.trac.ticket.listAttachments(trac_id)
        comments = {}
        if attachment_list:
            for filename, description, size, time, author in attachment_list:
                # The above are the variable names given in the tracrpc source
                 data = self.trac.ticket.getAttachment(trac_id, filename)
                 filename_path = (self.attachments_local_path
                                  / "tickets" / f"{trac_id:05d}" / filename)
                 filename_path.parent.mkdir(parents=True, exist_ok=True)
                 # Only write data to file if it does not already
                 # exist. If you want to rewrite it, you should delete
                 # the file on disk first
                 if not filename_path.exists():
                     with open(filename_path, "wb") as f:
                         f.write(data.data)
                 url = "/".join([
                     ATTACHMENTS_GITHUB_SITE,
                     self.attachments_github_repo,
                     ATTACHMENTS_GITHUB_PATH,
                     f"tickets/{trac_id:05d}",
                     filename,
                 ])
                 description += "\n" + f"Attachment: [{filename}]({url})"
                 comments.setdefault(time.value, []).append(description)
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
        if assignee is not GithubObject.NotSet and ASSIGN_IMMEDIATELY:
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
        failure = True
        while failure:
            try:
                headers, data = self.github_repo._requester.requestJsonAndCheck(
                    "POST",
                    self.github_repo.url + "/import/issues",
                    input=post_parameters,
                    headers={'Accept': 'application/vnd.github.golden-comet-preview+json'}
                )
                failure = False
            except ssl.SSLError as e:
                print("Retrying import due to %s" % e, file=sys.stderr)
                time.sleep(2)
        return data["id"]

    def migrate_tickets(self, ticket_range=None):
        print("Loading information from Trac…", file=sys.stderr)

        get_all_tickets = xmlrpclib.MultiCall(self.trac)

        ticket_list = self.trac.ticket.query("max=0&order=id")

        # Optional argument ticket_range (2-sequence) can restrict
        # range of tickets to be processed
        if ticket_range is None:
            first_ticket, last_ticket = min(ticket_list), max(ticket_list)
        else:
            first_ticket, last_ticket = ticket_range
            
        for ticket in ticket_list:
            # Only get tickets within requested range
            if first_ticket <= ticket <= last_ticket:
                get_all_tickets.ticket.get(ticket)

        print (f"Creating GitHub tickets {first_ticket} to {last_ticket} …", file=sys.stderr)
        for trac_id, time_created, time_changed, attributes in sorted(get_all_tickets(), key=lambda t: int(t[0])):
            # need to keep trac # in title to have unique titles
            title = "%s (trac #%d)" % (attributes['summary'], trac_id)

            r=self.get_github_username(attributes['reporter'])
            if r ==GithubObject.NotSet:
                rep=attributes['reporter']
            else:
                try: 
                    rep='@'+r.login
                except:
                    rep=attributes['reporter']

            body ='\nreported by: '+rep
            
            newCC=[]
            for u in attributes['cc'].strip().split(', '):
                if u:
                    newU=self.get_github_username(u)
                    if newU is GithubObject.NotSet:
                        newCC.append(u)
                    else:
                        newCC.append('@'+newU.login)
            if newCC:
                body += "\ncc: %s"%' '.join(newCC)

            body += '\n\n'+self.fix_wiki_syntax(attributes['description'])
            body += "\n\nMigrated from %s\n" % urljoin(self.trac_public_url, "ticket/%d" % trac_id)
            text_attributes = {k: convert_value_for_json(v) for k, v in attributes.items()}
            body += "```json\n" + json.dumps(text_attributes, indent=4) + "\n```\n"

            milestone = self.get_gh_milestone(attributes['milestone'])
            assignee = self.get_github_username(attributes['owner'])

            labels = []
            # User does not exist in GitHub -> Add username as label
            if (assignee is GithubObject.NotSet
                    and (attributes['owner'] and attributes['owner'].strip())
            ):
                labels = self.get_mapped_labels('owner', attributes['owner'])

            for attr in ('type', 'component', 'resolution', 'priority', 'keywords'):
                labels += self.get_mapped_labels(attr, attributes.get(attr))

            if title in self.gh_issues and not self.is_dry_run:
                # Set should_reassign_existing_issues=False when the script
                # needs to run multiple times without assigning
                # tickets (which is slow and error prone)
                gh_issue = self.gh_issues[title]
                print ("\tIssue exists: %s" % str(gh_issue),
                       file=sys.stderr)
                if self.should_reassign_existing_issues:
                    if (assignee is not GithubObject.NotSet and
                        (not gh_issue.assignee
                         or (gh_issue.assignee.login != assignee.login))):
                        print ("\t\tChanging assignee: %s" % (assignee), file=sys.stderr)
                        gh_issue.edit(assignee=assignee)
                continue
            else:
                comments = self.get_trac_comments(trac_id)
                if self.should_import_attachments:
                    # This will overwrite any comment that has the
                    # same timestamp as an attachment, but those
                    # should all be "changed attachment" edits so that
                    # is OK I think
                    comments.update(self.get_trac_attachments_as_comments(trac_id))
                if self.is_dry_run:
                    print(f"\tDry run for issue: {title}", file=sys.stderr)
                    print(f"\t\tAssignee: {assignee}", file=sys.stderr)
                    print(f"\t\tBody: {body}", file=sys.stderr)
                    print(f"\t\tMilestone: {milestone}", file=sys.stderr)
                    print(f"\t\tLabels: {labels}", file=sys.stderr)
                    print(f"\t\tComments: {comments}", file=sys.stderr)
                else:
                    gh_issue = self.import_issue(
                        title, assignee, body,
                        milestone, labels,
                        attributes, comments)
                    print ("\tInitiated issue: %s (%s)" % (title, gh_issue),
                           file=sys.stderr)
                    self.gh_issues[title] = gh_issue

            if not self.is_dry_run:
                print("\tChecking completion…", file=sys.stderr)
                failure = True
                sleep = 0
                while failure:
                    try:
                        gh_issue = self.github_repo.get_issue(trac_id)
                        print("\t%s (%s)" % (gh_issue.title, gh_issue.html_url),
                              file=sys.stderr)
                        failure = False
                    except (UnknownObjectException, ssl.SSLError) as e:
                        sleep += 1
                        print("\t\tnot completed waiting", e, sleep, file=sys.stderr)
                        time.sleep(sleep)


def check_simple_output(*args, **kwargs):
    return "".join(subprocess.check_output(*args, shell=True, **kwargs).decode()).strip()


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

    parser.add_argument("--ssl-verify",
                        action="store_true",
                        help="Do SSL properly")

    parser.add_argument("--dry-run",
                        action="store_true",
                        help="Do not actually import any issues into GitHub")

    parser.add_argument("--ticket-range",
                        nargs=2,
                        type=int,
                        default=[None, None],
                        help="First and last ticket IDs to process")

    parser.add_argument("--import-attachments",
                        action="store_true",
                        help="Download attachments and add link to issues")

    parser.add_argument('--attachments-local-path',
                        action="store",
                        default=".",
                        help="File attachments are saved to this local path in subfolder tickets/NNN/")

    parser.add_argument('--attachments-github-repo',
                        action="store",
                        help="Github repo where file attachments are stored")

    args = parser.parse_args()

    if args.trac_hub_config:
        config = yaml.load(args.trac_hub_config, Loader=yaml.SafeLoader)
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
        m = Migrator(
            trac_url=trac_url,
            github_username=args.github_username,
            github_password=github_password,
            github_api_url=args.github_api_url,
            github_project=args.github_project,
            username_map=user_map,
            config=config,
            should_verify_ssl=args.ssl_verify,
            is_dry_run=args.dry_run,
            should_import_attachments=args.import_attachments,
            attachments_local_path=args.attachments_local_path,
            attachments_github_repo=args.attachments_github_repo,
        )
        m.run(ticket_range=args.ticket_range)
    except Exception as e:
        print("Exception: %s" % e, file=sys.stderr)

        tb = sys.exc_info()[2]

        sys.last_traceback = tb
        pdb.pm()
        raise
