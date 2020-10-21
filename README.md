# Migrate TRAC tickets to Github issues

This works with github.com and Github Enterprise

This script migrates issues from Trac to Github:

* Component & Ticket-Type are converted to labels
* Comments to tickets are copied over
* Basic conversion of Wiki Syntax in comments and descriptions
* All titles will be suffixed with `(Trac #<>)` for ease of searching
* All created issues will have the full Trac attributes appended to the issue body in JSON format
* Issue links (i.e. `#1`, `refs 1`, etc.) will be converted to use the corresponding Github issue number instead of the original Trac ticket ID
* Users not in GH will be added as labels

Run migrate.py with --help for more information

Requirements:

* Python 3.6
* [PyGithub](https://pypi.python.org/pypi/PyGithub)
 
```
pip install PyGithub
```

 * Currently, you must add the GH credentials to the git config:

```
git config --global github.username myusername
git config --global github.password <your_github_token>
```

## Example usage with Github Enterprise
```
./migrate.py --trac-url=https://USERNAME:PASSWORD@trac.sample.local/mycustomer/project --github-api-url=https://github.sample.local/api/v3 --github-project=mycustomer/project
```

Note: Currently, you must leave USERNAME:PASSWORD _as_is, as it is replaced with the real user/pass in the script (will change, soon)