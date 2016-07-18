#!/usr/bin/env python3

from configparser import ConfigParser
from datetime import datetime
import hashlib
import hmac
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network, ip_address, ip_network
import json
import logging
from logging import DEBUG, INFO
import os
from os import environ, path
import re
from urllib.error import URLError
from urllib.request import urlopen

import bottle
from bottle import BaseResponse, Bottle, HTTPError, abort, post, request, response
from funcy import cache, cut_prefix, keep, memoize, partial as par, rcompose as pipe, re_find
from github import Github
from github.Commit import Commit
from github.GithubException import BadCredentialsException, GithubException, TwoFactorException
from github.PullRequest import PullRequest
from github.Repository import Repository

# type hints per PEP 484
from typing import Generator, Iterable as Iter, List, Tuple, Union
AuthorTuple = Tuple[str, str, datetime]
IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


GH_BASE_URL = 'https://api.github.com'
BASE_DIR = path.dirname(__file__)
LOG = logging.getLogger(__name__)
VERSION = '0.2.0'

ref_head_name = par(re_find, r'refs/heads/(.*)')


@post('/')
def post_index():
    event_type = request.get_header('X-GitHub-Event')

    if not is_request_from_github():
        abort(403, "Forbidden for IP %s, it's not GitHub's address" % remote_ip())

    if request.content_type.split(';')[0] != 'application/json':
        abort(415, "Expected application/json, but got %s" % request.content_type)

    if event_type == 'ping':
        return handle_ping()

    elif event_type == 'push':
        return handle_push()

    else:
        abort(400, "Unsupported event type: %s" % event_type)


def handle_ping():
    return {'msg': "github-pr-closer %s" % VERSION}


def handle_push():
    payload = request.json

    try:
        repo_slug = payload['repository']['full_name']
    except KeyError:
        abort(422, 'Invalid JSON payload: repository.full_name is missing')

    try:
        conf = config()[repo_slug]
    except KeyError:
        abort(400, "Unknown repository: %s" % repo_slug)

    LOG.info("Handling push from repository: %s", repo_slug)

    verify_signature(conf.get('hook_secret', ''),
                     request.get_header('X-Hub-Signature'),
                     request.body)

    branch = ref_head_name(payload.get('ref', ''))
    if not re.match(r"^%s$" % conf.get('branch_regex', 'master'), branch):
        return ok("Skipping push into branch: %s" % branch)

    closed_pullreqs = []
    try:
        repo = Github(conf.get('github_token'), base_url=GH_BASE_URL).get_repo(repo_slug)
        pushed_commits = (repo.get_commit(c['id'])
                          for c in payload.get('commits', []))

        for pullreq, merged_commits in find_matching_pulls(repo, pushed_commits):
            pullreq_id = "%s#%s" % (repo_slug, pullreq.number)

            LOG.debug("Closing pull request %s", pullreq_id)
            close_pullreq_with_comment(pullreq, gen_comment(repo_slug, merged_commits))
            closed_pullreqs.append(pullreq_id)

    except (BadCredentialsException, TwoFactorException) as e:
        abort(500, "Authentication error, GitHub returned: %s" % e)

    except GithubException as e:
        abort(503, str(e))

    if closed_pullreqs:
        return ok("Closed pull requests: %s" % ', '.join(closed_pullreqs))
    else:
        return ok('No pull request has been closed')


def default_error_handler(resp: BaseResponse):
    response.content_type = 'application/problem+json'
    LOG.error(resp.body)
    return json.dumps({'title': resp.body, 'status': resp.status_code})


def ok(message: str) -> dict:
    LOG.info(message)
    return {'msg': message}


def is_request_from_github() -> bool:
    """Return True if the current request comes from GitHub."""

    return any(remote_ip() in net for net in github_source_networks())


def remote_ip() -> IPAddress:
    """Return request's IP address (i.e. address of the client)."""

    addr = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('REMOTE_ADDR')
    # nginx uses ::ffff: as a prefix for IPv4 addresses in ipv6only=off mode.
    return ip_address(cut_prefix(addr, '::ffff:'))


@cache(timeout=86400)
def github_source_networks() -> List[IPNetwork]:
    """Return GitHub's IP addresses that may be used for delivering webhook events."""

    try:
        LOG.debug('Fetching GitHub /meta')
        resp = urlopen("%s/meta" % GH_BASE_URL, timeout=5)
        data = json.loads(resp.read().decode('utf-8'))

        return [ip_network(net) for net in data['hooks']]

    except (URLError, ValueError, KeyError) as e:
        raise GithubResponseError('Failed to fetch list of allowed IP addresses from GitHub', e)


def verify_signature(secret: str, signature: str, resp_body: BytesIO) -> None:
    """Verify HMAC-SHA1 signature of the given response body.

    The signature is expected to be in format ``sha1=<hex-digest>``.
    """
    try:
        alg, digest = signature.lower().split('=', 1)
    except (ValueError, AttributeError):
        raise InvalidSignatureError('signature is malformed')

    if alg != 'sha1':
        raise InvalidSignatureError("expected type sha1, but got %s" % alg)

    computed_digest = hmac.new(secret.encode('utf-8'),
                               msg=resp_body.getbuffer(),
                               digestmod=hashlib.sha1).hexdigest()

    if not hmac.compare_digest(computed_digest, digest):
        raise InvalidSignatureError('digests do not match')


def find_matching_pulls(gh_repo: Repository, commits: Iter[Commit]) -> Generator:
    """Find pull requests that contains commits matching the given ``commits``.

    It yields tuple :class:`PullRequest` and list of the matched
    :class:`Commit`s (subset of the given ``commits``).

    The matching algorithm is based on comparing commits by an *author*
    (triplet name, email and date) and set of the affected files (just file
    names). The match is found when a pull request contains at least one commit
    from the given ``commits`` (i.e. their author triplet is the same), and
    an union of filenames affected by all the matching commits is the same as of
    all the pull request's commits.
    """
    LOG.debug('Fetching commits referenced in payload')
    commits_by_author = {commit_git_author(c): c for c in commits}
    find_matching_commit = pipe(commit_git_author, commits_by_author.get)

    for pullreq in gh_repo.get_pulls(state='open'):
        LOG.debug("Checking pull request #%s", pullreq.number)

        merged_commits = list(keep(find_matching_commit, pullreq.get_commits()))
        merged_files = (f.filename for c in merged_commits for f in c.files)
        pullreq_files = (f.filename for f in pullreq.get_files())

        if any(merged_commits) and set(merged_files) == set(pullreq_files):
            yield pullreq, merged_commits


def commit_git_author(commit: Commit) -> AuthorTuple:
    """Return git *author* from the given ``commit`` as a triple."""

    a = commit.commit.author
    return (a.name, a.email, a.date)


def gen_comment(repo_slug: str, commits: List[Commit]) -> str:
    """Return closing comment for the specified repository.

    The comment template is read from config file under the repository's
    section and key ``close_comment``. It may contain replacement fields:

    committer
      Will be replaced by GitHub login (prefixed with ``@``) or name (if the
      login is not available) of the committer (based on the first commit from
      the given ``commits``).

    commits
      Will be replaced by a comma-separated list of the ``commits``
      SHA hashes.
    """
    comment = config()[repo_slug]['close_comment']

    # Get committer's GitHub login, or just a name if his email is not
    # associated with any GitHub account.
    try:
        committer = "@%s" % commits[0].committer.login
    except AttributeError:
        committer = commits[0].commit.committer.name

    return comment.format(committer=committer,
                          commits=', '.join(c.sha for c in commits))


def close_pullreq_with_comment(pullreq: PullRequest, comment: str) -> None:
    pullreq.create_issue_comment(comment)
    pullreq.edit(state='closed')


@memoize
def config() -> ConfigParser:
    """Read settings from a file.

    It tries to read ``./settings.ini`` and a file specified by the environment
    variable ``CONF_FILE``. If none of them exist, then it raises an error.
    """
    conf = ConfigParser()
    if not conf.read([path.join(BASE_DIR, 'settings.ini'), os.getenv('CONF_FILE', '')]):
        raise FileNotFoundError('No configuration file was found.')
    return conf


class InvalidSignatureError(HTTPError):

    def __init__(self, message: str, **kwargs) -> None:
        msg = "Invalid X-Hub-Signature: %s" % message
        super().__init__(status=403, body=msg, **kwargs)


class GithubResponseError(HTTPError):

    def __init__(self, message: str, exception: Exception, **kwargs) -> None:
        msg = "%s: %s" % (message, exception)
        super().__init__(status=503, body=msg, exception=exception, **kwargs)


# Monkey-patch bottle.
Bottle.default_error_handler = lambda _, resp: default_error_handler(resp)  # type: ignore

# Set up logging.
logging.basicConfig(format="%(levelname)s: %(message)s")
LOG.setLevel(DEBUG if environ.get('DEBUG') else INFO)

LOG.info("Starting github-pr-closer %s" % VERSION)

# Fail fast when config file is not found.
try:
    config()
except FileNotFoundError as e:
    LOG.fatal(e)
    exit(1)

# Run bottle internal server when invoked directly (mainly for development).
if __name__ == '__main__':
    bottle.run(host=environ.get('HTTP_HOST', '127.0.0.1'),
               port=environ.get('HTTP_PORT', '8080'))
# Run bottle in application mode (in production under uWSGI server).
else:
    application = bottle.default_app()
