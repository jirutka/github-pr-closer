#!/usr/bin/env python3

from configparser import ConfigParser
import hashlib
import hmac
from ipaddress import ip_address, ip_network
import json
import logging
from logging import DEBUG, INFO
import os
from os import environ, path
import re
import urllib
from urllib.request import urlopen

import bottle
from bottle import BaseResponse, Bottle, HTTPError, abort, post, request, response
from funcy import cache, cut_prefix, keep, memoize, partial as par, rcompose as pipe, re_find
from github import Github
from github.GithubException import BadCredentialsException, GithubException, TwoFactorException

GH_BASE_URL = 'https://api.github.com'
BASE_DIR = path.dirname(__file__)
LOG = logging.getLogger(__name__)

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
    return json.dumps({'msg': 'pong'})


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

    verify_signature(conf.get('hook_secret', ''),
                     request.get_header('X-Hub-Signature'),
                     request.body)

    branch = ref_head_name(payload.get('ref', ''))
    if branch not in re.split(r',\s*', conf.get('branches', 'master')):
        abort(200, "Skipping push into branch: %s" % branch)

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
        abort(200, "Closed pull requests: %s" % ', '.join(closed_pullreqs))
    else:
        abort(200, 'No pull request has been closed')


def default_handler(resp):
    if resp.status_code >= 400:
        response.content_type = 'application/problem+json'
        LOG.error(resp.body)
        return json.dumps({'title': resp.body, 'status': resp.status_code})
    else:
        LOG.info(resp.body)
        return json.dumps({'msg': resp.body})


def is_request_from_github():
    return any(remote_ip() in net for net in github_source_networks())


def remote_ip():
    addr = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('REMOTE_ADDR')
    # nginx uses ::ffff: as a prefix for IPv4 addresses in ipv6only=off mode.
    return ip_address(cut_prefix(addr, '::ffff:'))


@cache(timeout=86400)
def github_source_networks():
    try:
        resp = urlopen("%s/meta" % GH_BASE_URL, timeout=5)
        data = json.loads(resp.read().decode('utf-8'))

        return [ip_network(net) for net in data['hooks']]

    except (urllib.error.URLError, ValueError, KeyError) as e:
        raise GithubResponseError('Failed to fetch list of allowed IP addresses from GitHub', e)


def verify_signature(secret, signature, resp_body):
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


def find_matching_pulls(gh_repo, commits):
    commits_by_author = {commit_git_author(c): c for c in commits}
    find_matching_commit = pipe(commit_git_author, commits_by_author.get)

    for pullreq in gh_repo.get_pulls(state='open'):
        merged_commits = list(keep(find_matching_commit, pullreq.get_commits()))
        merged_files = (f.filename for c in merged_commits for f in c.files)
        pullreq_files = (f.filename for f in pullreq.get_files())

        if any(merged_commits) and set(merged_files) == set(pullreq_files):
            yield pullreq, merged_commits


def commit_git_author(commit):
    a = commit.commit.author
    return (a.name, a.email, a.date)


def gen_comment(repo_slug, commits):
    comment = config()[repo_slug]['close_comment']

    # Get committer's GitHub login, or just a name if his email is not
    # associated with any GitHub account.
    try:
        committer = "@%s" % commits[0].committer.login
    except AttributeError:
        committer = commits[0].commit.committer.name

    return comment.format(committer=committer,
                          commits=', '.join(c.sha for c in commits))


def close_pullreq_with_comment(pullreq, comment):
    pullreq.create_issue_comment(comment)
    pullreq.edit(state='closed')


@memoize
def config():
    conf = ConfigParser()
    conf.read([path.join(BASE_DIR, 'settings.ini'), os.getenv('CONF_FILE', '')])
    return conf


class InvalidSignatureError(HTTPError):

    def __init__(self, message, **kwargs):
        msg = "Invalid X-Hub-Signature: %s" % message
        super().__init__(status=403, body=msg, **kwargs)


class GithubResponseError(HTTPError):

    def __init__(self, message, exception, **kwargs):
        msg = "%s: %s" % (message, exception)
        super().__init__(status=503, body=msg, exception=exception, **kwargs)


# Monkey-patch bottle.
Bottle.default_error_handler = lambda _, resp: default_handler(resp)
BaseResponse.default_content_type = 'application/json;charset=utf-8'

# Set up logging.
logging.basicConfig(format="%(levelname)s: %(message)s")
LOG.setLevel(DEBUG if environ.get('DEBUG') else INFO)

# Run bottle internal server when invoked directly (mainly for development).
if __name__ == '__main__':
    bottle.run(host=environ.get('HTTP_HOST', '127.0.0.1'),
               port=environ.get('HTTP_PORT', 8080))
# Run bottle in application mode (in production under uWSGI server).
else:
    application = bottle.default_app()
