#!/usr/bin/env python3

###############################################################################
# Copyright (c) 2019, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-795365
# All rights reserved
#
# This file is part of gitlab-runner-auth:
# https://github.com/LLNL/gitlab-runner-auth
#
# SPDX-License-Identifier: MIT
###############################################################################

import re
import sys
import socket
import argparse
import json
import urllib.request
from pathlib import Path
from shutil import which
from urllib.request import Request
from urllib.parse import urlencode, urljoin
from urllib.error import HTTPError
from json import JSONDecodeError

LOGGER_NAME = "gitlab-runner-config"
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger(LOGGER_NAME)


class TagMixin:
    def tags(self):
        return [self.identifier] + self._tags()


class Executor(TagMixin):
    @classmethod
    def from_template(cls, template_file):
        with open(template_file) as fh:
            config = toml.load(fh)
        return cls(config["executor"], template_file)

    def __init__(self, executor_type, template_file):
        self.host = socket.gethostname()
        self.executor_type = executor_type
        self.template_file = template_file

    @property
    def identifier(self):
        return "{}-{}".format(self.host, self.executor_type)

    @property
    def config(self):
        pass

    def _tags(self):
        tags = []
        if self.executor_type == "batch":
            if which("bsub"):
                tags.append("lsf")
            elif which("salloc"):
                tags.append("slurm")
            elif which("cqsub"):
                tags.append("cobalt")
        return tags


class Runner(TagMixin):
    def __init__(self, executors, service="main"):
        self.host = socket.gethostname()
        self.executors = executors
        self.service = service

    @property
    def identifier(self):
        return "{}-{}".format(self.host, self.service)

    def _tags(self):
        # TODO add archspec cpu
        cluster = re.sub(r"\d", "", self.host)
        tags = [self.host, cluster]
        for executor in self.executors:
            tags += executor.tags()
        return tags


# TODO: GitLab client factory built from executor info?
class GitlabInstance:
    def __init__(self, url, admin_token, access_token):
        self.url = url
        self.admin_token = admin_token
        self.access_token = access_token


def list_runners(base_url, access_token, filters=None):
    try:
        query = ""
        if filters:
            query = "?" + urlencode(filters)

        url = urljoin(base_url, "runners/all" + query)
        request = Request(url, headers={"PRIVATE-TOKEN": access_token})
        return json.load(urllib.request.urlopen(request))
    except JSONDecodeError:
        print("Failed parsing request data JSON")
        sys.exit(1)
    except HTTPError as e:
        print("Error listing Gitlab repos: {reason}".format(reason=e.reason))
        sys.exit(1)


def runner_info(base_url, access_token, repo_id):
    try:
        url = urljoin(base_url, "runners/" + str(repo_id))
        request = Request(url, headers={"PRIVATE-TOKEN": access_token})
        return json.load(urllib.request.urlopen(request))
    except JSONDecodeError:
        print("Failed parsing request data JSON")
        sys.exit(1)
    except HTTPError as e:
        print(
            "Error while requesting repo info for repo {repo}: {reason}".format(
                repo=repo_id, reason=e.reason
            )
        )
        sys.exit(1)


def valid_runner_token(base_url, token):
    """Test whether or not a runner token is valid"""

    try:
        url = urljoin(base_url, "runners/verify")
        data = urlencode({"token": token})

        request = Request(url, data=data.encode(), method="POST")
        urllib.request.urlopen(request)
        return True
    except HTTPError as e:
        if e.code == 403:
            return False
        else:
            print("Error while validating token: {}".format(e.reason))
            sys.exit(1)


def register_runner(base_url, admin_token, runner_type, tags):
    """Registers a runner and returns its info"""

    try:
        # the first tag is always the hostname
        url = urljoin(base_url, "runners")
        data = urlencode(
            {
                "token": admin_token,
                "description": tags[0] + "-" + runner_type,
                "tag_list": ",".join(tags + [runner_type]),
            }
        )

        request = Request(url, data=data.encode(), method="POST")
        response = urllib.request.urlopen(request)
        if response.getcode() == 201:
            return json.load(response)
        else:
            print("Registration for {runner_type} failed".format(runner_type))
            sys.exit(1)
    except HTTPError as e:
        print(
            "Error registering runner {runner} with tags {tags}: {reason}".format(
                runner=runner_type, tags=",".join(tags), reason=e.reason
            )
        )
        sys.exit(1)


def delete_runner(base_url, runner_token):
    """Delete an existing runner"""

    try:
        url = urljoin(base_url, "runners")
        data = urlencode({"token": runner_token,})

        request = Request(url, data=data.encode(), method="DELETE")
        response = urllib.request.urlopen(request)
        if response.getcode() == 204:
            return True
        else:
            print("Deleting runner with id failed")
            sys.exit(1)
    except HTTPError as e:
        print("Error deleting runner: {reason}".format(reason=e.reason))
        sys.exit(1)


def owner_only_permissions(path):
    st = path.stat()
    return not (bool(st.st_mode & stat.S_IRWXG) and bool(st.st_mode & stat.S_IRWXU))


def configure_runner(prefix, service_instance):
    """Takes a config template and substitutes runner tokens"""

    runner_config = {}
    config_file = prefix / Path("config.{}.toml".format(service_instance))
    executor_template_dir = prefix / Path(service_instance)

    if not config_file.is_file():
        if not all(owner_only_permissions(d) for d in [prefix, executor_template_dir]):
            logger.error(
                "check permissions on {prefix} or {template}, too permissive, exiting".format(
                    prefix=prefix, template=executor_template_dir
                )
            )
            sys.exit(1)
        # delete all runners associated with this **specific** host and instance type
        # build executors from the available templates
        # build a runner from the available executors
        # register each executor with GitLab and dump the runner config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="On the fly runner config")
    parser.add_argument(
        "-p",
        "--prefix",
        default="/etc/gitlab-runner",
        help="""The runner config directory prefix""",
    )
    parser.add_argument(
        "--instance",
        default="main",
        help="""The instance being controlled by systemd""",
    )
    args = parser.parse_args()
    configure_runner(args.prefix, args.service_instance)
