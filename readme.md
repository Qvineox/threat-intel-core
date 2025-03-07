## Setup

First, enable GitLab access to the package.

```shell
go env -w GOPROXY='https://gitlab.domsnail.ru/api/v4/projects/domsnail/threat-intel-core/packages/go,https://proxy.golang.org,direct'
git config --global url."https://${user}:${personal_access_token}@gitlab.domsnail.ru".insteadOf "https://gitlab.domsnail.ru"
```

Also, configure your machine using [official](https://docs.gitlab.com/ee/user/project/use_project_as_go_package.html)
manuals.

https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Go.gitlab-ci.yml
https://gitlab.com/guided-explorations/cfg-data/write-ci-cd-variables-in-pipeline

## Interfaces

Generating protocol buffers:

https://github.com/grpc-ecosystem/grpc-gateway?tab=readme-ov-file

## Release policy

```shell
git tag -a v0.1.4 -m 'version 0.1.4'
```