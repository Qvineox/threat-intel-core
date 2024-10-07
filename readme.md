## Setup

First, enable GitLab access to the package.

```shell
go env -w GOPROXY='https://gitlab.qvineox.ru/api/v4/projects/domsnail/threat-intel-core/packages/go,https://proxy.golang.org,direct'
git config --global url."https://${user}:${personal_access_token}@gitlab.qvineox.ru".insteadOf "https://gitlab.qvineox.ru"
```

Also, configure your machine using [official](https://docs.gitlab.com/ee/user/project/use_project_as_go_package.html)
manuals.