# How to deploy fabric8-analytics-notification-scheduler cron job on OpenShift

## Install required tools

Use your preferred package manager to install `origin-clients`.

If you are running Fedora, then following command will do the trick:

```shell
$ sudo dnf install origin-clients
```

## Configure fabric8-analytics services

The deploy.sh script expects to find configuration in `env.sh` file.
The easiest way how to create the configuration file is to copy [env-template.sh](env-template.sh) and modify it.

```shell
$ cp env-template.sh env.sh
$ vim env.sh
```

## Deploy fabric8-analytics services

Just run the deploy script and enjoy!

```shell
$ ./deploy.sh`
```