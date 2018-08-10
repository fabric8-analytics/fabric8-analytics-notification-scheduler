REGISTRY?= registry.devshift.net
REPOSITORY?= fabric8-analytics/ f8a-analytics-notification
DEFAULT_TAG = latest

ifeq($(TARGET), rhel)
    DOCKERFILE: = Dockerfile.rhel
else
    DOCKERFILE: = Dockerfile
endif

.PHONY: all docker - build fast - docker - build test get - image - name get - image - repository

all: fast - docker - build

docker - build:
    docker build - -no - cache - t $(REGISTRY) /$(REPOSITORY): $(DEFAULT_TAG) - f $(DOCKERFILE) .

fast - docker - build:
    docker build - t $(REGISTRY) /$(REPOSITORY): $(DEFAULT_TAG) - f $(DOCKERFILE) .

test:
    . / runtests.sh

get - image - name:
    @echo $(REGISTRY) /$(REPOSITORY): $(DEFAULT_TAG)
get - image - repository:
    @echo $(REPOSITORY)
