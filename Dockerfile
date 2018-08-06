FROM registry.centos.org / centos / centos: 7

ENV APP_DIR = '/f8a_notification'


WORKDIR ${APP_DIR}

RUN yum install - y epel - release & &\
    yum install - y gcc git python34 - pip python34 - devel & &\
    yum clean all & &\
    mkdir - p ${APP_DIR}


COPY f8a_notification / ${APP_DIR} / f8a_notification

CMD["python", "f8a_notification/entryscript.py"]
