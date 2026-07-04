FROM scratch
ARG PROFILE=debug
ENV APP_ENV=test PATH=/usr/bin:/bin
WORKDIR /workspace
COPY app /opt/app/
ADD local.txt ./local.txt
RUN echo should-not-run
